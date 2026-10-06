// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// zt-shield: agente Zero-Trust locale (eBPF XDP + LSM).
//
// Flusso di avvio, in ordine:
//  1. carica il profilo di configurazione (default: /etc/zt-shield/shield.yaml)
//  2. risolve la home dell'utente da proteggere (non quella di root)
//  3. rimuove il limite memlock, necessario per caricare programmi e mappe
//  4. carica i programmi eBPF e popola la mappa delle impostazioni
//  5. sincronizza le mappe LSM (file protetti + binari autorizzati)
//  6. aggancia l'hook LSM file_open, fail-closed
//  7. avvia il rescan periodico delle mappe in background
//  8. aggancia XDP (non fatale se fallisce)
//  9. consuma il ring buffer degli eventi di audit
//  10. attende SIGTERM/SIGINT, poi stacca tutto
//
// Nota sulla persistenza: gli hook vivono finche' il processo vive. `systemctl stop`
// stacca l'hook LSM e rimuove quello XDP, quindi in quel momento la protezione e' via.
// Il pinning in bpffs (/sys/fs/bpf) risolverebbe, ma non e' implementato: se devi
// difenderti da qualcuno che puo' fermare il servizio, questa assunzione cade.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"zt-shield/bpf"
	"zt-shield/internal/audit"
	"zt-shield/internal/canary"
	"zt-shield/internal/config"
	"zt-shield/internal/lsm"
	"zt-shield/internal/netstat"
	"zt-shield/internal/vpn"
	"zt-shield/internal/watchdog"
	"zt-shield/internal/xdp"
	"zt-shield/pkg/ipc"
)

// Indici nella mappa `settings` di zerotrust.c. Devono corrispondere alle #define li'.
const (
	settingEnforce = 0 // 0 = audit (logga), 1 = enforce (nega con -EACCES)
	settingPoison  = 1 // 1 = drop XDP di LLMNR/mDNS/NBT-NS
)

// version: impostata al build con -ldflags "-X main.version=..." (Makefile, pacchetto).
var version = "dev"

// b2u: le mappe BPF trattano ogni valore come u32, quindi un bool di Go va
// tradotto esplicitamente. Utile solo perche' i mappe non hanno un tipo bool.
func b2u(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func main() {
	// -config: se omesso prova /etc/zt-shield/shield.yaml e, se non esiste,
	// usa il profilo di default senza leggere nulla dal filesystem.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `ZeroShield demone (serve root: eBPF + fanotify).

Uso:
  sudo SHIELD_USER=$USER %s [-config FILE]     prova in primo piano (audit: non blocca)
  sudo %s -config /etc/zt-shield/shield.yaml  config di sistema
  sudo bash scripts/install_service.sh $USER home   installa come servizio

Config: copia configs/shield.example.yaml in /etc/zt-shield/shield.yaml,
  imposta 'user', parti in audit, passa a enforce a log puliti.
  UI: ./bin/zt-tui (terminale) o ZeroShield nel menu app (desktop).

Opzioni:
`, os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	cfgPath := flag.String("config", "", "file YAML (default: "+config.DefaultPath+" se esiste, altrimenti profilo '"+config.DefaultProfile+"')")
	showVersion := flag.Bool("version", false, "stampa la versione ed esce")
	flag.Parse()
	if *showVersion {
		fmt.Println("zt-shield", version)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("Configurazione: %v", err)
	}
	acct, err := cfg.Account()
	if err != nil {
		log.Fatal(err)
	}
	home := acct.HomeDir
	log.Printf("⚙️ Profilo: %s | modalità: %s | home: %s", cfg.Profile, cfg.Mode, home)

	// Su kernel < 5.11 il caricamento delle mappe e' limitato a RLIMIT_MEMLOCK.
	// Dalla 5.11 il limite e' per cgroup e questa chiamata e' un no-op innocuo,
	// ma va fatta comunque per non fallire sui kernel piu' vecchi.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Errore rimozione memlock: %v", err)
	}

	// Carica i programmi e le mappe in un colpo solo. Se fallisce qui non e' stato
	// agganciato nulla: e' l'unico punto in cui un errore e' recuperabile.
	var objs bpf.ShieldObjects
	if err := bpf.LoadShieldObjects(&objs, nil); err != nil {
		log.Fatalf("Errore caricamento programmi eBPF: %v", err)
	}
	defer objs.Close()

	// Le impostazioni sono lette dal kernel a ogni invocazione del programma.
	must(objs.Settings.Put(uint32(settingEnforce), b2u(cfg.Enforce())))
	must(objs.Settings.Put(uint32(settingPoison), b2u(cfg.BlockPoisoning)))

	// --- LSM: fail-closed ------------------------------------------------------------
	// Un'hook non agganciato che si dichiara attivo e' peggio di un'hook assente:
	// l'utente crede di essere protetto. Per questo Attach() fa restituire l'errore
	// e main lo trasforma in uscita fatale invece di proseguire.
	mgr := lsm.New(objs.ProtectedFiles, objs.AllowedExes,
		[]*ebpf.Program{objs.ZtFileOpen, objs.ZtFileUnlink, objs.ZtFileRename, objs.ZtPathTruncate},
		home, cfg.AllRules())

	// Popola le mappe PRIMA di agganciare l'hook: cosi' al primo open() dal sistema
	// i file sono gia' protetti, senza una finestra in cui sono liberi.
	p, a := mgr.Sync()
	log.Printf("🔒 File protetti: %d | binari autorizzati: %d", p, a)
	if err := mgr.Attach(); err != nil {
		log.Fatal(err)
	}
	defer mgr.Close()
	log.Println("🛡️ Hook LSM 'file_open' attivo.")

	// Avvisa su filesystem dove la chiave dev+inode non matcha (btrfs/overlay):
	// prima la protezione era inerte in silenzio, ora almeno un log a avvio.
	lsm.CheckFilesystem(home)

	// Rescan periodico in background: copre i file creati dopo l'avvio (es. una nuova
	// chiave generata dal tool) e i binari sostituiti dagli aggiornamenti di apt, che
	// cambiano inode. reconcile() rimuove anche le voci che non esistono piu'.
	//
	// NewTicker (non Tick): il ticker va fermato a chiusura, altrimenti la goroutine
	// vive oltre il necessario e i linter segnalano leak.
	// La goroutine parte DOPO il server IPC e publishStatus (vedi sotto): da li'
	// in poi p/a/topSrc/tracker sono toccati solo da lei, niente data race.
	ticker := time.NewTicker(time.Duration(cfg.RescanSeconds) * time.Second)
	defer ticker.Stop()
	// Radar eBPF: tracker userspace sopra la LRU kernel. La mappa conta per IP,
	// qui si aggiunge wall-clock (lastSeen quando i contatori crescono) e top-12.
	type seen struct {
		poison, subnet uint32
		last           time.Time
	}
	tracker := map[[4]byte]*seen{}
	var topSrc []ipc.SourceStat
	refreshRadar := func() {
		stats := xdp.ReadStats(objs.XdpStats)
		// FIX: il tracker cresceva senza limite (IP sorgente spoofati su mDNS
		// = memoria del demone illimitata). Ora segue la LRU kernel: un IP
		// sfrattato dal kernel esce anche da qui, tetto 1024 voci.
		live := make(map[[4]byte]bool, len(stats))
		for _, s := range stats {
			live[s.IP] = true
		}
		for ip := range tracker {
			if !live[ip] {
				delete(tracker, ip)
			}
		}
		for _, s := range stats {
			tot := s.Poison + s.Subnet
			e, ok := tracker[s.IP]
			if !ok {
				e = &seen{}
				tracker[s.IP] = e
			}
			if tot > e.poison+e.subnet {
				e.last = time.Now()
			}
			e.poison, e.subnet = s.Poison, s.Subnet
		}
		topSrc = topSrc[:0]
		for ip, e := range tracker {
			topSrc = append(topSrc, ipc.SourceStat{
				IP: xdp.IPString(ip), Poison: e.poison, Subnet: e.subnet,
				Total: e.poison + e.subnet, LastSeen: e.last.UTC().Format(time.RFC3339),
			})
		}
		sort.Slice(topSrc, func(i, j int) bool { return topSrc[i].Total > topSrc[j].Total })
		if len(topSrc) > 12 {
			topSrc = topSrc[:12]
		}
	}
	// --- XDP: non fatale --------------------------------------------------------------
	// Se XDP non parte si continua: la protezione dei segreti (LSM) e' indipendente
	// e resta attiva. Il log e' un warning perche' l'utente deve sapere che la rete
	// non e' filtrata, ma non ha senso morire per questo.
	// Multi-interfaccia: `interface` accetta csv ("wlan0,eth0"); un attach fallito
	// non blocca gli altri e le UP scoperte vengono segnalate nel log.
	xlinks, xifaces := xdp.AttachAll(objs.XdpShield, cfg.Interface)
	for _, xl := range xlinks {
		defer xl.Close()
	}
	var xdpNames []string
	for _, fi := range xifaces {
		xdpNames = append(xdpNames, fi.Name)
	}
	if len(xifaces) == 0 {
		log.Printf("⚠️ XDP non attivo su alcuna interfaccia")
	} else {
		log.Printf("🔥 XDP attivo su %v (poisoning drop: %v)", xdpNames, cfg.BlockPoisoning)
		n := xdp.BlockSubnets(objs.InfectedSubnets, cfg.BlockSubnets)
		log.Printf("🚫 Subnet bloccate: %d/%d", n, len(cfg.BlockSubnets))
	}

	// --- IPC per le UI ----------------------------------------------------------------
	// Socket Unix sola-lettura per TUI/GUI (stato + stream eventi). Non fatale:
	// senza socket il demone protegge comunque, solo senza interfaccia.
	// Il socket e' dell'utente protetto (0600): stato ed eventi contengono PID, exe e
	// percorsi dei processi di tutti, non vanno a qualunque utente locale.
	var srv *ipc.Server
	uid, uerr := strconv.Atoi(acct.Uid)
	gid, gerr := strconv.Atoi(acct.Gid)
	if uerr != nil || gerr != nil {
		log.Printf("⚠️ IPC non attivo: uid/gid di %q non numerici (%q/%q)", acct.Username, acct.Uid, acct.Gid)
	} else if s, err := ipc.NewServerOwnedBy(uid, gid); err != nil {
		log.Printf("⚠️ IPC non attivo (niente TUI/GUI): %v", err)
	} else {
		srv = s
		defer srv.Close()
	}
	// Stato VPN osservato (tunnel, kill-switch nft, handshake). Il demone non applica
	// nulla: misura e avvisa. Proprieta' della goroutine di rescan dopo l'avvio.
	curVpn := vpn.Check(cfg.Vpn, vpn.ExecRunner)
	// publishStatus fotografa demone per le UI. Chiamata a ogni cambio rilevante
	// (avvio, rescan) perche' il protocollo ritrasmette ai connessi.
	publishStatus := func() {
		if srv == nil {
			return
		}
		var rules []ipc.RuleSummary
		for _, r := range cfg.AllRules() {
			rules = append(rules, ipc.RuleSummary{Name: r.Name, Paths: r.Paths, Allow: r.Allow})
		}
		listening, listeningTotal := listeningSnapshot()
		srv.UpdateStatus(ipc.Status{
			Profile: cfg.Profile, Mode: cfg.Mode, Home: home,
			HookLSM: true, XDP: xdpNames,
			Protected: p, Allowed: a,
			BlockPoisoning: cfg.BlockPoisoning, BlockSubnets: cfg.BlockSubnets,
			Vpn: curVpn, TopSources: topSrc,
			Listening: listening, ListeningTotal: listeningTotal, Rules: rules,
		})
	}
	publishStatus()

	// Rescan periodico (vedi sopra). lastRescan alimenta il watchdog: se il
	// rescan si pianta (walk bloccato su NFS, deadlock) i ping si fermano e
	// systemd riavvia, invece di un demone che si dichiara vivo ma non lavora.
	var lastRescan atomic.Int64
	lastRescan.Store(time.Now().UnixNano())
	// Il tunnel puo' cadere tra un rescan e l'altro: con la VPN configurata lo stato
	// si rilegge ogni 5 s (non ogni rescan_seconds) e si ripubblica solo se cambia.
	// Stessa goroutine del rescan: nessuno stato condiviso da proteggere.
	var vpnC <-chan time.Time
	if cfg.Vpn.Enabled {
		vt := time.NewTicker(5 * time.Second)
		defer vt.Stop()
		vpnC = vt.C
	}
	go func() {
		for {
			select {
			case <-ticker.C:
				p, a = mgr.Sync()
				log.Printf("🔄 Rescan mappe: file=%d binari=%d", p, a)
				refreshRadar()
				curVpn = vpn.Check(cfg.Vpn, vpn.ExecRunner)
				publishStatus()
				lastRescan.Store(time.Now().UnixNano())
			case <-vpnC:
				if st := vpn.Check(cfg.Vpn, vpn.ExecRunner); st != curVpn {
					log.Printf("🔒 VPN: tunnel=%v kill-switch=%v handshake=%ds (prima: tunnel=%v kill-switch=%v)",
						st.Up, st.KillSwitch, st.HandshakeAge, curVpn.Up, curVpn.KillSwitch)
					curVpn = st
					publishStatus()
				}
			}
		}
	}()

	// Watchdog systemd su ticker proprio a meta' WatchdogSec (no-op senza
	// NOTIFY_SOCKET/WATCHDOG_USEC). Il ping si ferma se l'ultimo rescan e'
	// piu' vecchio di 2 intervalli + margine: hung = restart.
	if err := watchdog.Ready(); err != nil {
		log.Printf("⚠️ sd_notify READY: %v", err)
	}
	if every := watchdog.Interval(); every > 0 {
		stale := 2*time.Duration(cfg.RescanSeconds)*time.Second + 30*time.Second
		go func() {
			wd := time.NewTicker(every)
			defer wd.Stop()
			for range wd.C {
				if time.Since(time.Unix(0, lastRescan.Load())) > stale {
					log.Printf("⚠️ rescan fermo da oltre %s: stop ping watchdog", stale)
					continue
				}
				if err := watchdog.Ping(); err != nil {
					log.Printf("⚠️ watchdog: %v", err)
				}
			}
		}()
	}

	// --- Audit ------------------------------------------------------------------------
	// Lettore del ring buffer: una sola lettura per programma, poi il consumer gira
	// in background finche' il reader non viene chiuso. Oltre al log, ogni evento
	// viene pubblicato sul socket IPC per le UI live.
	rd, err := ringbuf.NewReader(objs.AuditLogs)
	if err != nil {
		log.Fatalf("Errore apertura ringbuf: %v", err)
	}
	defer rd.Close()
	go audit.Run(rd, cfg.LogFormat, mgr.RuleName, func(ev audit.ParsedEvent) {
		if srv == nil {
			return
		}
		srv.Publish(ipc.WireEvent{
			Action: ev.Action, PID: ev.PID, Comm: ev.Comm,
			Exe: ev.Exe, Rule: ev.Rule, Inode: ev.Inode,
		})
	})

	// --- Canary anti-ransomware (fanotify, solo userspace) ------------------------------
	// Disabilitato di default (canary.enabled). Non fatale: senza CAP_SYS_ADMIN
	// il watcher non parte ma LSM/XDP restano attivi. Vedi docs/CANARY.md.
	if cfg.Canary.Enabled {
		w, err := canary.Start(home, cfg.Canary.Dirs, cfg.Canary.Names,
			cfg.Canary.ExcludeExe, cfg.Canary.BurstCount, cfg.Canary.BurstSecs,
			cfg.Enforce(), func(hit canary.Hit) {
				// exe e path sono scelti dal processo osservato: niente ANSI grezzo.
				hit.Exe, hit.Path = ipc.SafeText(hit.Exe), ipc.SafeText(hit.Path)
				icon := "🐤 [CANARY-ALERT]"
				if hit.Verdict == canary.VerdictKill {
					if hit.Killed {
						icon = "🐤 [CANARY-KILL]"
					} else if hit.KillErr != nil {
						icon = "🐤 [CANARY-KILL-FALLITO]"
					}
				}
				log.Printf("%s pid=%d exe=%s kind=%s path=%s motivo=%s", icon,
					hit.PID, hit.Exe, hit.Kind, hit.Path, hit.Reason)
				if srv == nil {
					return
				}
				action := "alert"
				if hit.Verdict == canary.VerdictKill && hit.Killed {
					action = "killed"
				}
				srv.PublishCanary(ipc.CanaryAlert{
					Action: action, PID: hit.PID, Exe: hit.Exe, Path: hit.Path,
					Kind: string(hit.Kind), Reason: hit.Reason,
				})
			})
		if err != nil {
			log.Printf("⚠️ canary non attivo: %v", err)
		} else {
			defer w.Close()
			log.Println("🐤 Watcher canary attivo.")
		}
	}

	// --- Ciclo di vita ----------------------------------------------------------------
	// Resta in attesa di un segnale. Alla fine le defer girano in ordine inverso:
	// chiude il ring buffer, stacca XDP, stacca l'hook LSM, chiude le mappe.
	// ATTENZIONE: in quel momento la protezione non e' piu' attiva (vedi nota in testa).
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	log.Println("🚀 Local Zero-Trust Shield in esecuzione.")
	<-stop
	log.Println("🛑 Chiusura agent e rilascio hook eBPF.")
}

// maxListening: tetto delle porte in ascolto nello status. Ogni voce viaggia a ogni
// client a ogni publish: oltre qualche centinaio la riga supera il buffer del client.
const maxListening = 256

// listeningSnapshot converte internal/netstat in ipc (taglie diverse, stesso dato) e
// restituisce anche il totale, cosi' le UI dichiarano il troncamento. La sanificazione
// dei testi la fa ipc.UpdateStatus, in un punto solo.
func listeningSnapshot() ([]ipc.ListenEntry, int) {
	entries, total := netstat.Listening(maxListening)
	out := make([]ipc.ListenEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, ipc.ListenEntry{
			Proto: e.Proto, Addr: e.Addr, Port: e.Port, PID: e.PID, Exe: e.Exe,
		})
	}
	return out, total
}

// must: usato solo per i Put sulle mappe delle impostazioni, dove un errore
// significa configurazione interna incoerente e non e' recuperabile a runtime.
// Gli errori dei Put nelle mappe delle regole non passano di qui: li gestisce
// lsm.Sync, che li logga e prosegue perche' una regola non risolvibile non deve
// impedire la protezione delle altre.
func must(err error) {
	if err != nil {
		log.Fatalf("Errore configurazione mappe eBPF: %v", err)
	}
}
