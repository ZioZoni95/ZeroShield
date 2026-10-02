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
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"zt-shield/bpf"
	"zt-shield/internal/audit"
	"zt-shield/internal/config"
	"zt-shield/internal/lsm"
	"zt-shield/internal/xdp"
	"zt-shield/pkg/ipc"
)

// Indici nella mappa `settings` di zerotrust.c. Devono corrispondere alle #define li'.
const (
	settingEnforce = 0 // 0 = audit (logga), 1 = enforce (nega con -EACCES)
	settingPoison  = 1 // 1 = drop XDP di LLMNR/mDNS/NBT-NS
)

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
	cfgPath := flag.String("config", "", "file YAML (default: "+config.DefaultPath+" se esiste, altrimenti profilo '"+config.DefaultProfile+"')")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("Configurazione: %v", err)
	}
	home, err := cfg.HomeDir()
	if err != nil {
		log.Fatal(err)
	}
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
	mgr := lsm.New(&objs, home, cfg.AllRules())

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
	// publishStatus fotografa demone per le UI (definita dopo il server IPC,
	// usata anche dal rescan: dichiarata qui per visibilita').
	var publishStatus func()

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
		for _, s := range xdp.ReadStats(objs.XdpStats) {
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
	go func() {
		for range ticker.C {
			p, a = mgr.Sync()
			log.Printf("🔄 Rescan mappe: file=%d binari=%d", p, a)
			refreshRadar()
			publishStatus()
		}
	}()

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
	var srv *ipc.Server
	if s, err := ipc.NewServer(); err != nil {
		log.Printf("⚠️ IPC non attivo (niente TUI/GUI): %v", err)
	} else {
		srv = s
		defer srv.Close()
	}
	// publishStatus fotografa demone per le UI. Chiamata a ogni cambio rilevante
	// (avvio, rescan) perche' il protocollo ritrasmette ai connessi.
	publishStatus = func() {
		if srv == nil {
			return
		}
		var rules []ipc.RuleSummary
		for _, r := range cfg.AllRules() {
			rules = append(rules, ipc.RuleSummary{Name: r.Name, Paths: r.Paths, Allow: r.Allow})
		}
		srv.UpdateStatus(ipc.Status{
			Profile: cfg.Profile, Mode: cfg.Mode, Home: home,
			HookLSM: true, XDP: xdpNames,
			Protected: p, Allowed: a,
			BlockPoisoning: cfg.BlockPoisoning, BlockSubnets: cfg.BlockSubnets,
			TopSources: topSrc, Rules: rules,
		})
	}
	publishStatus()

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
