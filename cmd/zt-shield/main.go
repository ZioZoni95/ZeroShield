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
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"zt-shield/bpf"
	"zt-shield/internal/audit"
	"zt-shield/internal/config"
	"zt-shield/internal/lsm"
	"zt-shield/internal/xdp"
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

	// Rescan periodico in background: copre i file creati dopo l'avvio (es. una nuova
	// chiave generata dal tool) e i binari sostituiti dagli aggiornamenti di apt, che
	// cambiano inode. reconcile() rimuove anche le voci che non esistono piu'.
	//
	// Nota: time.Tick non ha canale di stop, quindi la goroutine vive per tutta la
	// vita del processo. Dato che il processo vive finche' gira il servizio, non
	// e' un leak reale, ma e' il pattern che i linter segnalano.
	go func() {
		for range time.Tick(time.Duration(cfg.RescanSeconds) * time.Second) {
			mgr.Sync()
		}
	}()

	// --- XDP: non fatale --------------------------------------------------------------
	// Se XDP non parte si continua: la protezione dei segreti (LSM) e' indipendente
	// e resta attiva. Il log e' un warning perche' l'utente deve sapere che la rete
	// non e' filtrata, ma non ha senso morire per questo.
	xl, iface, err := xdp.Attach(objs.XdpShield, cfg.Interface)
	if err != nil {
		log.Printf("⚠️ XDP non attivo: %v", err)
	} else {
		defer xl.Close()
		log.Printf("🔥 XDP attivo su %s (poisoning drop: %v)", iface.Name, cfg.BlockPoisoning)
		xdp.BlockSubnets(objs.InfectedSubnets, cfg.BlockSubnets)
	}

	// --- Audit ------------------------------------------------------------------------
	// Lettore del ring buffer: una sola lettura per programma, poi il consumer gira
	// in background finche' il reader non viene chiuso.
	rd, err := ringbuf.NewReader(objs.AuditLogs)
	if err != nil {
		log.Fatalf("Errore apertura ringbuf: %v", err)
	}
	defer rd.Close()
	go audit.Run(rd, cfg.LogFormat, mgr.RuleName)

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
