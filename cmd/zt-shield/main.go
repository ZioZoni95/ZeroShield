// zt-shield: agente Zero-Trust locale (eBPF XDP + LSM).
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

const (
	settingEnforce = 0
	settingPoison  = 1
)

func b2u(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func main() {
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

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Errore rimozione memlock: %v", err)
	}
	var objs bpf.ShieldObjects
	if err := bpf.LoadShieldObjects(&objs, nil); err != nil {
		log.Fatalf("Errore caricamento programmi eBPF: %v", err)
	}
	defer objs.Close()

	must(objs.Settings.Put(uint32(settingEnforce), b2u(cfg.Enforce())))
	must(objs.Settings.Put(uint32(settingPoison), b2u(cfg.BlockPoisoning)))

	// LSM: fail-closed. Senza hook lo scudo non deve fingersi attivo.
	mgr := lsm.New(&objs, home, cfg.AllRules())
	p, a := mgr.Sync()
	log.Printf("🔒 File protetti: %d | binari autorizzati: %d", p, a)
	if err := mgr.Attach(); err != nil {
		log.Fatal(err)
	}
	defer mgr.Close()
	log.Println("🛡️ Hook LSM 'file_open' attivo.")

	// Rescan periodico: file creati dopo l'avvio, binari aggiornati da apt, voci obsolete.
	go func() {
		for range time.Tick(time.Duration(cfg.RescanSeconds) * time.Second) {
			mgr.Sync()
		}
	}()

	// XDP
	xl, iface, err := xdp.Attach(objs.XdpShield, cfg.Interface)
	if err != nil {
		log.Printf("⚠️ XDP non attivo: %v", err)
	} else {
		defer xl.Close()
		log.Printf("🔥 XDP attivo su %s (poisoning drop: %v)", iface.Name, cfg.BlockPoisoning)
		xdp.BlockSubnets(objs.InfectedSubnets, cfg.BlockSubnets)
	}

	rd, err := ringbuf.NewReader(objs.AuditLogs)
	if err != nil {
		log.Fatalf("Errore apertura ringbuf: %v", err)
	}
	defer rd.Close()
	go audit.Run(rd, cfg.LogFormat, mgr.RuleName)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	log.Println("🚀 Local Zero-Trust Shield in esecuzione.")
	<-stop
	log.Println("🛑 Chiusura agent e rilascio hook eBPF.")
}

func must(err error) {
	if err != nil {
		log.Fatalf("Errore configurazione mappe eBPF: %v", err)
	}
}
