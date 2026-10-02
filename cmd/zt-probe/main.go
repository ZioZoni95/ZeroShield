// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// zt-probe: collaudo del lato kernel SENZA avviare il demone.
//
// Il demone carica tutti i programmi in un colpo: se il kernel ne rifiuta uno
// (verifier, LSM non disponibile) non si sa quale ne' perche'. Qui ogni
// programma viene caricato da solo e il risultato del verifier e' stampato per
// nome, cosi' si sa esattamente cosa funziona su una macchina prima di fidarsi.
//
//	sudo ./bin/zt-probe            # solo verifier, nessun hook agganciato
//	sudo ./bin/zt-probe -xdp-lo    # in piu': XDP su lo, UDP verso 5355/5353/9999
//
// -xdp-lo aggancia XDP generic a loopback per pochi secondi e verifica che i
// pacchetti di poisoning vengano droppati (e contati in xdp_stats) mentre una
// porta neutra passa. Non tocca le interfacce reali.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"zt-shield/bpf"
	"zt-shield/internal/xdp"
)

func main() {
	xdpLo := flag.Bool("xdp-lo", false, "test funzionale XDP su loopback")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Printf("⚠️ memlock: %v\n", err)
	}
	spec, err := bpf.LoadShield()
	if err != nil {
		fmt.Printf("❌ spec eBPF: %v\n", err)
		os.Exit(1)
	}

	names := make([]string, 0, len(spec.Programs))
	for n := range spec.Programs {
		names = append(names, n)
	}
	sort.Strings(names)

	failed, unverified := 0, 0
	for _, n := range names {
		s := spec.Copy()
		for k := range s.Programs {
			if k != n {
				delete(s.Programs, k)
			}
		}
		coll, err := ebpf.NewCollection(s)
		if err != nil {
			if unsupported(err) {
				// Il kernel non ammette questo tipo di programma (es. LSM senza
				// trampolini BPF): non e' un difetto del codice, ma va saputo.
				unverified++
				fmt.Printf("⚠️ %-18s %s: non verificabile su questo kernel (%s)\n", n, s.Programs[n].Type, short(err))
				continue
			}
			failed++
			fmt.Printf("❌ %-18s %s: %s\n", n, s.Programs[n].Type, short(err))
			continue
		}
		coll.Close()
		fmt.Printf("✅ %-18s %s: accettato dal verifier\n", n, s.Programs[n].Type)
	}

	if *xdpLo {
		if err := testXDP(spec); err != nil {
			fmt.Printf("❌ XDP su lo: %v\n", err)
			failed++
		}
	}
	if unverified > 0 {
		fmt.Printf("⚠️ %d programmi non verificabili qui: serve un kernel con BPF LSM (vedi docs/TEST_SANDBOX.md)\n", unverified)
	}
	if failed > 0 {
		os.Exit(1)
	}
}

// unsupported: errore del kernel che rifiuta il TIPO di programma, non il suo
// contenuto. Un rifiuto del verifier (VerifierError) resta un fallimento vero.
func unsupported(err error) bool {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) && len(ve.Log) > 0 {
		return false
	}
	return errors.Is(err, unix.EPERM) || errors.Is(err, ebpf.ErrNotSupported)
}

// short: il log completo del verifier e' lungo centinaia di righe; qui basta
// la causa. Con ZT_PROBE_VERBOSE=1 si stampa tutto.
func short(err error) string {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) && os.Getenv("ZT_PROBE_VERBOSE") != "" {
		return fmt.Sprintf("%+v", ve)
	}
	return err.Error()
}

func testXDP(spec *ebpf.CollectionSpec) error {
	s := spec.Copy()
	for k := range s.Programs {
		if k != "xdp_shield" {
			delete(s.Programs, k)
		}
	}
	coll, err := ebpf.NewCollection(s)
	if err != nil {
		return err
	}
	defer coll.Close()

	// settings e' un ARRAY: le voci esistono sempre e partono da 0, quindi il
	// "default 1" di setting() nel C non scatta mai. Va scritto come fa il demone.
	if err := coll.Maps["settings"].Put(uint32(1), uint32(1)); err != nil {
		return fmt.Errorf("settings: %w", err)
	}

	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: coll.Programs["xdp_shield"], Interface: lo.Index, Flags: link.XDPGenericMode})
	if err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	defer l.Close()

	// 5355 (LLMNR) e 5353 (mDNS) devono sparire, 9999 deve arrivare.
	results := map[int]bool{}
	for _, port := range []int{5355, 5353, 9999} {
		got, err := udpRoundTrip(port)
		if err != nil {
			return fmt.Errorf("porta %d: %w", port, err)
		}
		results[port] = got
	}
	ok := !results[5355] && !results[5353] && results[9999]
	for _, port := range []int{5355, 5353, 9999} {
		fmt.Printf("   UDP 127.0.0.1:%d ricevuto=%v\n", port, results[port])
	}
	stats := xdp.ReadStats(coll.Maps["xdp_stats"])
	for _, st := range stats {
		fmt.Printf("   xdp_stats %s poisoning=%d subnet=%d\n", xdp.IPString(st.IP), st.Poison, st.Subnet)
	}
	if !ok || len(stats) == 0 {
		return fmt.Errorf("comportamento inatteso (atteso: 5355/5353 droppati, 9999 ricevuto, stats > 0)")
	}
	fmt.Println("✅ XDP su lo: poisoning droppato, traffico normale passa, radar popolato")
	return nil
}

// udpRoundTrip: ascolta su 127.0.0.1:port, invia un datagramma, riporta se e' arrivato.
func udpRoundTrip(port int) (bool, error) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	srv, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return false, err
	}
	defer srv.Close()
	cli, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return false, err
	}
	defer cli.Close()
	if _, err := cli.Write([]byte("zt-probe")); err != nil {
		return false, err
	}
	_ = srv.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	_, _, err = srv.ReadFromUDP(buf)
	return err == nil, nil
}
