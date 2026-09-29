// Package xdp gestisce attach XDP (generic mode) e la trie LPM delle subnet bloccate.
package xdp

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// lpmKey ha lo stesso layout di lpm_key in zerotrust.c (IPv4 in network byte order).
type lpmKey struct {
	PrefixLen uint32
	Addr      [4]byte
}

// Attach aggancia il programma XDP all'interfaccia indicata, o a quella della route di default.
func Attach(prog *ebpf.Program, custom string) (link.Link, *net.Interface, error) {
	iface, err := defaultInterface(custom)
	if err != nil {
		return nil, nil, err
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // universale (Wi-Fi, Ethernet, VPN)
	})
	if err != nil {
		return nil, iface, fmt.Errorf("attach XDP su %s: %w", iface.Name, err)
	}
	return l, iface, nil
}

// BlockSubnets inserisce i CIDR IPv4 nella trie. ATTENZIONE: XDP scarta anche le risposte
// provenienti da quelle subnet: non includere gateway/DNS che ti servono.
func BlockSubnets(m *ebpf.Map, cidrs []string) int {
	n := 0
	for _, c := range cidrs {
		_, ipn, err := net.ParseCIDR(c)
		if err != nil || ipn.IP.To4() == nil {
			log.Printf("⚠️ CIDR IPv4 non valido: %q", c)
			continue
		}
		ones, _ := ipn.Mask.Size()
		k := lpmKey{PrefixLen: uint32(ones)}
		copy(k.Addr[:], ipn.IP.To4())
		if err := m.Put(k, uint32(1)); err != nil {
			log.Printf("⚠️ subnet %s: %v", c, err)
			continue
		}
		log.Printf("🚫 Subnet bloccata in XDP: %s", c)
		n++
	}
	return n
}

func defaultInterface(custom string) (*net.Interface, error) {
	if custom != "" {
		return net.InterfaceByName(custom)
	}
	conn, err := net.Dial("udp", "1.1.1.1:80") // nessun pacchetto inviato: serve solo la route
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(local.IP) {
				return &ifc, nil
			}
		}
	}
	return nil, fmt.Errorf("nessuna interfaccia di default identificata (imposta 'interface')")
}
