// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package xdp

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"zt-shield/bpf"
)

const (
	xdpDrop = 1
	xdpPass = 2
)

// xdpObjs: solo il programma XDP e le mappe che usa. I programmi LSM restano fuori
// perche' molti kernel (CI, container) non li caricano: qui si prova solo il parser.
type xdpObjs struct {
	XdpShield  *ebpf.Program `ebpf:"xdp_shield"`
	Settings   *ebpf.Map     `ebpf:"settings"`
	XdpV6Drops *ebpf.Map     `ebpf:"xdp_v6_drops"`
}

// loadXDP carica il vero programma xdp_shield e salta il test se il kernel o i
// privilegi non lo permettono (CI senza root, kernel senza BPF).
func loadXDP(t *testing.T) *xdpObjs {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("memlock: %v", err)
	}
	spec, err := bpf.LoadShield()
	if err != nil {
		t.Fatalf("spec eBPF: %v", err)
	}
	for name := range spec.Programs {
		if name != "xdp_shield" {
			delete(spec.Programs, name)
		}
	}
	var objs xdpObjs
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Skipf("eBPF non caricabile qui: %v", err)
	}
	t.Cleanup(func() {
		objs.XdpShield.Close()
		objs.Settings.Close()
		objs.XdpV6Drops.Close()
	})
	if err := objs.Settings.Put(uint32(1), uint32(1)); err != nil { // SETTING_POISON
		t.Fatal(err)
	}
	return &objs
}

func run(t *testing.T, p *ebpf.Program, pkt []byte) uint32 {
	t.Helper()
	ret, _, err := p.Test(pkt)
	if err != nil {
		t.Skipf("BPF_PROG_TEST_RUN non disponibile: %v", err)
	}
	return ret
}

func u16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }

func ethHdr(proto uint16) []byte {
	b := make([]byte, 12)
	b[0], b[6] = 0x02, 0x04
	return append(b, u16(proto)...)
}

// vlan avvolge payload in tag: ogni tag = TCI(2) + EtherType incapsulato(2).
// outer sono gli ethertype dei tag, nell'ordine in cui compaiono sul filo.
func vlanFrame(tags []uint16, inner uint16, payload []byte) []byte {
	if len(tags) == 0 {
		return append(ethHdr(inner), payload...)
	}
	out := ethHdr(tags[0])
	for i := range tags {
		out = append(out, 0x00, byte(100+i)) // TCI
		next := inner
		if i+1 < len(tags) {
			next = tags[i+1]
		}
		out = append(out, u16(next)...)
	}
	return append(out, payload...)
}

func udp(sport, dport uint16) []byte {
	b := append(u16(sport), u16(dport)...)
	return append(b, 0, 8, 0, 0)
}

func ip4(proto byte, l4 []byte) []byte {
	h := make([]byte, 20)
	h[0], h[8], h[9] = 0x45, 64, proto
	copy(h[12:], []byte{10, 1, 2, 3})
	copy(h[16:], []byte{224, 0, 0, 251})
	return append(h, l4...)
}

func ip6(next byte, l4 []byte) []byte {
	h := make([]byte, 40)
	h[0], h[6], h[7] = 0x60, next, 255
	h[8], h[9] = 0xfe, 0x80
	h[24], h[25], h[39] = 0xff, 0x02, 0xfb
	return append(h, l4...)
}

func pad(b []byte) []byte {
	for len(b) < 64 {
		b = append(b, 0)
	}
	return b
}

func TestXDPPoisoningParsing(t *testing.T) {
	objs := loadXDP(t)
	p := objs.XdpShield
	q, ad := uint16(0x8100), uint16(0x88A8)
	cases := []struct {
		name string
		pkt  []byte
		want uint32
	}{
		{"v4 mDNS", vlanFrame(nil, 0x0800, ip4(17, udp(5353, 5353))), xdpDrop},
		{"v4 LLMNR risposta (sport)", vlanFrame(nil, 0x0800, ip4(17, udp(5355, 49152))), xdpDrop},
		{"v4 NBT-NS", vlanFrame(nil, 0x0800, ip4(17, udp(40000, 137))), xdpDrop},
		{"v4 DNS normale", vlanFrame(nil, 0x0800, ip4(17, udp(40000, 53))), xdpPass},
		{"v4 TCP su 5353 non e' UDP", vlanFrame(nil, 0x0800, ip4(6, udp(5353, 5353))), xdpPass},
		{"v4 1 tag 802.1Q", vlanFrame([]uint16{q}, 0x0800, ip4(17, udp(5353, 5353))), xdpDrop},
		{"v4 QinQ 88a8+8100", vlanFrame([]uint16{ad, q}, 0x0800, ip4(17, udp(5353, 5353))), xdpDrop},
		{"v4 doppio 8100", vlanFrame([]uint16{q, q}, 0x0800, ip4(17, udp(5355, 5355))), xdpDrop},
		{"v4 QinQ traffico normale", vlanFrame([]uint16{ad, q}, 0x0800, ip4(17, udp(40000, 53))), xdpPass},
		{"v4 tre tag: oltre il limite, PASS", vlanFrame([]uint16{q, q, q}, 0x0800, ip4(17, udp(5353, 5353))), xdpPass},
		{"v6 mDNS", vlanFrame(nil, 0x86DD, ip6(17, udp(5353, 5353))), xdpDrop},
		{"v6 LLMNR", vlanFrame(nil, 0x86DD, ip6(17, udp(49152, 5355))), xdpDrop},
		{"v6 con QinQ", vlanFrame([]uint16{ad, q}, 0x86DD, ip6(17, udp(5353, 5353))), xdpDrop},
		{"v6 DNS normale", vlanFrame(nil, 0x86DD, ip6(17, udp(40000, 53))), xdpPass},
		{"v6 DHCPv6 (non toccato)", vlanFrame(nil, 0x86DD, ip6(17, udp(546, 547))), xdpPass},
		{"v6 TCP", vlanFrame(nil, 0x86DD, ip6(6, udp(5353, 5353))), xdpPass},
		{"ARP passa", vlanFrame(nil, 0x0806, make([]byte, 28)), xdpPass},
		{"troncato dopo eth", ethHdr(0x0800), xdpPass},
		{"troncato nel tag", append(ethHdr(0x8100), 0, 1), xdpPass},
		{"troncato in ipv6", vlanFrame(nil, 0x86DD, make([]byte, 20)), xdpPass},
	}
	for _, c := range cases {
		if got := run(t, p, pad(c.pkt)); got != c.want {
			t.Errorf("%s: XDP=%d, atteso %d", c.name, got, c.want)
		}
	}
	// I troncati vanno provati senza padding (pad li renderebbe lunghi): ricontrollo.
	for _, c := range cases[len(cases)-3:] {
		if got := run(t, p, c.pkt); got != xdpPass {
			t.Errorf("%s (senza padding): XDP=%d, atteso PASS", c.name, got)
		}
	}
}

func TestXDPPoisoningOffPassesEverything(t *testing.T) {
	objs := loadXDP(t)
	if err := objs.Settings.Put(uint32(1), uint32(0)); err != nil {
		t.Fatal(err)
	}
	for name, pkt := range map[string][]byte{
		"v4": vlanFrame(nil, 0x0800, ip4(17, udp(5353, 5353))),
		"v6": vlanFrame(nil, 0x86DD, ip6(17, udp(5353, 5353))),
	} {
		if got := run(t, objs.XdpShield, pad(pkt)); got != xdpPass {
			t.Errorf("%s con block_poisoning=false: XDP=%d, atteso PASS", name, got)
		}
	}
}

func TestXDPCountsV6Drops(t *testing.T) {
	objs := loadXDP(t)
	for i := 0; i < 3; i++ {
		run(t, objs.XdpShield, pad(vlanFrame(nil, 0x86DD, ip6(17, udp(5353, 5353)))))
	}
	var n uint64
	if err := objs.XdpV6Drops.Lookup(uint32(0), &n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("contatore v6 = %d, atteso 3", n)
	}
}
