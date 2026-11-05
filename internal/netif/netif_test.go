// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package netif

import (
	"os"
	"path/filepath"
	"testing"
)

// fake costruisce un finto /sys/class/net: ogni voce e' una lista di file/cartelle da creare.
func fake(t *testing.T, spec map[string][]string, devices map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, items := range spec {
		d := filepath.Join(root, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			p := filepath.Join(d, it)
			if filepath.Ext(it) == "" && it != "uevent" && it != "tun_flags" {
				_ = os.MkdirAll(p, 0o755)
			} else {
				_ = os.WriteFile(p, []byte(""), 0o644)
			}
		}
	}
	for name, target := range devices { // symlink "device" verso un percorso che puo' contenere /usb
		tgt := filepath.Join(t.TempDir(), target)
		if err := os.MkdirAll(tgt, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(tgt, filepath.Join(root, name, "device")); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestClassify(t *testing.T) {
	root := fake(t, map[string][]string{
		"enp3s0": {}, "enx00e04c478980": {}, "wlp1s0": {"wireless"}, "docker0": {"bridge"}, "br-abc": {"bridge"},
		"veth123": {}, "wg0": {}, "ppp0": {}, "tide0": {}, "tun0": {"tun_flags"}, "lo": {}, "dummy0": {},
	}, map[string]string{"enp3s0": "pci0000:00/0000:00:1c.0/0000:03:00.0", "enx00e04c478980": "pci0000:00/usb1/1-2/1-2:1.0", "wlp1s0": "pci0000:00/0000:00:14.3"})
	want := map[string]string{
		"enp3s0": KindEthernet, "enx00e04c478980": KindUSB, "wlp1s0": KindWifi, "docker0": KindBridge, "br-abc": KindBridge,
		"veth123": KindVirtual, "wg0": KindVPN, "ppp0": KindVPN, "tide0": KindVPN, "tun0": KindVPN, "lo": KindLoopback, "dummy0": KindVirtual,
	}
	for n, k := range want {
		if got := Classify(root, n); got != k {
			t.Errorf("%s: %q, atteso %q", n, got, k)
		}
	}
}

func TestListOrderAndPhysical(t *testing.T) {
	root := fake(t, map[string][]string{"veth1": {}, "enp3s0": {}, "lo": {}, "wlp1s0": {"wireless"}, "docker0": {"bridge"}},
		map[string]string{"enp3s0": "pci/0000:03:00.0", "wlp1s0": "pci/0000:00:14.3"})
	l := List(root, func(n string) bool { return n != "wlp1s0" })
	var names []string
	for _, i := range l {
		names = append(names, i.Name)
	}
	if got := names[0] + "," + names[1] + "," + names[len(names)-1]; got != "enp3s0,wlp1s0,lo" {
		t.Fatalf("ordine: %v", names)
	}
	phys := 0
	for _, i := range l {
		if i.Physical() {
			phys++
		}
		if i.Name == "wlp1s0" && i.Up {
			t.Error("wlp1s0 risulta accesa")
		}
	}
	if phys != 2 {
		t.Errorf("fisiche: %d", phys)
	}
	if List(filepath.Join(root, "nope"), Up) != nil {
		t.Error("percorso mancante deve dare lista vuota")
	}
}

func TestRealSysfsDoesNotPanic(t *testing.T) {
	// Sul sistema vero lo e' sempre presente e classificato come loopback.
	for _, i := range List(Sys, Up) {
		if i.Name == "lo" && i.Kind != KindLoopback {
			t.Errorf("lo: %q", i.Kind)
		}
		if i.Kind == "" {
			t.Errorf("%s senza tipo", i.Name)
		}
	}
}
