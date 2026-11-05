// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package netif riconosce il tipo delle interfacce di rete (cavo, USB, Wi-Fi, VPN, container...) leggendo
// /sys/class/net, per far scegliere alle UI quali filtrare e per non allarmare su quelle che non contano.
package netif

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Tipi di interfaccia. L'ordine di presentazione e' quello dei valori (le fisiche prima).
const (
	KindEthernet = "ethernet" // scheda di rete cablata
	KindUSB      = "usb"      // adattatore USB (cavo o tethering)
	KindWifi     = "wifi"
	KindVPN      = "vpn"     // tunnel: wireguard, tun/tap, ppp, tailscale
	KindBridge   = "bridge"  // bridge (docker, libvirt...)
	KindVirtual  = "virtual" // veth e altre interfacce virtuali dei container
	KindLoopback = "loopback"
)

// Info: una interfaccia come la vede la GUI.
type Info struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Up   bool   `json:"up"`
}

// Physical: interfacce su cui ha senso proteggersi da una rete ostile (le altre sono di norma locali o gia' dentro un tunnel).
func (i Info) Physical() bool {
	return i.Kind == KindEthernet || i.Kind == KindUSB || i.Kind == KindWifi
}

var vpnPrefixes = []string{"wg", "tun", "tap", "ppp", "tailscale", "zt", "tide", "utun", "nordlynx", "proton"}

// Classify decide il tipo da quello che sysfs racconta dell'interfaccia. sysRoot e' /sys/class/net
// (parametro per i test).
func Classify(sysRoot, name string) string {
	if name == "lo" {
		return KindLoopback
	}
	dir := filepath.Join(sysRoot, name)
	exists := func(p string) bool { _, err := os.Stat(filepath.Join(dir, p)); return err == nil }
	uevent, _ := os.ReadFile(filepath.Join(dir, "uevent"))
	devtype := ""
	for _, l := range strings.Split(string(uevent), "\n") {
		if v, ok := strings.CutPrefix(l, "DEVTYPE="); ok {
			devtype = strings.TrimSpace(v)
		}
	}
	switch {
	case exists("bridge") || devtype == "bridge":
		return KindBridge
	case exists("wireless") || exists("phy80211") || devtype == "wlan":
		return KindWifi
	case exists("tun_flags") || devtype == "wireguard" || devtype == "ppp":
		return KindVPN
	case devtype == "veth" || strings.HasPrefix(name, "veth"):
		return KindVirtual
	}
	for _, p := range vpnPrefixes {
		if strings.HasPrefix(name, p) && !exists("device") {
			return KindVPN
		}
	}
	if exists("device") { // ha un dispositivo reale dietro: e' hardware
		if real, err := filepath.EvalSymlinks(filepath.Join(dir, "device")); err == nil && strings.Contains(real, "/usb") {
			return KindUSB
		}
		return KindEthernet
	}
	return KindVirtual
}

// List elenca le interfacce con il loro tipo, le fisiche prima. up dice se un'interfaccia e' accesa
// (net.Interfaces in produzione, una funzione finta nei test).
func List(sysRoot string, up func(name string) bool) []Info {
	ents, err := os.ReadDir(sysRoot)
	if err != nil {
		return nil
	}
	var out []Info
	for _, e := range ents {
		n := e.Name()
		out = append(out, Info{Name: n, Kind: Classify(sysRoot, n), Up: up(n)})
	}
	rank := map[string]int{KindEthernet: 0, KindUSB: 1, KindWifi: 2, KindVPN: 3, KindBridge: 4, KindVirtual: 5, KindLoopback: 6}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Kind] != rank[out[j].Kind] {
			return rank[out[i].Kind] < rank[out[j].Kind]
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Sys e' il percorso reale; Up usa il flag IFF_UP del kernel.
const Sys = "/sys/class/net"

func Up(name string) bool {
	ifc, err := net.InterfaceByName(name)
	return err == nil && ifc.Flags&net.FlagUp != 0
}
