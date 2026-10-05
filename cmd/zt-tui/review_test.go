// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"strconv"
	"strings"
	"testing"

	"zt-shield/pkg/ipc"
)

// Un exe con sequenze di controllo (lo sceglie chi lancia il processo) non deve
// arrivare grezzo al terminale nella tab Rete.
func TestNetViewNeverEmitsControlChars(t *testing.T) {
	m := initialModel()
	m.st = ipc.Status{
		Profile: "home", Mode: "audit",
		Vpn: ipc.VpnStatus{Enabled: true, Tunnel: "wg0\x1b[2J", Endpoint: "1.2.3.4:5\x07"},
		Listening: []ipc.ListenEntry{
			{Proto: "tcp", Addr: "0.0.0.0", Port: 8080, PID: 9, Exe: "/tmp/\x1b]52;c;ZXZpbA==\x07evil"},
		},
	}
	out := m.netView()
	for _, bad := range []string{"\x1b]52", "\x1b[2J", "\x07"} {
		if strings.Contains(out, bad) {
			t.Errorf("sequenza %q arrivata alla tab Rete: %q", bad, out)
		}
	}
	if !strings.Contains(out, `\x1b]52`) {
		t.Errorf("l'exe deve restare leggibile in forma escapata: %q", out)
	}
}

func TestNetViewShowsUDPAndTruncation(t *testing.T) {
	m := initialModel()
	m.st = ipc.Status{
		Listening:      []ipc.ListenEntry{{Proto: "udp", Addr: "0.0.0.0", Port: 5353, PID: 7, Exe: "/usr/sbin/avahi-daemon"}},
		ListeningTotal: 300,
	}
	out := m.netView()
	if !strings.Contains(out, "udp") || !strings.Contains(out, "5353") {
		t.Errorf("la tab Rete deve mostrare i socket UDP: %q", out)
	}
	if !strings.Contains(out, "mostrate 1 di 300") {
		t.Errorf("il troncamento va dichiarato: %q", out)
	}
}

func TestVpnLineStates(t *testing.T) {
	cases := []struct {
		name string
		v    ipc.VpnStatus
		want string
	}{
		{"spenta", ipc.VpnStatus{}, "non monitorata"},
		{"protetta", ipc.VpnStatus{Enabled: true, Tunnel: "wg0", Endpoint: "1.2.3.4:5", Up: true, KillSwitch: true, HandshakeAge: 12}, "protetta"},
		{"su senza kill-switch", ipc.VpnStatus{Enabled: true, Tunnel: "wg0", Up: true, HandshakeAge: 12}, "kill-switch NON attivo"},
		{"giu con kill-switch", ipc.VpnStatus{Enabled: true, Tunnel: "wg0", KillSwitch: true, HandshakeAge: -1}, "non in chiaro"},
		{"giu senza kill-switch", ipc.VpnStatus{Enabled: true, Tunnel: "wg0", HandshakeAge: -1}, "in chiaro!"},
	}
	for _, c := range cases {
		if got := vpnLine(c.v); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q non contiene %q", c.name, got, c.want)
		}
	}
	// Il verde richiede entrambi: tunnel su da solo non e' "protetta".
	if strings.Contains(vpnLine(ipc.VpnStatus{Enabled: true, Tunnel: "wg0", Up: true}), "protetta") {
		t.Error("tunnel su senza kill-switch non puo' risultare protetto")
	}
}

func TestSuggestVerdict(t *testing.T) {
	no := []string{
		"/usr/bin/python3.12", "/usr/bin/python3", "/usr/bin/bash", "/bin/sh", "/usr/bin/node",
		"/usr/bin/perl5.38.2", "/usr/bin/env", "/usr/bin/cat", "/usr/bin/curl", "/usr/bin/rsync",
		"/tmp/ssh", "/var/tmp/x", "/dev/shm/x", "/home/u/bin/aws", "/run/user/1000/x", "/mnt/usb/tool",
		"/usr/bin/python3.12 (deleted)",
	}
	for _, e := range no {
		if ok, why := suggestVerdict(e); ok || why == "" {
			t.Errorf("%s: non va suggerito (ok=%v why=%q)", e, ok, why)
		}
	}
	yes := []string{"/usr/bin/ssh", "/usr/bin/kubectl", "/usr/local/bin/terraform", "/opt/google/chrome/chrome", "/snap/bin/helm", "/usr/bin/git (deleted)"}
	for _, e := range yes {
		if ok, why := suggestVerdict(e); !ok {
			t.Errorf("%s: rifiutato a torto (%s)", e, why)
		}
	}
}

func TestRulesViewSuggestionsFollowVerdict(t *testing.T) {
	m := initialModel()
	m.st = ipc.Status{Rules: []ipc.RuleSummary{{Name: "ssh-keys", Paths: []string{".ssh/id_*"}, Allow: []string{"ssh"}}}}
	m.events = []ipc.WireEvent{
		{Action: "blocked", Rule: "ssh-keys", Exe: "/usr/bin/python3.12"},
		{Action: "blocked", Rule: "ssh-keys", Exe: "/var/tmp/x"},
		{Action: "blocked", Rule: "ssh-keys", Exe: "/usr/bin/kubectl"},
	}
	out := m.rulesView()
	for _, e := range []string{"/usr/bin/python3.12", "/var/tmp/x"} {
		if strings.Contains(out, "+"+e) {
			t.Errorf("%s suggerito come autorizzabile", e)
		}
		if !strings.Contains(out, "⛔"+e) {
			t.Errorf("%s deve comparire come NON autorizzare", e)
		}
	}
	if !strings.Contains(out, "+/usr/bin/kubectl") {
		t.Error("un tool legittimo di sistema va suggerito")
	}
}

func TestBlastRadiusStableAndNormalized(t *testing.T) {
	rules := []ruleAllow{
		{Name: "a", Allow: []string{"git", "gh", "docker", "ssh"}},
		{Name: "b", Allow: []string{"/usr/bin/git", "/usr/bin/gh", "docker"}},
		{Name: "c", Allow: []string{"docker"}},
	}
	first := blastRadius(rules)
	// git e /usr/bin/git sono lo stesso binario: prima risultavano due e il rischio era sottostimato.
	if len(first) != 3 || first[0].Exe != "docker" || len(first[0].Rules) != 3 {
		t.Fatalf("atteso docker in 3 regole per primo, git/gh in 2: %+v", first)
	}
	if first[1].Exe != "gh" || first[2].Exe != "git" {
		t.Errorf("a pari merito l'ordine e' alfabetico: %+v", first)
	}
	for i := 0; i < 100; i++ {
		again := blastRadius(rules)
		for j := range again {
			if again[j].Exe != first[j].Exe {
				t.Fatalf("ordine instabile tra due calcoli: %+v vs %+v", first, again)
			}
		}
	}
}

func TestOfflineViewDistinguishesPermissionDenied(t *testing.T) {
	m := initialModel()
	m.connErr = errString("dial unix /run/zt-shield/api.sock: connect: permission denied")
	out := m.offlineView()
	if !strings.Contains(out, "riservato a root") || strings.Contains(out, "non raggiungibile") {
		t.Errorf("un rifiuto di permesso non e' 'demone spento': %q", out)
	}
	m.connErr = errString("dial unix /run/zt-shield/api.sock: connect: no such file or directory")
	out = m.offlineView()
	if !strings.Contains(out, "non raggiungibile") || !strings.Contains(out, "systemctl enable --now zt-shield") {
		t.Errorf("demone assente: serve il percorso da pacchetto: %q", out)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestHostPortBracketsIPv6(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"0.0.0.0", "22"}: "0.0.0.0:22", {"::1", "631"}: "[::1]:631", {"2001:db8::1", "443"}: "[2001:db8::1]:443",
	} {
		port, _ := strconv.Atoi(in[1])
		if got := hostPort(in[0], uint16(port)); got != want {
			t.Errorf("hostPort(%s,%s) = %s, atteso %s", in[0], in[1], got, want)
		}
	}
	m := initialModel()
	m.st = ipc.Status{Listening: []ipc.ListenEntry{{Proto: "tcp6", Addr: "::1", Port: 631, PID: 9, Exe: "/usr/sbin/cupsd"}}}
	if out := m.netView(); !strings.Contains(out, "[::1]:631") {
		t.Errorf("la tab Rete deve mostrare [::1]:631: %q", out)
	}
}
