// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package svc

import (
	"context"
	"strings"
	"testing"
)

func TestValidateKillSwitch(t *testing.T) {
	ok := []struct {
		ep, tun string
		lans    []string
	}{
		{"203.0.113.7:51820", "wg0", nil},
		{"[2001:db8::1]:51820", "tide0", []string{"192.168.1.0/24", "10.0.0.0/8"}},
	}
	for _, c := range ok {
		if err := ValidateKillSwitch(c.ep, c.tun, c.lans); err != nil {
			t.Errorf("%v: %v", c, err)
		}
	}
	bad := []struct {
		ep, tun string
		lans    []string
		why     string
	}{
		{"vpn.example.com:51820", "wg0", nil, "nome host"},
		{"203.0.113.7", "wg0", nil, "senza porta"},
		{"203.0.113.7:0", "wg0", nil, "porta 0"},
		{"203.0.113.7:70000", "wg0", nil, "porta troppo alta"},
		{"999.1.1.1:51820", "wg0", nil, "IPv4 inesistente"},
		{"203.0.113.7:51820", "wg0; rm -rf /", nil, "interfaccia con shell"},
		{"203.0.113.7:51820", "", nil, "interfaccia vuota"},
		{"203.0.113.7:51820", "wg0", []string{"192.168.1.0"}, "LAN senza prefisso"},
		{"203.0.113.7:51820", "wg0", []string{"$(id)"}, "LAN con shell"},
	}
	for _, c := range bad {
		if err := ValidateKillSwitch(c.ep, c.tun, c.lans); err == nil {
			t.Errorf("%s: doveva essere rifiutato", c.why)
		}
	}
}

// L'anteprima lancia lo script con --dry-run e SOLO con un profilo noto; l'output e' limitato.
func TestHardenPreview(t *testing.T) {
	var got []string
	old := execCombined
	t.Cleanup(func() { execCombined = old })
	execCombined = func(_ context.Context, name string, args ...string) ([]byte, error) {
		got = append([]string{name}, args...)
		return []byte("diff finto\n"), nil
	}
	if HardenScript() == "" {
		t.Skip("harden_system.sh non trovato in questo albero")
	}
	out, err := HardenPreview("public-wifi")
	if err != nil || !strings.Contains(out, "diff finto") {
		t.Fatalf("anteprima: %q %v", out, err)
	}
	if len(got) != 4 || got[0] != "bash" || got[2] != "public-wifi" || got[3] != "--dry-run" {
		t.Errorf("comando inatteso: %v", got)
	}
	if _, err := HardenPreview("home; reboot"); err == nil {
		t.Error("un profilo non valido va rifiutato")
	}
	execCombined = func(context.Context, string, ...string) ([]byte, error) {
		return []byte(strings.Repeat("x", previewMax+500)), nil
	}
	long, _ := HardenPreview("home")
	if len(long) > previewMax+40 {
		t.Errorf("output non troncato: %d byte", len(long))
	}
}

func TestKillSwitchRefusesBadArgsBeforeRunning(t *testing.T) {
	old := execCombined
	t.Cleanup(func() { execCombined = old })
	called := false
	execCombined = func(context.Context, string, ...string) ([]byte, error) { called = true; return nil, nil }
	if err := KillSwitchOn("vpn.example.com:1", "wg0", nil); err == nil || called {
		t.Errorf("argomenti non validi: nessun comando deve partire (err=%v called=%v)", err, called)
	}
}
