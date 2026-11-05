// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package rules

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = "# config di prova\nprofile: home\nuser: alice # mio\n\ncanary:\n  enabled: false\n"

func TestApplyKeepsRestAndIsIdempotent(t *testing.T) {
	c := Choice{AllowExtra: map[string][]string{"dev-tokens": {"/usr/local/bin/k3d", "/usr/local/bin/helm"}}, DisableRules: []string{"gpg-keys"}}
	out, err := Apply(sample, c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, sample) {
		t.Fatalf("il resto del file deve restare identico:\n%s", out)
	}
	again, err := Apply(out, c)
	if err != nil || again != out {
		t.Fatalf("applicare due volte lo stesso risultato cambia il file (err=%v)", err)
	}
	got, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.AllowExtra["dev-tokens"]) != 2 || got.DisableRules[0] != "gpg-keys" {
		t.Fatalf("round-trip: %+v", got)
	}
	// Le scelte cambiano: si rimpiazza il blocco senza duplicarlo.
	out2, _ := Apply(out, Choice{EnableGroups: []string{"browsers"}})
	if strings.Count(out2, blockBegin) != 1 || strings.Contains(out2, "k3d") || !strings.HasPrefix(out2, sample) {
		t.Fatalf("blocco non rimpiazzato:\n%s", out2)
	}
	// Scelta vuota: il blocco sparisce e il file torna com'era (a meno di una riga vuota).
	out3, _ := Apply(out2, Choice{})
	if strings.Contains(out3, "ZeroShield GUI") || !strings.HasPrefix(out3, sample) {
		t.Fatalf("blocco non rimosso:\n%s", out3)
	}
}

func TestManualKeysRefused(t *testing.T) {
	txt := sample + "disable_rules: [gpg-keys]\n"
	if _, err := Parse(txt); !errors.Is(err, ErrManual) {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := Apply(txt, Choice{EnableGroups: []string{"browsers"}}); !errors.Is(err, ErrManual) {
		t.Fatalf("Apply: %v", err)
	}
}

func TestRenderRefusesHostileValues(t *testing.T) {
	// Percorsi con a-capo, glob, relativi o non puliti non devono arrivare nel config.
	for _, evil := range []string{"/opt/x\nprofile: paranoid", "/opt/*", "relativo/x", "/opt/../bin/x", "/opt/x\x00"} {
		if _, err := Apply("profile: home\n", Choice{AllowExtra: map[string][]string{"ssh-keys": {evil}}}); err == nil {
			t.Errorf("%q doveva essere rifiutato", evil)
		}
	}
	if _, err := Apply("profile: home\n", Choice{DisableRules: []string{"a: b"}}); err == nil {
		t.Error("nome regola ostile accettato")
	}
	// Un percorso valido ma con caratteri YAML speciali viene quotato e fa il giro intero.
	odd := "/opt/we ird: #dir/tool"
	out, err := Apply("profile: home\n", Choice{AllowExtra: map[string][]string{"ssh-keys": {odd}}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(out)
	if err != nil || got.AllowExtra["ssh-keys"][0] != odd {
		t.Fatalf("round-trip: %v %+v", err, got)
	}
}

func TestNoBlockOnEmpty(t *testing.T) {
	out, err := Apply(sample, Choice{})
	if err != nil || out != sample {
		t.Fatalf("niente scelte = file invariato: %v", err)
	}
}

func TestVerdict(t *testing.T) {
	cases := map[string]bool{
		"/usr/local/bin/k3d": true, "/usr/bin/kubectl": true, "/opt/google/chrome/chrome": true,
		"/usr/bin/cat": false, "/usr/bin/bash": false, "/usr/bin/python3.12": false,
		"/tmp/ssh": false, "/home/u/.local/bin/oh-my-posh": false, "/usr/bin/curl": false,
	}
	for exe, want := range cases {
		if ok, why := Verdict(exe); ok != want || (!ok && why == "") {
			t.Errorf("%s: ok=%v why=%q, atteso %v", exe, ok, why, want)
		}
	}
}

func TestTrustedAndResolve(t *testing.T) {
	// Un binario in una dir temporanea dell'utente NON e' affidabile (non e' di root).
	dir := t.TempDir()
	exe := filepath.Join(dir, "tool")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if err := Trusted(exe); err == nil {
			t.Error("un binario dell'utente non deve essere affidabile")
		}
	}
	if err := Trusted("/usr/bin/env"); err != nil {
		t.Errorf("/usr/bin/env deve essere affidabile: %v", err)
	}
	link := filepath.Join(dir, "lnk")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}
	real, ok := Resolve(dir, link)
	want, _ := filepath.EvalSymlinks(exe)
	if !ok || real != want {
		t.Errorf("symlink non seguito: %q %v", real, ok)
	}
	if _, ok := Resolve(dir, "a/b"); ok {
		t.Error("nome relativo con directory deve essere rifiutato")
	}
	if _, ok := Resolve(dir, "questo-binario-non-esiste-xyz"); ok {
		t.Error("binario inesistente")
	}
	if p, ok := Resolve(dir, "env"); !ok || !strings.HasSuffix(p, "/env") {
		t.Errorf("env via PATH: %q %v", p, ok)
	}
}

func TestCatalogRulesExist(t *testing.T) {
	known := map[string]bool{"ssh-keys": true, "cloud-creds": true, "dev-tokens": true, "gpg-keys": true, "browser-secrets": true}
	seen := map[string]bool{}
	for _, tl := range Tools {
		if seen[tl.ID] || len(tl.Names) == 0 || len(tl.Rules) == 0 {
			t.Errorf("voce incompleta o duplicata: %+v", tl)
		}
		seen[tl.ID] = true
		for _, r := range tl.Rules {
			if !known[r] {
				t.Errorf("%s: regola %q inesistente", tl.ID, r)
			}
		}
	}
}
