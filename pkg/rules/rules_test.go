// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package rules

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
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

func TestCustomRulesRoundTripAndValidation(t *testing.T) {
	txt := "profile: home\nuser: alice\n"
	c := Choice{
		RuleModes:   map[string]string{"ssh-keys": "enforce"},
		RemoveAllow: map[string][]string{"dev-tokens": {"cargo"}},
		ExtraRules: []CustomRule{{Name: "wallet", Paths: []string{".wallet", "Documents/*.kdbx"},
			Allow: []string{"/usr/bin/keepassxc"}, DenyWrite: true, Mode: "enforce"}},
	}
	out, err := Apply(txt, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(out); err != nil {
		t.Fatalf("il demone accetterebbe? %v\n%s", err, out)
	}
	got, err := Parse(out)
	if err != nil || len(got.ExtraRules) != 1 || got.ExtraRules[0].Name != "wallet" || !got.ExtraRules[0].DenyWrite || got.RuleModes["ssh-keys"] != "enforce" {
		t.Fatalf("round-trip: %v %+v", err, got)
	}
	m := BuildModel(out, t.TempDir())
	if m.Error != "" || len(m.MyRules) != 1 || m.MyRules[0].EffectiveMode != "enforce" {
		t.Fatalf("modello: %+v", m)
	}
	for _, g := range m.Groups {
		if g.ID == "ssh" && (g.Mode != "enforce" || g.ModeSet != "enforce") {
			t.Errorf("ssh: %+v", g)
		}
		if g.ID == "gpg" && (g.Mode != "audit" || g.ModeSet != "") {
			t.Errorf("gpg eredita la globale: %+v", g)
		}
		if g.ID == "tokens" && len(g.Removed) != 1 {
			t.Errorf("tokens: programma tolto non riportato: %+v", g)
		}
	}
	bad := map[string]CustomRule{
		"nome vuoto":      {Name: "", Paths: []string{"x"}, Allow: []string{"/usr/bin/y"}},
		"nome riservato":  {Name: "ssh-keys", Paths: []string{"x"}, Allow: []string{"/usr/bin/y"}},
		"nome con spazio": {Name: "mio wallet", Paths: []string{"x"}, Allow: []string{"/usr/bin/y"}},
		"nessun percorso": {Name: "a", Allow: []string{"/usr/bin/y"}},
		"home intera":     {Name: "a", Paths: []string{"."}, Allow: []string{"/usr/bin/y"}},
		"tutto":           {Name: "a", Paths: []string{"/"}, Allow: []string{"/usr/bin/y"}},
		"etc":             {Name: "a", Paths: []string{"/etc"}, Allow: []string{"/usr/bin/y"}},
		"glob totale":     {Name: "a", Paths: []string{"*"}, Allow: []string{"/usr/bin/y"}},
		"risale":          {Name: "a", Paths: []string{"../x"}, Allow: []string{"/usr/bin/y"}},
		"nessun exe":      {Name: "a", Paths: []string{"x"}},
		"exe relativo":    {Name: "a", Paths: []string{"x"}, Allow: []string{"keepassxc"}},
		"exe con jolly":   {Name: "a", Paths: []string{"x"}, Allow: []string{"/usr/bin/*"}},
		"modo strano":     {Name: "a", Paths: []string{"x"}, Allow: []string{"/usr/bin/y"}, Mode: "boh"},
	}
	for n, r := range bad {
		if _, err := Apply(txt, Choice{ExtraRules: []CustomRule{r}}); err == nil {
			t.Errorf("%s: doveva essere rifiutato", n)
		}
	}
	dup := Choice{ExtraRules: []CustomRule{c.ExtraRules[0], c.ExtraRules[0]}}
	if _, err := Apply(txt, dup); err == nil {
		t.Error("regola duplicata accettata")
	}
	// extra_rules a mano: le regole personali sono spente, il resto no
	manual := txt + "extra_rules:\n  - name: mia\n    paths: [x]\n    allow: [/usr/bin/y]\n"
	if _, err := Apply(manual, Choice{ExtraRules: c.ExtraRules}); !errors.Is(err, ErrManualRules) {
		t.Errorf("extra_rules a mano: %v", err)
	}
	if _, err := Apply(manual, Choice{DisableRules: []string{"gpg-keys"}}); err != nil {
		t.Errorf("il resto della GUI deve funzionare: %v", err)
	}
	if mm := BuildModel(manual, t.TempDir()); !mm.ManualRules || len(mm.Custom) != 1 {
		t.Errorf("modello con extra_rules a mano: %+v", mm)
	}
}

func TestPreview(t *testing.T) {
	home := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(home, "Documents"), 0o755))
	must(os.MkdirAll(filepath.Join(home, ".wallet"), 0o755))
	for _, f := range []string{"Documents/a.kdbx", "Documents/b.kdbx", "Documents/note.txt", ".wallet/w1", ".wallet/w2"} {
		must(os.WriteFile(filepath.Join(home, f), []byte("x"), 0o600))
	}
	r := Preview(home, []string{"Documents/*.kdbx", ".wallet", "non-esiste"})
	if r.Matched != 4 || len(r.Missing) != 1 || len(r.Errors) != 0 {
		t.Fatalf("anteprima: %+v", r)
	}
	if r2 := Preview(home, []string{"/etc"}); len(r2.Errors) == 0 || r2.Matched != 0 {
		t.Fatalf("troppo largo deve essere un errore: %+v", r2)
	}
	if r3 := Preview(home, []string{"mai-esistito"}); len(r3.Warnings) == 0 {
		t.Errorf("percorso inesistente: nessun avviso: %+v", r3)
	}
	// Tanti file: avviso di troppo largo.
	big := filepath.Join(home, "big")
	must(os.MkdirAll(big, 0o755))
	for i := 0; i < manyFilesLimit+5; i++ {
		must(os.WriteFile(filepath.Join(big, "f"+strconv.Itoa(i)), nil, 0o600))
	}
	if r4 := Preview(home, []string{"big"}); r4.Matched <= manyFilesLimit || len(r4.Warnings) == 0 {
		t.Errorf("avviso cartella enorme: %+v", r4)
	}
	// I symlink non si seguono: una cartella che punta altrove non fa contare i file di la'.
	must(os.Symlink("/usr/bin", filepath.Join(home, "lnk")))
	if r5 := Preview(home, []string{"lnk"}); r5.Matched > 0 {
		t.Errorf("symlink seguito: %+v", r5)
	}
}

func TestInterfaceChoice(t *testing.T) {
	txt := "profile: home\nuser: alice\n"
	out, err := Apply(txt, Choice{Interface: "enx00e04c478980, wlp1s0 "})
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(out); err != nil {
		t.Fatalf("il demone accetterebbe? %v\n%s", err, out)
	}
	got, _ := Parse(out)
	if got.Interface != "enx00e04c478980,wlp1s0" {
		t.Fatalf("normalizzata (spazi tolti): %q", got.Interface)
	}
	m := BuildModel(out, t.TempDir())
	if m.Choice.Interface != "enx00e04c478980,wlp1s0" || m.ManualInterface {
		t.Fatalf("modello: %+v", m)
	}
	// Automatica: la scelta vuota toglie il blocco.
	back, _ := Apply(out, Choice{})
	if strings.Contains(back, "interface") {
		t.Errorf("l'automatica deve togliere la chiave:\n%s", back)
	}
	for _, bad := range []string{"eth 0", "a;b", "x/y", "troppolungoxxxxxxxxx", "eth0,eth0"} {
		if _, err := Apply(txt, Choice{Interface: bad}); err == nil {
			t.Errorf("%q doveva essere rifiutato", bad)
		}
	}
	// `interface` a mano: la GUI non la sovrascrive, ma il resto resta modificabile.
	manual := txt + "interface: \"eth0,lo\"\n"
	if _, err := Apply(manual, Choice{Interface: "wlan0"}); !errors.Is(err, ErrManualInterface) {
		t.Errorf("interface a mano: %v", err)
	}
	if _, err := Apply(manual, Choice{DisableRules: []string{"gpg-keys"}}); err != nil {
		t.Errorf("il resto della GUI deve funzionare: %v", err)
	}
	if mm := BuildModel(manual, t.TempDir()); !mm.ManualInterface || mm.BaseInterface != "eth0,lo" || mm.Manual {
		t.Errorf("modello con interface a mano: %+v", mm)
	}
}

func TestHelpersAreOnlyListedWhenPresentAndTrusted(t *testing.T) {
	m := BuildModel("profile: home\nuser: alice\n", t.TempDir())
	if len(m.Helpers) != len(Helpers) {
		t.Fatalf("helper nel modello: %d", len(m.Helpers))
	}
	for _, h := range m.Helpers {
		for _, p := range h.Found {
			if err := Trusted(p); err != nil {
				t.Errorf("%s: %s suggerito ma non affidabile: %v", h.ID, p, err)
			}
			if _, err := os.Stat(p); err != nil {
				t.Errorf("%s: %s suggerito ma non esiste", h.ID, p)
			}
		}
	}
}

// Il catalogo contiene l'agente SSH di GNOME e punta a una regola che esiste davvero tra i gruppi predefiniti.
func TestCatalogHasGnomeSSHAgent(t *testing.T) {
	tool, ok := ToolByID("gcr-ssh-agent")
	if !ok {
		t.Fatal("gcr-ssh-agent manca dal catalogo")
	}
	if len(tool.Names) != 1 || tool.Names[0] != "/usr/libexec/gcr-ssh-agent" {
		t.Errorf("percorso inatteso: %v", tool.Names)
	}
	if len(tool.Rules) != 1 || tool.Rules[0] != "ssh-keys" {
		t.Errorf("regole inattese: %v", tool.Rules)
	}
}

// Funzioni attivabili con un pulsante: la scelta finisce nel blocco gestito, si rilegge identica e rispetta le chiavi scritte a mano.
func TestFeatureChoicesRoundTrip(t *testing.T) {
	off := false
	c := Choice{BlockPoisoning: &off, Canary: &CanaryChoice{Enabled: true, Dirs: []string{"Documents", "Scrivania", "Documents"}}}
	text, err := Apply("profile: home\nuser: u\n", c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"block_poisoning: false", "canary:", "enabled: true", "- Documents", "- Scrivania"} {
		if !strings.Contains(text, want) {
			t.Errorf("manca %q nel blocco:\n%s", want, text)
		}
	}
	if strings.Count(text, "Documents") != 1 {
		t.Errorf("cartella duplicata:\n%s", text)
	}
	back, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if back.BlockPoisoning == nil || *back.BlockPoisoning || back.Canary == nil || !back.Canary.Enabled || len(back.Canary.Dirs) != 2 {
		t.Errorf("rilettura diversa: %+v", back)
	}
	// Acceso (default) e canary spento non si scrivono: il blocco sparisce.
	on := true
	empty, err := Apply(text, Choice{BlockPoisoning: &on, Canary: &CanaryChoice{Enabled: false}})
	if err != nil || strings.Contains(empty, "block_poisoning") || strings.Contains(empty, "canary") {
		t.Errorf("il blocco doveva sparire: %v\n%s", err, empty)
	}
}

func TestFeatureManualKeysAreRespected(t *testing.T) {
	off := false
	if _, err := Apply("profile: home\nuser: u\nblock_poisoning: true\n", Choice{BlockPoisoning: &off}); err != ErrManualFeature {
		t.Errorf("block_poisoning scritto a mano: atteso ErrManualFeature, ottenuto %v", err)
	}
	if _, err := Apply("profile: home\nuser: u\ncanary:\n  enabled: true\n", Choice{Canary: &CanaryChoice{Enabled: true}}); err != ErrManualFeature {
		t.Errorf("canary scritto a mano: atteso ErrManualFeature, ottenuto %v", err)
	}
	if _, err := Apply("profile: home\nuser: u\n", Choice{Canary: &CanaryChoice{Enabled: true, Dirs: []string{"../etc"}}}); err == nil {
		t.Error("una cartella con .. va rifiutata")
	}
}

func TestModelFeaturesFromConfig(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, "Documents"), 0o755)
	m := BuildModel("profile: home\nuser: u\n", home)
	if !m.Features.BlockPoisoning || m.Features.CanaryEnabled || len(m.Features.CanaryCandidates) != 1 || m.Features.CanaryCandidates[0] != "Documents" {
		t.Errorf("funzioni di partenza inattese: %+v", m.Features)
	}
	off := false
	text, _ := Apply("profile: home\nuser: u\n", Choice{BlockPoisoning: &off, Canary: &CanaryChoice{Enabled: true, Dirs: []string{"Documents"}}})
	m = BuildModel(text, home)
	if m.Features.BlockPoisoning || !m.Features.CanaryEnabled || m.Features.ManualCanary {
		t.Errorf("funzioni dopo la scelta inattese: %+v", m.Features)
	}
}
