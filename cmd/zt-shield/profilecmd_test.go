// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"zt-shield/pkg/rules"
)

const cliHost = "profile: home\nuser: alice\n"

func cliCfg(t *testing.T) string {
	t.Helper()
	cfg, err := rules.Apply(cliHost, rules.Choice{
		AllowExtra: map[string][]string{"dev-tokens": {"/usr/bin/git"}},
		RuleModes:  map[string]string{"cloud-creds": "enforce"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func runCLI(t *testing.T, cfg string, apply func(string) error, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = profileMain(args, &o, &e, func() (string, error) { return cfg, nil }, apply,
		func() time.Time { return time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC) })
	return code, o.String(), e.String()
}

func TestProfileExportToFileAndNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ufficio.yaml")
	code, out, errOut := runCLI(t, cliCfg(t), nil, "export", "-name", "Ufficio", "-o", path)
	if code != 0 || !strings.Contains(out, path) {
		t.Fatalf("export: code=%d out=%q err=%q", code, out, errOut)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "name: Ufficio") || !strings.Contains(string(b), "zeroshield-profile") {
		t.Errorf("contenuto inatteso:\n%s", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("permessi %v, attesi 0644", fi.Mode().Perm())
	}
	// Seconda volta: rifiuta; con -f sovrascrive.
	if code, _, errOut := runCLI(t, cliCfg(t), nil, "export", "-o", path); code == 0 || !strings.Contains(errOut, "esiste già") {
		t.Errorf("non deve sovrascrivere senza -f: code=%d err=%q", code, errOut)
	}
	if code, _, _ := runCLI(t, cliCfg(t), nil, "export", "-f", "-o", path); code != 0 {
		t.Errorf("con -f deve sovrascrivere: %d", code)
	}
}

func TestProfileExportStdoutAndNothing(t *testing.T) {
	code, out, _ := runCLI(t, cliCfg(t), nil, "export")
	if code != 0 || !strings.HasPrefix(out, "# Profilo ZeroShield") {
		t.Errorf("senza -o scrive su stdout: code=%d out=%q", code, out)
	}
	if code, _, errOut := runCLI(t, cliHost, nil, "export"); code == 0 || !strings.Contains(errOut, "non ci sono scelte") {
		t.Errorf("senza scelte deve spiegare: code=%d err=%q", code, errOut)
	}
}

func exportFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.yaml")
	if code, _, errOut := runCLI(t, cliCfg(t), nil, "export", "-o", path); code != 0 {
		t.Fatalf("export: %s", errOut)
	}
	return path
}

func TestProfileImportPreviewWritesNothing(t *testing.T) {
	called := false
	apply := func(string) error { called = true; return nil }
	code, out, _ := runCLI(t, cliHost, apply, "import", exportFile(t))
	if code != 0 || called {
		t.Fatalf("senza -yes non si applica: code=%d called=%v", code, called)
	}
	for _, want := range []string{"Cosa cambierebbe", "/usr/bin/git per «dev-tokens»", "Impronta SHA-256", "Non è stato scritto nulla"} {
		if !strings.Contains(out, want) {
			t.Errorf("manca %q nell'anteprima:\n%s", want, out)
		}
	}
	// Di norma le modalità si importano in sola osservazione.
	if !strings.Contains(out, "sola osservazione") {
		t.Errorf("manca l'avviso sulle modalità:\n%s", out)
	}
}

func TestProfileImportYesApplies(t *testing.T) {
	var got string
	code, out, errOut := runCLI(t, cliHost, func(s string) error { got = s; return nil }, "import", "-yes", exportFile(t))
	if code != 0 || !strings.Contains(out, "Applicato") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
	c, err := rules.Parse(got)
	if err != nil || len(c.AllowExtra["dev-tokens"]) != 1 {
		t.Errorf("config applicato inatteso: %v %+v", err, c)
	}
	if c.RuleModes["cloud-creds"] != "audit" {
		t.Errorf("default: modalità in sola osservazione, trovato %q", c.RuleModes["cloud-creds"])
	}
	// Con -keep-modes la modalità del profilo resta.
	_, _, _ = runCLI(t, cliHost, func(s string) error { got = s; return nil }, "import", "-yes", "-keep-modes", exportFile(t))
	if c, _ := rules.Parse(got); c.RuleModes["cloud-creds"] != "enforce" {
		t.Errorf("-keep-modes deve conservare enforce: %q", c.RuleModes["cloud-creds"])
	}
}

func TestProfileImportErrors(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "x.yaml")
	_ = os.WriteFile(bad, []byte("profile: home\nuser: x\n"), 0o600)
	if code, _, errOut := runCLI(t, cliHost, nil, "import", bad); code == 0 || !strings.Contains(errOut, "non è un profilo") {
		t.Errorf("file non valido: code=%d err=%q", code, errOut)
	}
	if code, _, _ := runCLI(t, cliHost, nil, "import", filepath.Join(t.TempDir(), "manca.yaml")); code == 0 {
		t.Error("file inesistente deve fallire")
	}
	if code, _, _ := runCLI(t, cliHost, nil); code != 2 {
		t.Errorf("senza argomenti: usage (2), trovato %d", code)
	}
	if code, _, _ := runCLI(t, cliHost, nil, "import"); code != 2 {
		t.Errorf("import senza file: usage (2), trovato %d", code)
	}
	// Applicazione che fallisce: errore, non «Applicato».
	code, out, errOut := runCLI(t, cliHost, func(string) error { return errors.New("pkexec annullato") }, "import", "-yes", exportFile(t))
	if code == 0 || strings.Contains(out, "Applicato") || !strings.Contains(errOut, "pkexec annullato") {
		t.Errorf("un fallimento non va nascosto: code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestProfileImportSameTwiceSaysNoDifference(t *testing.T) {
	f := exportFile(t)
	var applied string
	_, _, _ = runCLI(t, cliHost, func(s string) error { applied = s; return nil }, "import", "-yes", "-keep-modes", f)
	called := false
	code, out, _ := runCLI(t, applied, func(string) error { called = true; return nil }, "import", "-yes", "-keep-modes", f)
	if code != 0 || called || !strings.Contains(out, "Nessuna differenza") {
		t.Errorf("riapplicare lo stesso profilo non deve riscrivere: code=%d called=%v out=%q", code, called, out)
	}
}
