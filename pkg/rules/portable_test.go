// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package rules

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Macchine di prova: nessuna dipende dal filesystem vero.
const (
	srcHost = "profile: home\nuser: alice\n"
	dstHost = "profile: home\nuser: bob\n"
)

func fakeProbe(missing, untrusted map[string]bool) func(string) (bool, error) {
	return func(p string) (bool, error) {
		if missing[p] {
			return false, nil
		}
		if untrusted[p] {
			return true, errors.New("non è di root")
		}
		return true, nil
	}
}

func exportedFrom(t *testing.T, c Choice) []byte {
	t.Helper()
	cfg, err := Apply(srcHost, c)
	if err != nil {
		t.Fatal(err)
	}
	data, _, err := Export(cfg, ExportOptions{Name: "Ufficio", Note: "pilota", Version: "0.0.22", Now: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func hasChange(r ImportResult, sub string) bool {
	for _, c := range r.Changes {
		if strings.Contains(c.Text, sub) {
			return true
		}
	}
	return false
}

func hasText(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func officeChoice() Choice {
	off := false
	return Choice{
		AllowExtra:     map[string][]string{"dev-tokens": {"/usr/libexec/docker/cli-plugins/docker-buildx", "/usr/local/bin/helm"}},
		DisableRules:   []string{"gpg-keys"},
		RuleModes:      map[string]string{"cloud-creds": "enforce", "ssh-keys": "audit"},
		ExtraRules:     []CustomRule{{Name: "contratti", Paths: []string{"Documents/contratti"}, Allow: []string{"/usr/bin/evince"}, Mode: "enforce"}},
		BlockPoisoning: &off,
		Canary:         &CanaryChoice{Enabled: true, Dirs: []string{"Documents"}},
		Interface:      "wlp1s0",
	}
}

func TestExportLeavesOutMachineSpecificThings(t *testing.T) {
	c := officeChoice()
	c.AllowExtra["dev-tokens"] = append(c.AllowExtra["dev-tokens"], "/home/alice/.local/bin/oh-my-posh")
	c.ExtraRules = append(c.ExtraRules, CustomRule{Name: "mio", Paths: []string{"/home/alice/segreto"}, Allow: []string{"/usr/bin/cat"}})
	cfg, err := Apply(srcHost+"vpn:\n  endpoint: 203.0.113.7:51820\n", c)
	if err != nil {
		t.Fatal(err)
	}
	data, left, err := Export(cfg, ExportOptions{Name: "Ufficio", Version: "0.0.22"})
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	for _, bad := range []string{"alice", "wlp1s0", "interface", "vpn", "203.0.113.7", "oh-my-posh", "user:"} {
		if strings.Contains(out, bad) {
			t.Errorf("il profilo non deve contenere %q:\n%s", bad, out)
		}
	}
	for _, good := range []string{"zeroshield-profile", "docker-buildx", "contratti", "gpg-keys", "base_profile: home"} {
		if !strings.Contains(out, good) {
			t.Errorf("il profilo deve contenere %q:\n%s", good, out)
		}
	}
	if !hasText(left, "oh-my-posh") || !hasText(left, "interfaccia di rete") || !hasText(left, "«mio»") {
		t.Errorf("l'elenco di ciò che resta fuori è incompleto: %v", left)
	}
}

func TestExportNothingAndManual(t *testing.T) {
	if _, _, err := Export(srcHost, ExportOptions{}); !errors.Is(err, ErrProfileNothing) {
		t.Errorf("senza scelte atteso ErrProfileNothing, trovato %v", err)
	}
	manual := srcHost + "allow_extra:\n  ssh-keys:\n    - /usr/bin/ssh\n"
	if _, _, err := Export(manual, ExportOptions{}); !errors.Is(err, ErrManual) {
		t.Errorf("scelte scritte a mano: atteso ErrManual, trovato %v", err)
	}
}

func TestRoundTripMerge(t *testing.T) {
	data := exportedFrom(t, officeChoice())
	res, err := PreviewImport(dstHost, data, ImportOptions{probe: fakeProbe(nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "Ufficio" || res.Note != "pilota" || res.ExportedBy != "0.0.22" || len(res.SHA256) != 64 {
		t.Errorf("intestazione alterata: %+v", res)
	}
	for _, want := range []string{"docker-buildx per «dev-tokens»", "Spegne la protezione «gpg-keys»", "regola personale «contratti»", "Spegne il filtro di rete", "Accende il canary"} {
		if !hasChange(res, want) {
			t.Errorf("manca il cambiamento %q in %v", want, res.Changes)
		}
	}
	// Il testo risultante si rilegge e contiene le stesse scelte, senza l'interfaccia della macchina di origine.
	got, err := Parse(res.NewText)
	if err != nil {
		t.Fatal(err)
	}
	if got.Interface != "" {
		t.Errorf("l'interfaccia non deve arrivare dall'altra macchina: %q", got.Interface)
	}
	if len(got.AllowExtra["dev-tokens"]) != 2 || got.Canary == nil || !got.Canary.Enabled {
		t.Errorf("scelte perse: %+v", got)
	}
	if !strings.HasPrefix(res.NewText, "profile: home\nuser: bob\n") {
		t.Errorf("il resto del config di destinazione deve restare intatto:\n%s", res.NewText)
	}
}

func TestImportAsAuditDowngradesEnforce(t *testing.T) {
	data := exportedFrom(t, officeChoice())
	res, err := PreviewImport(dstHost, data, ImportOptions{AsAudit: true, probe: fakeProbe(nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Parse(res.NewText)
	if got.RuleModes["cloud-creds"] != "audit" || got.ExtraRules[0].Mode != "audit" {
		t.Errorf("con AsAudit nessuna modalità deve restare in Blocca: %+v", got)
	}
	if !hasText(res.Warnings, "importata in sola osservazione") {
		t.Errorf("manca l'avviso sulla modalità: %v", res.Warnings)
	}
	// Senza AsAudit le modalità arrivano com'erano.
	res, err = PreviewImport(dstHost, data, ImportOptions{probe: fakeProbe(nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	got, _ = Parse(res.NewText)
	if got.RuleModes["cloud-creds"] != "enforce" {
		t.Errorf("senza AsAudit la modalità del profilo si conserva: %+v", got.RuleModes)
	}
}

func TestImportSkipsUnsafePrograms(t *testing.T) {
	data := exportedFrom(t, officeChoice())
	probe := fakeProbe(map[string]bool{"/usr/local/bin/helm": true}, map[string]bool{"/usr/libexec/docker/cli-plugins/docker-buildx": true})
	res, err := PreviewImport(dstHost, data, ImportOptions{probe: probe})
	if err != nil {
		t.Fatal(err)
	}
	if !hasText(res.Skipped, "docker-buildx non è di proprietà di root") {
		t.Errorf("un binario non di root va scartato e spiegato: %v", res.Skipped)
	}
	if hasChange(res, "docker-buildx") {
		t.Errorf("un binario scartato non deve comparire fra i cambiamenti: %v", res.Changes)
	}
	if !hasText(res.Warnings, "helm non è installato") {
		t.Errorf("un programma assente si segnala: %v", res.Warnings)
	}
	if !hasChange(res, "helm per «dev-tokens»") {
		t.Errorf("un programma assente si importa lo stesso: %v", res.Changes)
	}
}

// Un file costruito a mano può contenere un percorso nella home: l'esportazione non lo scrive mai,
// ma l'importazione non si fida del file.
func TestImportRejectsUserPaths(t *testing.T) {
	hostile := "format: zeroshield-profile\nversion: 1\nchoice:\n  allow_extra:\n    ssh-keys:\n      - /home/mallory/.local/bin/ssh\n      - /tmp/ssh\n      - /usr/bin/ssh\n"
	res, err := PreviewImport(dstHost, []byte(hostile), ImportOptions{probe: fakeProbe(nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 2 || !hasText(res.Skipped, "/home/mallory") || !hasText(res.Skipped, "/tmp/ssh") {
		t.Errorf("i percorsi nelle cartelle di un utente vanno scartati: %v", res.Skipped)
	}
	got, _ := Parse(res.NewText)
	if len(got.AllowExtra["ssh-keys"]) != 1 || got.AllowExtra["ssh-keys"][0] != "/usr/bin/ssh" {
		t.Errorf("deve restare solo il programma di sistema: %+v", got.AllowExtra)
	}
}

func TestImportReplaceVsMerge(t *testing.T) {
	cfg, err := Apply(dstHost, Choice{AllowExtra: map[string][]string{"cloud-creds": {"/usr/local/bin/k9s"}}, Interface: "enp3s0"})
	if err != nil {
		t.Fatal(err)
	}
	data := exportedFrom(t, Choice{AllowExtra: map[string][]string{"dev-tokens": {"/usr/local/bin/helm"}}})
	merged, err := PreviewImport(cfg, data, ImportOptions{probe: fakeProbe(nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := Parse(merged.NewText)
	if len(m.AllowExtra["cloud-creds"]) != 1 || len(m.AllowExtra["dev-tokens"]) != 1 || m.Interface != "enp3s0" {
		t.Errorf("unire conserva ciò che c'era e aggiunge: %+v", m)
	}
	repl, err := PreviewImport(cfg, data, ImportOptions{Replace: true, probe: fakeProbe(nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := Parse(repl.NewText)
	if len(r.AllowExtra["cloud-creds"]) != 0 || len(r.AllowExtra["dev-tokens"]) != 1 {
		t.Errorf("sostituire toglie ciò che il profilo non ha: %+v", r)
	}
	if r.Interface != "enp3s0" {
		t.Errorf("l'interfaccia della macchina resta anche sostituendo: %q", r.Interface)
	}
	if !hasChange(repl, "Non autorizza più /usr/local/bin/k9s") {
		t.Errorf("l'anteprima deve dire cosa si perde: %v", repl.Changes)
	}
}

func TestImportMergeEnableDisableConflict(t *testing.T) {
	// Qui la protezione «cloud-creds» e' spenta; il profilo la accende (enable_groups usa l'id «cloud»).
	cfg, err := Apply(dstHost, Choice{DisableRules: []string{"cloud-creds"}})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("format: zeroshield-profile\nversion: 1\nchoice:\n  enable_groups:\n    - cloud\n")
	res, err := PreviewImport(cfg, data, ImportOptions{probe: fakeProbe(nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Parse(res.NewText)
	for _, d := range got.DisableRules {
		if d == "cloud-creds" {
			t.Errorf("il profilo accende la protezione: non può restare spenta: %+v", got)
		}
	}
}

func TestImportIsIdempotent(t *testing.T) {
	data := exportedFrom(t, officeChoice())
	first, err := PreviewImport(dstHost, data, ImportOptions{probe: fakeProbe(nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := PreviewImport(first.NewText, data, ImportOptions{probe: fakeProbe(nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if !second.Unchanged || second.NewText != first.NewText || len(second.Changes) != 0 {
		t.Errorf("importare due volte lo stesso profilo non deve cambiare niente: %v", second.Changes)
	}
}

func TestParseProfileRejections(t *testing.T) {
	good := "format: zeroshield-profile\nversion: 1\nchoice:\n  disable_rules:\n    - gpg-keys\n"
	if _, sum, err := ParseProfile([]byte(good)); err != nil || len(sum) != 64 {
		t.Fatalf("il profilo minimo deve passare: %v", err)
	}
	cases := map[string]string{
		"vuoto":                "",
		"un altro yaml":        "profile: home\nuser: alice\n",
		"formato sbagliato":    "format: altro\nversion: 1\n",
		"versione mancante":    "format: zeroshield-profile\n",
		"versione più nuova":   "format: zeroshield-profile\nversion: 99\n",
		"chiave sconosciuta":   "format: zeroshield-profile\nversion: 1\nchoice:\n  interface: eth0\n",
		"chiave in cima":       "format: zeroshield-profile\nversion: 1\nuser: root\n",
		"non è yaml":           "{{{ non yaml",
		"nota con carattere 0": "format: zeroshield-profile\nversion: 1\nnote: \"a\\0b\"\n",
	}
	for name, in := range cases {
		if _, _, err := ParseProfile([]byte(in)); err == nil {
			t.Errorf("%s: doveva essere rifiutato", name)
		}
	}
	big := []byte("format: zeroshield-profile\nversion: 1\nnote: " + strings.Repeat("x", ProfileMaxBytes))
	if _, _, err := ParseProfile(big); !errors.Is(err, ErrProfileTooBig) {
		t.Errorf("file enorme: atteso ErrProfileTooBig, trovato %v", err)
	}
}

func TestImportRejectsInvalidValues(t *testing.T) {
	bad := map[string]string{
		"modalità sconosciuta": "choice:\n  rule_modes:\n    ssh-keys: sempre\n",
		"percorso relativo":    "choice:\n  allow_extra:\n    ssh-keys:\n      - ssh\n",
		"glob":                 "choice:\n  allow_extra:\n    ssh-keys:\n      - /usr/bin/*\n",
		"nome regola brutto":   "choice:\n  disable_rules:\n    - \"a: b\"\n",
		"canary con ..":        "choice:\n  canary:\n    enabled: true\n    dirs:\n      - ../etc\n",
		"gruppo inesistente":   "choice:\n  enable_groups:\n    - inesistente\n",
	}
	for name, body := range bad {
		_, err := PreviewImport(dstHost, []byte("format: zeroshield-profile\nversion: 1\n"+body), ImportOptions{probe: fakeProbe(nil, nil)})
		if err == nil {
			t.Errorf("%s: doveva essere rifiutato", name)
		}
	}
}

func TestImportOnManualConfigIsRefused(t *testing.T) {
	manual := dstHost + "disable_rules:\n  - gpg-keys\n"
	data := exportedFrom(t, officeChoice())
	if _, err := PreviewImport(manual, data, ImportOptions{probe: fakeProbe(nil, nil)}); !errors.Is(err, ErrManual) {
		t.Errorf("scelte a mano nel config: atteso ErrManual, trovato %v", err)
	}
}

func TestSHAChangesWithContent(t *testing.T) {
	a := exportedFrom(t, officeChoice())
	c := officeChoice()
	c.DisableRules = nil
	b := exportedFrom(t, c)
	ra, _ := PreviewImport(dstHost, a, ImportOptions{probe: fakeProbe(nil, nil)})
	rb, _ := PreviewImport(dstHost, b, ImportOptions{probe: fakeProbe(nil, nil)})
	rc, _ := PreviewImport(dstHost, a, ImportOptions{probe: fakeProbe(nil, nil)})
	if ra.SHA256 == rb.SHA256 || ra.SHA256 != rc.SHA256 {
		t.Errorf("l'impronta deve seguire il contenuto: %s %s %s", ra.SHA256, rb.SHA256, rc.SHA256)
	}
}

func TestBaseProfileMismatchWarns(t *testing.T) {
	data := exportedFrom(t, officeChoice()) // origine: home
	res, err := PreviewImport("profile: corporate\nuser: bob\n", data, ImportOptions{probe: fakeProbe(nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if !hasText(res.Warnings, "profilo di base") {
		t.Errorf("profili diversi vanno segnalati: %v", res.Warnings)
	}
}

func TestPreviewDoesNotTouchInput(t *testing.T) {
	data := exportedFrom(t, officeChoice())
	before := fmt.Sprint(dstHost)
	if _, err := PreviewImport(dstHost, data, ImportOptions{probe: fakeProbe(nil, nil)}); err != nil {
		t.Fatal(err)
	}
	if dstHost != before {
		t.Error("l'anteprima non deve modificare il config di partenza")
	}
}

func TestApplyPlanRequiresMatchingHash(t *testing.T) {
	data := exportedFrom(t, officeChoice())
	opt := ImportOptions{probe: fakeProbe(nil, nil)}
	prev, err := PreviewImport(dstHost, data, opt)
	if err != nil {
		t.Fatal(err)
	}
	text, err := ApplyPlan(dstHost, data, opt, prev.SHA256)
	if err != nil || text != prev.NewText {
		t.Fatalf("con l'impronta giusta si applica ciò che si è visto: %v", err)
	}
	if _, err := ApplyPlan(dstHost, data, opt, ""); err == nil {
		t.Error("senza impronta non si applica")
	}
	if _, err := ApplyPlan(dstHost, data, opt, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "è cambiato") {
		t.Errorf("impronta diversa = file scambiato: %v", err)
	}
	if _, err := ApplyPlan(prev.NewText, data, opt, prev.SHA256); err == nil || !strings.Contains(err.Error(), "niente da applicare") {
		t.Errorf("già applicato: %v", err)
	}
}

func TestReadProfileFile(t *testing.T) {
	dir := t.TempDir()
	ok := dir + "/ok.yaml"
	if err := os.WriteFile(ok, []byte("format: zeroshield-profile\nversion: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadProfileFile(ok); err != nil || len(b) == 0 {
		t.Errorf("file normale: %v", err)
	}
	if _, err := ReadProfileFile(dir); err == nil {
		t.Error("una cartella non è un profilo")
	}
	if _, err := ReadProfileFile(dir + "/manca.yaml"); err == nil {
		t.Error("file inesistente")
	}
	big := dir + "/big.yaml"
	if err := os.WriteFile(big, make([]byte, ProfileMaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProfileFile(big); !errors.Is(err, ErrProfileTooBig) {
		t.Errorf("file enorme: %v", err)
	}
}
