// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func loadText(t *testing.T, text string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func ruleByName(c *Config, n string) *Rule {
	for i, r := range c.AllRules() {
		if r.Name == n {
			return &c.AllRules()[i]
		}
	}
	return nil
}

func TestAllowExtraAddsToProfileRule(t *testing.T) {
	c, err := loadText(t, "profile: home\nallow_extra:\n  dev-tokens:\n    - /usr/local/bin/k3d\n    - /usr/local/bin/helm\n")
	if err != nil {
		t.Fatal(err)
	}
	r := ruleByName(c, "dev-tokens")
	if r == nil || !slices.Contains(r.Allow, "/usr/local/bin/k3d") || !slices.Contains(r.Allow, "docker") {
		t.Fatalf("k3d aggiunto e docker preservato: %+v", r)
	}
	// Il preset non deve restare alterato per un secondo Load (copie profonde).
	p, _ := Preset("home")
	for _, r := range p.Rules {
		if slices.Contains(r.Allow, "/usr/local/bin/k3d") {
			t.Fatal("il preset condiviso e' stato modificato")
		}
	}
}

func TestAllowExtraRejectsBadEntries(t *testing.T) {
	for _, bad := range []string{"k3d", "/usr/bin/../bin/k3d", "/usr/bin/k*", "relative/k3d"} {
		_, err := loadText(t, "allow_extra:\n  dev-tokens:\n    - \""+bad+"\"\n")
		if err == nil {
			t.Errorf("%q doveva essere rifiutato", bad)
		}
	}
	if _, err := loadText(t, "allow_extra:\n  nonesiste:\n    - /usr/bin/x\n"); err == nil || !strings.Contains(err.Error(), "inesistente") {
		t.Errorf("regola inesistente: %v", err)
	}
}

func TestDisableAndEnableGroups(t *testing.T) {
	c, err := loadText(t, "profile: home\ndisable_rules: [gpg-keys]\nenable_groups: [browsers]\n")
	if err != nil {
		t.Fatal(err)
	}
	if ruleByName(c, "gpg-keys") != nil {
		t.Error("gpg-keys doveva sparire")
	}
	if ruleByName(c, "browser-secrets") == nil {
		t.Error("browsers doveva comparire")
	}
	if ruleByName(c, "ssh-keys") == nil {
		t.Error("le altre regole restano")
	}
	// enable_groups su un gruppo gia' presente non duplica (i nomi devono essere unici).
	if _, err := loadText(t, "profile: home\nenable_groups: [ssh]\n"); err != nil {
		t.Errorf("gruppo gia' presente: %v", err)
	}
	if _, err := loadText(t, "enable_groups: [nope]\n"); err == nil {
		t.Error("gruppo sconosciuto accettato")
	}
	if _, err := loadText(t, "disable_rules: [nope]\n"); err == nil {
		t.Error("disable di regola inesistente accettato")
	}
	if _, err := loadText(t, "disable_rules: [ssh-keys, cloud-creds, dev-tokens, gpg-keys]\n"); err == nil {
		t.Error("disabilitare tutte le regole doveva fallire")
	}
}

func TestAllowExtraOnEnabledGroup(t *testing.T) {
	c, err := loadText(t, "enable_groups: [browsers]\nallow_extra:\n  browser-secrets:\n    - /opt/vivaldi/vivaldi\n")
	if err != nil {
		t.Fatal(err)
	}
	if r := ruleByName(c, "browser-secrets"); r == nil || !slices.Contains(r.Allow, "/opt/vivaldi/vivaldi") {
		t.Fatalf("allow_extra su gruppo abilitato: %+v", r)
	}
}

func TestInstallValidatesBacksUpAndIsAtomic(t *testing.T) {
	cur := os.Getenv("USER")
	if cur == "" {
		cur = "root"
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, "etc", "shield.yaml")
	good := "profile: home\nuser: " + cur + "\n"
	src := filepath.Join(dir, "new.yaml")
	if err := os.WriteFile(src, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	if bk, err := Install(src, dst, now); err != nil || bk != "" {
		t.Fatalf("prima installazione: bk=%q err=%v", bk, err)
	}
	if b, _ := os.ReadFile(dst); string(b) != good {
		t.Fatal("contenuto non copiato")
	}
	// Secondo install: backup del vecchio, nuovo al suo posto.
	good2 := good + "mode: audit\n"
	_ = os.WriteFile(src, []byte(good2), 0o600)
	bk, err := Install(src, dst, now)
	if err != nil || !strings.HasSuffix(bk, "shield.yaml.bak-20261105-100000") {
		t.Fatalf("backup: %q %v", bk, err)
	}
	if b, _ := os.ReadFile(bk); string(b) != good {
		t.Fatal("il backup deve contenere la versione precedente")
	}
	// Config invalido: rifiutato, dst intatto.
	for name, bad := range map[string]string{
		"chiave sconosciuta": "profile: home\nuser: " + cur + "\nblock_poisioning: true\n",
		"regola inesistente": "user: " + cur + "\ndisable_rules: [nope]\n",
		"utente inesistente": "user: utente-che-non-esiste-xyz\n",
		"yaml rotto":         "profile: [\n",
	} {
		_ = os.WriteFile(src, []byte(bad), 0o600)
		if _, err := Install(src, dst, now); err == nil {
			t.Errorf("%s: doveva fallire", name)
		}
		if b, _ := os.ReadFile(dst); string(b) != good2 {
			t.Errorf("%s: il config buono e' stato toccato", name)
		}
	}
	// Symlink come sorgente: rifiutato.
	link := filepath.Join(dir, "lnk.yaml")
	_ = os.Symlink(src, link)
	if _, err := Install(link, dst, now); err == nil {
		t.Error("un symlink come sorgente va rifiutato")
	}
	// Troppo grande.
	_ = os.WriteFile(src, []byte("user: "+cur+"\n#"+strings.Repeat("x", 300<<10)), 0o600)
	if _, err := Install(src, dst, now); err == nil {
		t.Error("file enorme accettato")
	}
	// Nessun residuo temporaneo accanto a dst.
	ents, _ := os.ReadDir(filepath.Dir(dst))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".shield-new-") {
			t.Errorf("residuo temporaneo %s", e.Name())
		}
	}
}

func TestRuleModesAndRemoveAllow(t *testing.T) {
	c, err := loadText(t, "profile: home\nrule_modes:\n  ssh-keys: enforce\nremove_allow:\n  dev-tokens: [cargo, /usr/bin/docker]\n")
	if err != nil {
		t.Fatal(err)
	}
	if r := ruleByName(c, "ssh-keys"); r.Mode != "enforce" || c.EffectiveMode(*r) != "enforce" {
		t.Fatalf("modalita' per regola: %+v", r)
	}
	if r := ruleByName(c, "gpg-keys"); r.Mode != "" || c.EffectiveMode(*r) != "audit" {
		t.Fatalf("le altre ereditano la globale (home = audit): %+v", r)
	}
	if r := ruleByName(c, "dev-tokens"); slices.Contains(r.Allow, "cargo") || !slices.Contains(r.Allow, "git") {
		t.Fatalf("remove_allow per nome: %v", r.Allow)
	}
	for name, txt := range map[string]string{
		"modo sconosciuto":      "rule_modes:\n  ssh-keys: paranoid\n",
		"regola inesistente":    "rule_modes:\n  nope: audit\n",
		"remove su inesistente": "remove_allow:\n  nope: [x]\n",
		"svuota allow":          "remove_allow:\n  gpg-keys: [gpg, gpg-agent, gpgsm]\n",
	} {
		if _, err := loadText(t, txt); err == nil {
			t.Errorf("%s: doveva fallire", name)
		}
	}
}

func TestRuleModeInExtraRulesAndLimits(t *testing.T) {
	ok := "extra_rules:\n  - name: wallet\n    paths: [\".wallet\"]\n    allow: [\"/usr/bin/electrum\"]\n    mode: enforce\n    deny_write: true\n"
	c, err := loadText(t, ok)
	if err != nil {
		t.Fatal(err)
	}
	if r := ruleByName(c, "wallet"); r == nil || c.EffectiveMode(*r) != "enforce" || !r.DenyWrite {
		t.Fatalf("regola personale: %+v", r)
	}
	bad := strings.Replace(ok, "mode: enforce", "mode: forse", 1)
	if _, err := loadText(t, bad); err == nil {
		t.Error("mode non valido accettato")
	}
	if _, err := loadText(t, strings.Replace(ok, "name: wallet", "name: \"a\\nb\"", 1)); err == nil {
		t.Error("nome con a-capo accettato (finirebbe nei log)")
	}
	var b strings.Builder
	b.WriteString("extra_rules:\n")
	for i := 0; i < MaxRules; i++ { // + le 4 del profilo supera il limite
		b.WriteString("  - name: r" + strconv.Itoa(i) + "\n    paths: [x]\n    allow: [/usr/bin/y]\n")
	}
	if _, err := loadText(t, b.String()); err == nil || !strings.Contains(err.Error(), "troppe regole") {
		t.Errorf("limite regole: %v", err)
	}
}

func TestInterfaceListValidation(t *testing.T) {
	for _, ok := range []string{"", "eth0", "enx00e04c478980,wlp1s0", " eth0 , wlan0 ", "lo"} {
		if _, err := loadText(t, "interface: \""+ok+"\"\n"); err != nil {
			t.Errorf("%q doveva passare: %v", ok, err)
		}
	}
	for _, bad := range []string{"eth0,eth0", "eth 0", "eth0;rm", "a/b", "nome-troppo-lungo-xxxxxxxx", "eth0,$(id)"} {
		if _, err := loadText(t, "interface: \""+bad+"\"\n"); err == nil {
			t.Errorf("%q doveva essere rifiutato", bad)
		}
	}
}
