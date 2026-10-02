// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Regressione fix: git non deve leggere le chiavi SSH (usa il binario ssh).
func TestGitNotInSSHKeys(t *testing.T) {
	c, _ := Preset("home")
	for _, r := range c.Rules {
		if r.Name != "ssh-keys" {
			continue
		}
		for _, a := range r.Allow {
			if a == "git" {
				t.Error("git in ssh-keys: canale di lettura via hash-object")
			}
		}
	}
}

func TestWideSubnetRejected(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "10.0.0.0/4", "0.0.0.0/1"} {
		c, _ := Preset("home")
		c.BlockSubnets = []string{cidr}
		if err := c.Validate(); err == nil {
			t.Errorf("%s accettato: stacca tutta la rete", cidr)
		}
	}
	c, _ := Preset("home")
	c.BlockSubnets = []string{"192.168.1.50/32", "10.0.0.0/8"}
	if err := c.Validate(); err != nil {
		t.Errorf("CIDR legittimi rifiutati: %v", err)
	}
}

func TestEmptyAllowAndDupesRejected(t *testing.T) {
	c, _ := Preset("home")
	c.Rules = append(c.Rules, Rule{Name: "vuota", Paths: []string{".x"}, Allow: nil})
	if err := c.Validate(); err == nil {
		t.Error("allow vuota accettata: deny-all silenzioso")
	}
	c, _ = Preset("home")
	c.Rules = append(c.Rules, Rule{Name: "ssh-keys", Paths: []string{".x"}, Allow: []string{"cat"}})
	if err := c.Validate(); err == nil {
		t.Error("nome duplicato accettato: log ambigui")
	}
}

func TestDenyWriteParsing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	yaml := "profile: home\nextra_rules:\n  - name: rootca\n    paths: [\".pki/ca.crt\"]\n    allow: [\"openssl\"]\n    deny_write: true\n"
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range c.AllRules() {
		if r.Name == "rootca" {
			found = true
			if !r.DenyWrite {
				t.Error("deny_write perso nel parsing")
			}
		}
	}
	if !found {
		t.Error("extra_rule rootca sparita")
	}
	// Default: preset senza deny_write.
	base, _ := Preset("home")
	for _, r := range base.Rules {
		if r.DenyWrite {
			t.Errorf("regola builtin %q con deny_write inatteso", r.Name)
		}
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("profile: home\nblock_poisioning: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Error("refuso block_poisioning ignorato in silenzio")
	}
}

// Fuzz: parsing+validazione non devono mai panicsare su input arbitrari.
// `go test` esegue solo il seed corpus; `go test -fuzz` per esplorare.
func FuzzConfigLoad(f *testing.F) {
	seeds := []string{
		"profile: home\nmode: enforce\n",
		"profile: public-wifi\nblock_subnets: [\"10.0.0.0/8\"]\n",
		"profile: [1,2\n",
		"\x00\x01\x02",
		"rules:\n  - name: x\n    paths: []\n",
		"block_subnets: [\"0.0.0.0/0\"]\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		p := filepath.Join(t.TempDir(), "f.yaml")
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Skip()
		}
		_, _ = Load(p) // solo assenza di panic, esito libero
	})
}
