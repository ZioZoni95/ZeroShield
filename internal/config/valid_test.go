// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"path/filepath"
	"strings"
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

func TestVpnValidation(t *testing.T) {
	c, _ := Preset("home")
	if err := c.Validate(); err != nil {
		t.Fatalf("preset senza vpn deve passare: %v", err)
	}
	c.Vpn = VpnConfig{Enabled: true}
	if err := c.Validate(); err == nil {
		t.Error("vpn senza endpoint/tunnel accettato: rete morta garantita")
	}
	c.Vpn = VpnConfig{Enabled: true, Endpoint: "203.0.113.7:51820", Tunnel: "wg0",
		AllowLAN: []string{"192.168.1.0/24"}}
	if err := c.Validate(); err != nil {
		t.Errorf("vpn completa rifiutata: %v", err)
	}
	c.Vpn.AllowLAN = []string{"nope"}
	if err := c.Validate(); err == nil {
		t.Error("allow_lan invalido accettato")
	}
}

// Il kill-switch e' sbagliato in modo grave se un valore malformato arriva allo
// script: qui si ferma prima, con un messaggio.
func TestVpnEndpointTunnelTable(t *testing.T) {
	ok := []VpnConfig{
		{Endpoint: "203.0.113.7:51820", Tunnel: "wg0"},
		{Endpoint: "[2001:db8::1]:51820", Tunnel: "proton"},
		{Endpoint: "10.0.0.1:1", Tunnel: "wg-proton_1.x", AllowLAN: []string{"192.168.1.0/24", "fd00::/8"}},
		{Endpoint: "10.0.0.1:65535", Tunnel: "abcdefghijklmno"}, // 15 caratteri
	}
	for _, v := range ok {
		v.Enabled = true
		if err := validateVpn(v); err != nil {
			t.Errorf("%+v rifiutato: %v", v, err)
		}
	}
	bad := map[string]VpnConfig{
		"nome host":             {Endpoint: "vpn.example.com:51820", Tunnel: "wg0"},
		"senza porta":           {Endpoint: "203.0.113.7", Tunnel: "wg0"},
		"porta 0":               {Endpoint: "203.0.113.7:0", Tunnel: "wg0"},
		"porta oltre 65535":     {Endpoint: "203.0.113.7:70000", Tunnel: "wg0"},
		"porta non numerica":    {Endpoint: "203.0.113.7:abc", Tunnel: "wg0"},
		"IPv6 senza parentesi":  {Endpoint: "2001:db8::1:51820", Tunnel: "wg0"},
		"iniezione nell'IP":     {Endpoint: "1.2.3.4; flush ruleset:51820", Tunnel: "wg0"},
		"tunnel con spazio":     {Endpoint: "203.0.113.7:51820", Tunnel: "wg 0"},
		"tunnel con ;":          {Endpoint: "203.0.113.7:51820", Tunnel: "wg0;ls"},
		"tunnel 16 caratteri":   {Endpoint: "203.0.113.7:51820", Tunnel: "abcdefghijklmnop"},
		"tunnel con slash":      {Endpoint: "203.0.113.7:51820", Tunnel: "../wg0"},
		"allow_lan non CIDR":    {Endpoint: "203.0.113.7:51820", Tunnel: "wg0", AllowLAN: []string{"192.168.1.1"}},
		"allow_lan con comando": {Endpoint: "203.0.113.7:51820", Tunnel: "wg0", AllowLAN: []string{"10.0.0.0/8; drop"}},
	}
	for name, v := range bad {
		v.Enabled = true
		if err := validateVpn(v); err == nil {
			t.Errorf("%s: accettato %+v", name, v)
		}
	}
}

func TestVpnProtonStyle(t *testing.T) {
	// Stile ProtonVPN: endpoint + tunnel dal .conf, senza connettere nulla.
	// Solo parsing+validazione: nessuna rete toccata, nessun privilegio.
	p := filepath.Join(t.TempDir(), "p.yaml")
	yaml := "profile: public-wifi\nuser: test\nvpn:\n  enabled: true\n  endpoint: \"185.107.80.5:51820\"\n  tunnel: \"proton\"\n"
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("config Proton valida rifiutata: %v", err)
	}
	if !c.Vpn.Enabled || c.Vpn.Tunnel != "proton" {
		t.Errorf("stanza vpn persa: %+v", c.Vpn)
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

// uncommentBlock toglie il "# " dalle righe di un blocco commentato dell'esempio
// (da `# <chiave>:` fino alla riga vuota successiva), tranne i commenti veri (`#   #`).
func uncommentBlock(text, key string) string {
	lines := strings.Split(text, "\n")
	in := false
	for i, l := range lines {
		switch {
		case l == "# "+key+":":
			in = true
			lines[i] = key + ":"
		case in && l == "":
			in = false
		case in && strings.HasPrefix(l, "#   ") && !strings.HasPrefix(l, "#   #"):
			lines[i] = "  " + strings.TrimPrefix(l, "#   ")
		}
	}
	return strings.Join(lines, "\n")
}

// La configurazione di esempio e' la documentazione piu' copiata: deve caricarsi, anche con
// le sezioni commentate attivate. Se cambia la validazione (come per vpn.endpoint) e
// l'esempio no, qui si rompe prima che lo faccia un utente.
func TestExampleConfigLoads(t *testing.T) {
	raw, err := os.ReadFile("../../configs/shield.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load("../../configs/shield.example.yaml"); err != nil {
		t.Fatalf("l'esempio cosi' com'e' non si carica: %v", err)
	}
	text := string(raw)
	for _, key := range []string{"vpn", "canary"} {
		text = uncommentBlock(text, key)
	}
	p := filepath.Join(t.TempDir(), "ex.yaml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("l'esempio con vpn e canary attivati non si carica: %v\n%s", err, text)
	}
	if !c.Vpn.Enabled || c.Vpn.Tunnel != "wg0" || len(c.Vpn.AllowLAN) != 1 {
		t.Errorf("stanza vpn dell'esempio non letta: %+v", c.Vpn)
	}
	if !c.Canary.Enabled {
		t.Error("stanza canary dell'esempio non letta")
	}
}
