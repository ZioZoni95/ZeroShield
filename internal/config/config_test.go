package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPresetsAreValid(t *testing.T) {
	for _, name := range Profiles() {
		c, err := Preset(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if len(c.AllRules()) == 0 {
			t.Errorf("%s: nessuna regola", name)
		}
	}
}

func TestHomeStartsInAudit(t *testing.T) {
	c, _ := Preset("home")
	if c.Enforce() {
		t.Error("il profilo home deve partire in audit")
	}
}

func TestLoadOverridesProfile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	yaml := "profile: public-wifi\nmode: audit\nblock_subnets: [\"10.0.0.0/8\"]\nextra_rules:\n  - name: wallet\n    paths: [\".bitcoin/wallet.dat\"]\n    allow: [\"bitcoin-qt\"]\n"
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != "audit" || len(c.BlockSubnets) != 1 {
		t.Errorf("override non applicato: %+v", c)
	}
	base, _ := Preset("public-wifi")
	if len(c.AllRules()) != len(base.Rules)+1 {
		t.Errorf("extra_rules non aggiunta: %d regole", len(c.AllRules()))
	}
}

func TestInvalidConfigRejected(t *testing.T) {
	c, _ := Preset("home")
	c.BlockSubnets = []string{"non-un-cidr"}
	if c.Validate() == nil {
		t.Error("CIDR invalido accettato")
	}
	c, _ = Preset("home")
	c.Mode = "boh"
	if c.Validate() == nil {
		t.Error("mode invalido accettato")
	}
}
