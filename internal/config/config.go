// Package config gestisce profili, regole di protezione e parsing del file YAML.
package config

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"sort"

	"gopkg.in/yaml.v3"
)

const (
	DefaultPath    = "/etc/zt-shield/shield.yaml"
	DefaultProfile = "home"
)

// Rule: un insieme di file segreti e i soli binari autorizzati a leggerli.
type Rule struct {
	Name  string   `yaml:"name"`
	Paths []string `yaml:"paths"` // relativi alla home, oppure assoluti; glob ammessi; le directory sono ricorsive
	Allow []string `yaml:"allow"` // nomi (risolti via PATH) o percorsi assoluti di binari
}

type Config struct {
	Profile        string   `yaml:"profile"`
	Mode           string   `yaml:"mode"` // audit | enforce
	User           string   `yaml:"user"`
	Interface      string   `yaml:"interface"`
	BlockPoisoning bool     `yaml:"block_poisoning"`
	BlockSubnets   []string `yaml:"block_subnets"`
	Rules          []Rule   `yaml:"rules"`       // sostituisce le regole del profilo
	ExtraRules     []Rule   `yaml:"extra_rules"` // si aggiunge a quelle del profilo
	LogFormat      string   `yaml:"log_format"`  // text | json
	RescanSeconds  int      `yaml:"rescan_seconds"`
}

// Gruppi di regole predefiniti. NB: tool interpretati (npm, pip, python, node) NON sono
// in whitelist di proposito: autorizzare l'interprete autorizzerebbe qualsiasi script.
var groups = map[string]Rule{
	"ssh": {
		Name:  "ssh-keys",
		Paths: []string{".ssh/id_*"},
		Allow: []string{"ssh", "ssh-add", "ssh-agent", "ssh-keygen", "scp", "sftp", "git"},
	},
	"cloud": {
		Name:  "cloud-creds",
		Paths: []string{".kube/config", ".aws/credentials", ".terraform.d/credentials.tfrc.json"},
		Allow: []string{"kubectl", "helm", "k9s", "aws", "terraform", "tofu"},
	},
	"tokens": {
		Name:  "dev-tokens",
		Paths: []string{".git-credentials", ".docker/config.json", ".config/gh/hosts.yml", ".cargo/credentials.toml"},
		Allow: []string{"git", "gh", "docker", "cargo"},
	},
	"gpg": {
		Name:  "gpg-keys",
		Paths: []string{".gnupg/private-keys-v1.d"},
		Allow: []string{"gpg", "gpg-agent", "gpgsm"},
	},
	"browsers": {
		Name: "browser-secrets",
		Paths: []string{
			".config/google-chrome/*/Cookies", ".config/google-chrome/*/Network/Cookies", ".config/google-chrome/*/Login Data",
			".config/chromium/*/Cookies", ".config/chromium/*/Network/Cookies", ".config/chromium/*/Login Data",
			".mozilla/firefox/*/cookies.sqlite", ".mozilla/firefox/*/key4.db", ".mozilla/firefox/*/logins.json",
			"snap/firefox/common/.mozilla/firefox/*/cookies.sqlite",
			"snap/firefox/common/.mozilla/firefox/*/key4.db",
			"snap/firefox/common/.mozilla/firefox/*/logins.json",
		},
		Allow: []string{
			"/opt/google/chrome/chrome", "/usr/lib/chromium/chromium", "/usr/lib/chromium-browser/chromium-browser",
			"/usr/lib/firefox/firefox", "/usr/lib/firefox-esr/firefox-esr",
			"/snap/firefox/current/usr/lib/firefox/firefox", "/snap/chromium/current/usr/lib/chromium-browser/chrome",
		},
	},
}

type profileDef struct {
	mode   string
	groups []string
}

// home parte in audit: nessun blocco finché non hai verificato che i tuoi tool funzionano.
var profiles = map[string]profileDef{
	"home":        {"audit", []string{"ssh", "cloud", "tokens", "gpg"}},
	"corporate":   {"enforce", []string{"ssh", "cloud", "tokens", "gpg"}},
	"public-wifi": {"enforce", []string{"ssh", "cloud", "tokens", "gpg", "browsers"}},
	"paranoid":    {"enforce", []string{"ssh", "cloud", "tokens", "gpg", "browsers"}},
}

func Profiles() []string {
	names := make([]string, 0, len(profiles))
	for n := range profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func Preset(name string) (*Config, error) {
	p, ok := profiles[name]
	if !ok {
		return nil, fmt.Errorf("profilo %q sconosciuto (validi: %v)", name, Profiles())
	}
	c := &Config{
		Profile:        name,
		Mode:           p.mode,
		BlockPoisoning: true,
		LogFormat:      "text",
		RescanSeconds:  30,
	}
	for _, g := range p.groups {
		c.Rules = append(c.Rules, groups[g])
	}
	return c, nil
}

// Load legge il file YAML sopra al profilo scelto. Con path vuoto usa DefaultPath se esiste,
// altrimenti il profilo di default.
func Load(path string) (*Config, error) {
	var data []byte
	if path == "" {
		if b, err := os.ReadFile(DefaultPath); err == nil {
			data = b
		}
	} else {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		data = b
	}

	head := struct {
		Profile string `yaml:"profile"`
	}{}
	if data != nil {
		if err := yaml.Unmarshal(data, &head); err != nil {
			return nil, fmt.Errorf("parsing config: %w", err)
		}
	}
	if head.Profile == "" {
		head.Profile = DefaultProfile
	}

	cfg, err := Preset(head.Profile)
	if err != nil {
		return nil, err
	}
	if data != nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config: %w", err)
		}
	}
	return cfg, cfg.Validate()
}

// AllRules: regole effettive (profilo o override + extra).
func (c *Config) AllRules() []Rule {
	out := make([]Rule, 0, len(c.Rules)+len(c.ExtraRules))
	out = append(out, c.Rules...)
	return append(out, c.ExtraRules...)
}

func (c *Config) Enforce() bool { return c.Mode == "enforce" }

func (c *Config) Validate() error {
	if c.Mode != "audit" && c.Mode != "enforce" {
		return fmt.Errorf("mode %q non valido (audit|enforce)", c.Mode)
	}
	if c.LogFormat != "text" && c.LogFormat != "json" {
		return fmt.Errorf("log_format %q non valido (text|json)", c.LogFormat)
	}
	if c.RescanSeconds < 5 {
		return fmt.Errorf("rescan_seconds deve essere >= 5")
	}
	for i, r := range c.AllRules() {
		if r.Name == "" || len(r.Paths) == 0 {
			return fmt.Errorf("regola #%d: servono name e almeno un path", i+1)
		}
	}
	for _, s := range c.BlockSubnets {
		if _, n, err := net.ParseCIDR(s); err != nil || n.IP.To4() == nil {
			return fmt.Errorf("block_subnets: %q non è un CIDR IPv4 valido", s)
		}
	}
	return nil
}

// HomeDir: sotto sudo/systemd $HOME è /root, quindi si risolve l'utente reale.
func (c *Config) HomeDir() (string, error) {
	name := c.User
	if name == "" {
		name = os.Getenv("SHIELD_USER")
	}
	if name == "" {
		name = os.Getenv("SUDO_USER")
	}
	if name == "" {
		return "", fmt.Errorf("utente da proteggere non definito: imposta 'user' nel config, SHIELD_USER, o usa sudo")
	}
	u, err := user.Lookup(name)
	if err != nil {
		return "", fmt.Errorf("utente %q non trovato: %w", name, err)
	}
	return u.HomeDir, nil
}
