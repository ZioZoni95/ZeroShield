// Package config gestisce profili, regole di protezione e parsing del file YAML.
//
// Modello: un profilo (home/corporate/public-wifi/paranoid) fornisce i default,
// un file YAML opzionale li sovrascrive chiave per chiave. Questo permette di
// passare da "audit, nessuna protezione attiva" a "enforce, blocco totale"
// cambiando una riga, senza toccare le regole.
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
	// DefaultPath: dove cerca la configurazione se -config non e' specificato.
	DefaultPath = "/etc/zt-shield/shield.yaml"
	// DefaultProfile: profilo usato se il file non esiste e non ne e' indicato uno.
	DefaultProfile = "home"
)

// Rule: un insieme di file segreti e i soli binari autorizzati a leggerli.
// Il legame e' regola-scoped: un binario autorizzato per "ssh-keys" non puo'
// leggere ".kube/config". Serve a contenere i danni se un tool viene compilato
// con un bug o con una dipendenza malevola.
type Rule struct {
	Name  string   `yaml:"name"`
	Paths []string `yaml:"paths"` // relativi alla home, oppure assoluti; glob ammessi; le directory sono ricorsive
	Allow []string `yaml:"allow"` // nomi (risolti via PATH) o percorsi assoluti di binari
}

// Config: file YAML completo. I campi non presenti nel file restano quelli del profilo.
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

// Gruppi di regole predefiniti.
//
// NB sul criterio di whitelist: i tool interpretati (npm, pip, python, node, gcloud)
// NON vanno in whitelist di proposito. Per un binario con shebang, exe_file e' l'interprete,
// quindi autorizzare "python" autorizzerebbe QUALSIASI script .py sulla macchina,
// compreso quello di un attaccante. Per un binario nativo, invece, l'inode e' univoco.
//
// CONTROMISURA DEL CRITERIO: anche i binari nativi in whitelist restano un vettore.
// `git hash-object ~/.kube/config` apre il file, e git e' in whitelist nelle regole
// "ssh-keys" e "dev-tokens". exe_file verifica correttamente CHI apre, ma "chi apre"
// e' scelto da chiunque passi per un binario che legge file per mestiere. Nessuna
// patch di questo programmo lo risolve: e' una conseguenza della whitelist.
var groups = map[string]Rule{
	// Chiavi SSH e di identita'. Copre i pattern, quindi anche le chiavi sk (FIDO2).
	"ssh": {
		Name:  "ssh-keys",
		Paths: []string{".ssh/id_*"},
		Allow: []string{"ssh", "ssh-add", "ssh-agent", "ssh-keygen", "scp", "sftp", "git"},
	},
	// Credenziali cloud e Kubernetes. terraform/tofu leggono il loro credentials file.
	"cloud": {
		Name:  "cloud-creds",
		Paths: []string{".kube/config", ".aws/credentials", ".terraform.d/credentials.tfrc.json"},
		Allow: []string{"kubectl", "helm", "k9s", "aws", "terraform", "tofu"},
	},
	// Token dei registry e dei package manager: la via piu' comune per rubare
	// accesso ai tuoi repository e ai tuoi container.
	"tokens": {
		Name:  "dev-tokens",
		Paths: []string{".git-credentials", ".docker/config.json", ".config/gh/hosts.yml", ".cargo/credentials.toml"},
		Allow: []string{"git", "gh", "docker", "cargo"},
	},
	// Chiavi private GPG, usate per firmare i commit e decifrare.
	"gpg": {
		Name:  "gpg-keys",
		Paths: []string{".gnupg/private-keys-v1.d"},
		Allow: []string{"gpg", "gpg-agent", "gpgsm"},
	},
	// Segreti dei browser. Solo nei profili public-wifi/paranoid, perche' bloccare
	// i database del browser di sotto e' scomodo e (Chrome) li ricrea spesso,
	// quindi in audit produce piu' rumore che segnale.
	// I path sono assoluti e con glob: i profili utente cambiano nome a ogni avvio.
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
		// Percorsi ASSOLUTI per i browser: sono pacchetti di sistema, non nell'home.
		Allow: []string{
			"/opt/google/chrome/chrome", "/usr/lib/chromium/chromium", "/usr/lib/chromium-browser/chromium-browser",
			"/usr/lib/firefox/firefox", "/usr/lib/firefox-esr/firefox-esr",
			"/snap/firefox/current/usr/lib/firefox/firefox", "/snap/chromium/current/usr/lib/chromium-browser/chrome",
		},
	},
}

// profileDef: mode di default e gruppi di regole.
type profileDef struct {
	mode   string
	groups []string
}

// "home" parte in audit di proposito: nessun blocco finche' non hai verificato in
// log che i tuoi tool funzionano. Un enforce sbagliato blocca kubectl e ti fa
// perdere piu' tempo di quanto il rischio valga. Gli altri profili sono enforce
// perche' presuppongono una rete gia' sospetta.
var profiles = map[string]profileDef{
	"home":        {"audit", []string{"ssh", "cloud", "tokens", "gpg"}},
	"corporate":   {"enforce", []string{"ssh", "cloud", "tokens", "gpg"}},
	"public-wifi": {"enforce", []string{"ssh", "cloud", "tokens", "gpg", "browsers"}},
	"paranoid":    {"enforce", []string{"ssh", "cloud", "tokens", "gpg", "browsers"}},
}

// Profiles restituisce i nomi dei profili disponibili, ordinati.
func Profiles() []string {
	names := make([]string, 0, len(profiles))
	for n := range profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Preset costruisce la configurazione di un profilo. Ignora Validate: usa Load.
func Preset(name string) (*Config, error) {
	p, ok := profiles[name]
	if !ok {
		return nil, fmt.Errorf("profilo %q sconosciuto (validi: %v)", name, Profiles())
	}
	c := &Config{
		Profile:        name,
		Mode:           p.mode,
		BlockPoisoning: true, // default sensato: drop broadcast, costo nullo
		LogFormat:      "text",
		RescanSeconds:  30,
	}
	// Copia i gruppi: senza questo, piu' profili condividerebbero lo stesso
	// backing array di Rule e una modifica a uno altererebbe gli altri.
	for _, g := range p.groups {
		c.Rules = append(c.Rules, groups[g])
	}
	return c, nil
}

// Load legge il file YAML sopra al profilo scelto. Con path vuoto usa DefaultPath
// se esiste, altrimenti il profilo di default senza toccare il filesystem.
//
// Due passaggi sul file, perche' il profilo va risolto PRIMA di sapere quali
// default applicare: nel primo si legge solo `profile`, nel secondo tutto il resto
// sopra il preset gia' materializzato.
func Load(path string) (*Config, error) {
	var data []byte
	if path == "" {
		// Assenza del file di default NON e' un errore: si gira sul profilo builtin.
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

	// Passaggio 1: quale profilo.
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

	// Passaggio 2: il preset, poi il file sopra.
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

// AllRules: regole effettive, profilo + extra. L'ordine e' significativo:
// l'id che il kernel assegna e' indice+1, e i log riportano il nome tramite quell'id,
// quindi rinumerare le regole cambia i nomi citati nei log storici.
func (c *Config) AllRules() []Rule {
	out := make([]Rule, 0, len(c.Rules)+len(c.ExtraRules))
	out = append(out, c.Rules...)
	return append(out, c.ExtraRules...)
}

func (c *Config) Enforce() bool { return c.Mode == "enforce" }

// Validate: fallisce presto e con un messaggio utile, invece di fallire piu' tardi
// dentro il kernel con un errore di permesso non spiegabile.
func (c *Config) Validate() error {
	if c.Mode != "audit" && c.Mode != "enforce" {
		return fmt.Errorf("mode %q non valido (audit|enforce)", c.Mode)
	}
	if c.LogFormat != "text" && c.LogFormat != "json" {
		return fmt.Errorf("log_format %q non valido (text|json)", c.LogFormat)
	}
	// Sotto i 5 secondi il rescan diventa un busy-loop di Put su mappe grandi.
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
		// BUG: nessun controllo di sanita' sulla lunghezza del prefisso. "0.0.0.0/0"
		// passa la validazione e blocca tutto il traffico in ingresso, IPv4 compreso
		// il DNS in uscita (XDP vede solo l'ingresso, ma il drop delle risposte
		// stacca anche la risoluzione). Dovrebbe rifiutare prefixlen < 8.
	}
	return nil
}

// HomeDir: sotto sudo e sotto systemd $HOME e' /root, quindi $HOME non e' utilizzabile.
// Si risolve l'utente reale con ordine di precedenza: config, SHIELD_USER (impostata dalla
// unit systemd), SUDO_USER (imposta solo da sudo).
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
