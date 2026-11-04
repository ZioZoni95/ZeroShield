// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package config gestisce profili, regole di protezione e parsing del file YAML.
//
// Modello: un profilo (home/corporate/public-wifi/paranoid) fornisce i default,
// un file YAML opzionale li sovrascrive chiave per chiave. Questo permette di
// passare da "audit, nessuna protezione attiva" a "enforce, blocco totale"
// cambiando una riga, senza toccare le regole.
package config

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// unmarshalStrict rifiuta chiavi sconosciute: un refuso come `block_poisioning`
// prima veniva ignorato in silenzio (nessuna protezione, zero errori).
func unmarshalStrict(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(v)
}

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
	Name      string   `yaml:"name"`
	Paths     []string `yaml:"paths"`      // relativi alla home, oppure assoluti; glob ammessi; le directory sono ricorsive
	Allow     []string `yaml:"allow"`      // nomi (risolti via PATH) o percorsi assoluti di binari
	DenyWrite bool     `yaml:"deny_write"` // se true, nega anche O_WRONLY/O_TRUNC (default false: chiavi e backup scrivibili)
}

// CanaryConfig: esche anti-ransomware via fanotify (vedi docs/CANARY.md).
// Disabilitato di default: va tarato in audit sui propri pattern di scrittura.
type CanaryConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Dirs       []string `yaml:"dirs"`        // relativi alla home o assoluti
	Names      []string `yaml:"names"`       // nomi esca (mai aperti dall'utente)
	BurstCount int      `yaml:"burst_count"` // rename/delete oltre soglia in finestra = allarme
	BurstSecs  int      `yaml:"burst_secs"`
	ExcludeExe []string `yaml:"exclude_exe"` // sottostringhe exe escluse dal conteggio massa (mai dal tocco esca)
	// AllowExe: percorsi ASSOLUTI esatti di binari che possono toccare le esche senza
	// essere uccisi (indicizzatori, backup). Solo binari di root non scrivibili da
	// altri: gli altri vengono scartati all'avvio con un avviso.
	AllowExe []string `yaml:"allow_exe"`
}

// VpnConfig descrive il tunnel che il demone deve MONITORARE (docs/VPN_SETUP.md).
//
// Il demone non applica il kill-switch: lo fa scripts/vpn_killswitch.sh, con gli
// stessi valori. Qui servono a mostrare nelle UI lo stato reale (tunnel su, handshake,
// tabella nft attiva) e a dare l'allarme se il tunnel cade. Non cifra nulla da solo:
// presuppone un tunnel WireGuard gestito altrove (wg-quick/NM). Spento di default.
type VpnConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Endpoint  string   `yaml:"endpoint"`   // IP:porta del server VPN, o [IPv6]:porta (mai un nome host)
	Tunnel    string   `yaml:"tunnel"`     // interfaccia tunnel (es. wg0), max 15 caratteri
	BlockDHCP bool     `yaml:"block_dhcp"` // default false: bloccarlo impedisce al tunnel di riallacciarsi
	AllowLAN  []string `yaml:"allow_lan"`  // CIDR extra (es. stampante), IPv4 o IPv6; vuoto = niente
}

// ifaceNameRe: nomi interfaccia Linux ragionevoli (IFNAMSIZ = 16 con il terminatore).
// Vieta spazi, punto e virgola e slash: il nome finisce in comandi e regole nft.
var ifaceNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// validateVpn: rifiuta qui, con un messaggio chiaro, cio' che lo script rifiuterebbe
// a meta' applicazione. Con il kill-switch un valore sbagliato significa rete morta.
func validateVpn(v VpnConfig) error {
	host, port, err := net.SplitHostPort(v.Endpoint)
	if err != nil {
		return fmt.Errorf("vpn.endpoint %q non valido: serve IP:porta (es. 203.0.113.7:51820 o [2001:db8::1]:51820)", v.Endpoint)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("vpn.endpoint %q: serve un indirizzo IP, non un nome host (il kill-switch non puo' risolvere il DNS)", v.Endpoint)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("vpn.endpoint %q: porta fuori da 1-65535", v.Endpoint)
	}
	if !ifaceNameRe.MatchString(v.Tunnel) {
		return fmt.Errorf("vpn.tunnel %q non valido (1-15 caratteri tra lettere, cifre, _ . -)", v.Tunnel)
	}
	for _, s := range v.AllowLAN {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return fmt.Errorf("vpn.allow_lan: %q non e' un CIDR valido", s)
		}
	}
	return nil
}

// Config: file YAML completo. I campi non presenti nel file restano quelli del profilo.
type Config struct {
	Profile        string       `yaml:"profile"`
	Mode           string       `yaml:"mode"` // audit | enforce
	User           string       `yaml:"user"`
	Interface      string       `yaml:"interface"`
	BlockPoisoning bool         `yaml:"block_poisoning"`
	BlockSubnets   []string     `yaml:"block_subnets"`
	Rules          []Rule       `yaml:"rules"`       // sostituisce le regole del profilo
	ExtraRules     []Rule       `yaml:"extra_rules"` // si aggiunge a quelle del profilo
	Canary         CanaryConfig `yaml:"canary"`
	Vpn            VpnConfig    `yaml:"vpn"`
	LogFormat      string       `yaml:"log_format"` // text | json
	RescanSeconds  int          `yaml:"rescan_seconds"`
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
	// NOTA: `git` e' stato RIMOSSO da qui (era in whitelist ssh-keys). Git over SSH
	// invoca il binario `ssh`, non apre le chiavi direttamente: git non ha bisogno
	// di leggere ~/.ssh/id_*. Tenerlo qui rendeva `git hash-object ~/.kube/config`
	// e simili canali di lettura per file di altre regole. Git resta in dev-tokens
	// dove serve davvero (.git-credentials per https).
	"ssh": {
		Name:  "ssh-keys",
		Paths: []string{".ssh/id_*"},
		Allow: []string{"ssh", "ssh-add", "ssh-agent", "ssh-keygen", "scp", "sftp"},
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
		Name: "dev-tokens",
		// glab (GitLab CLI) tiene il token in ~/.config/glab-cli/config.yml. NON si aggiungono
		// .npmrc/.pypirc: npm e pip sono script con shebang, autorizzarli vorrebbe dire
		// autorizzare l'interprete e ogni script che lo usa (vedi 'allow' in shield.example.yaml).
		Paths: []string{".git-credentials", ".docker/config.json", ".config/gh/hosts.yml", ".cargo/credentials.toml", ".config/glab-cli/config.yml"},
		Allow: []string{"git", "gh", "glab", "docker", "cargo"},
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
			// Chromium da snap: i dati stanno sotto snap/chromium/common.
			"snap/chromium/common/chromium/*/Cookies", "snap/chromium/common/chromium/*/Network/Cookies", "snap/chromium/common/chromium/*/Login Data",
			// Brave (pacchetto .deb ufficiale).
			".config/BraveSoftware/Brave-Browser/*/Cookies", ".config/BraveSoftware/Brave-Browser/*/Network/Cookies", ".config/BraveSoftware/Brave-Browser/*/Login Data",
			// NON coperto: Flatpak. Il binario visto dal kernel e' quello dentro
			// /var/lib/flatpak/app/<id>/current/active/files; senza verificarlo in audit su una
			// macchina con Flatpak, proteggere i dati rischia di chiudere fuori il browser.
		},
		// Percorsi ASSOLUTI per i browser: sono pacchetti di sistema, non nell'home.
		Allow: []string{
			"/opt/google/chrome/chrome", "/usr/lib/chromium/chromium", "/usr/lib/chromium-browser/chromium-browser",
			"/usr/lib/firefox/firefox", "/usr/lib/firefox-esr/firefox-esr",
			"/snap/firefox/current/usr/lib/firefox/firefox", "/snap/chromium/current/usr/lib/chromium-browser/chrome",
			"/opt/brave.com/brave/brave",
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
	// Copia PROFONDA dei gruppi: struct + slice. Senza, piu' profili condividerebbero
	// lo stesso backing array di Rule/Paths/Allow e una modifica a uno altererebbe
	// gli altri (prima si copiava solo la struct, le slice restavano condivise).
	for _, g := range p.groups {
		src := groups[g]
		cp := Rule{
			Name:  src.Name,
			Paths: append([]string(nil), src.Paths...),
			Allow: append([]string(nil), src.Allow...),
		}
		c.Rules = append(c.Rules, cp)
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

	// Passaggio 1: quale profilo. NON strict: la struct ha solo `profile`,
	// strict qui rifiuterebbe tutte le altre chiavi valide del file.
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
		if err := unmarshalStrict(data, cfg); err != nil {
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

// CanaryWritePaths: cartelle da rendere scrivibili al servizio (ReadWritePaths=) perche'
// il canary possa creare le esche sotto ProtectHome=read-only. Per ogni cartella
// configurata vale lei stessa se esiste, altrimenti il suo primo antenato esistente
// (dove il demone potra' creare le directory mancanti). Vuoto se il canary e' spento.
func (c *Config) CanaryWritePaths(home string) []string {
	if !c.Canary.Enabled {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range c.Canary.Dirs {
		if !filepath.IsAbs(d) {
			d = filepath.Join(home, d)
		}
		d = filepath.Clean(d)
		for d != "/" {
			if fi, err := os.Stat(d); err == nil && fi.IsDir() {
				break
			}
			d = filepath.Dir(d)
		}
		if d != "/" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// SystemdDropin: contenuto del drop-in che apre al servizio le cartelle del canary.
// Stringa vuota se non serve. Va in /etc/systemd/system/zt-shield.service.d/canary.conf.
func (c *Config) SystemdDropin(home string) string {
	paths := c.CanaryWritePaths(home)
	if len(paths) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Generato da `zt-shield dropin`: apre al canary le sole cartelle delle esche.\n")
	b.WriteString("[Service]\n")
	for _, p := range paths {
		fmt.Fprintf(&b, "ReadWritePaths=%s\n", p)
	}
	return b.String()
}

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
	if c.Canary.Enabled {
		// Default sensati se abilitato ma non dettagliato: Documents + 3 esche.
		if len(c.Canary.Dirs) == 0 {
			c.Canary.Dirs = []string{"Documents"}
		}
		if len(c.Canary.Names) == 0 {
			c.Canary.Names = []string{".canary-accounts.xlsx", ".canary-wallet.dat", ".canary-backup.zip"}
		}
		if c.Canary.BurstCount <= 0 {
			c.Canary.BurstCount = 50
		}
		if c.Canary.BurstSecs <= 0 {
			c.Canary.BurstSecs = 10
		}
		// Un nome con "/" o ".." porterebbe l'esca fuori dalla cartella scelta.
		for _, n := range c.Canary.Names {
			if n == "" || n == "." || n == ".." || strings.ContainsAny(n, "/\\\x00") {
				return fmt.Errorf("canary.names: %q non valido (solo nome file, niente / o ..)", n)
			}
		}
		for _, d := range c.Canary.Dirs {
			if d == "" || strings.ContainsRune(d, 0) {
				return fmt.Errorf("canary.dirs: voce vuota o non valida")
			}
			for _, part := range strings.Split(filepath.ToSlash(d), "/") {
				if part == ".." {
					return fmt.Errorf("canary.dirs: %q contiene '..'", d)
				}
			}
		}
		for _, e := range c.Canary.AllowExe {
			if !filepath.IsAbs(e) || filepath.Clean(e) != e || strings.ContainsAny(e, "*?[") {
				return fmt.Errorf("canary.allow_exe: %q deve essere un percorso assoluto pulito, senza glob", e)
			}
		}
	}
	if c.Vpn.Enabled {
		if err := validateVpn(c.Vpn); err != nil {
			return err
		}
	}
	for i, r := range c.AllRules() {
		if r.Name == "" || len(r.Paths) == 0 {
			return fmt.Errorf("regola #%d: servono name e almeno un path", i+1)
		}
		// FIX: allow vuota = deny-all totale (nemmeno il proprietario legge).
		// Prima passava in silenzio e l'unica via era fermare il demone da root.
		// Se davvero vuoi deny-all, resta possibile ma deve essere esplicito:
		// qui si rifiuta per forzare consapevolezza.
		if len(r.Allow) == 0 {
			return fmt.Errorf("regola %q: allow vuota = deny-all anche per te; aggiungi almeno un binario o rimuovi la regola", r.Name)
		}
	}
	// FIX: nomi duplicati = log ambigui (stesso nome, id diversi). Rifiuta.
	seen := map[string]bool{}
	for _, r := range c.AllRules() {
		if seen[r.Name] {
			return fmt.Errorf("regola %q duplicata: i nomi devono essere unici (i log traducono id->nome)", r.Name)
		}
		seen[r.Name] = true
	}
	for _, s := range c.BlockSubnets {
		_, n, err := net.ParseCIDR(s)
		if err != nil || n.IP.To4() == nil {
			return fmt.Errorf("block_subnets: %q non è un CIDR IPv4 valido", s)
		}
		// FIX: prima "0.0.0.0/0" passava e staccava tutto l'IPv4 in ingresso
		// (risposte DNS comprese). Ora si rifiutano prefissi troppo larghi.
		if ones, _ := n.Mask.Size(); ones < 8 {
			return fmt.Errorf("block_subnets: %q troppo largo (/%d): minimo /8, 0.0.0.0/0 stacca tutta la rete", s, ones)
		}
	}
	return nil
}

// Account risolve l'utente da proteggere. Precedenza: config, SHIELD_USER (impostata
// dalla unit systemd), SUDO_USER (solo sotto sudo). Sotto sudo e sotto systemd $HOME
// e' /root, quindi $HOME non e' utilizzabile.
func (c *Config) Account() (*user.User, error) {
	name := c.User
	if name == "" {
		name = os.Getenv("SHIELD_USER")
	}
	if name == "" {
		name = os.Getenv("SUDO_USER")
	}
	if name == "" {
		return nil, fmt.Errorf("utente da proteggere non definito: imposta 'user' nel config, SHIELD_USER, o usa sudo")
	}
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("utente %q non trovato: %w", name, err)
	}
	return u, nil
}

// HomeDir: home dell'utente protetto (vedi Account).
func (c *Config) HomeDir() (string, error) {
	u, err := c.Account()
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}
