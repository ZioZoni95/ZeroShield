// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package rules

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"zt-shield/internal/config"
)

// Profilo condivisibile: le scelte della GUI (programmi autorizzati, protezioni accese o spente, modalita' per
// regola, regole personali, filtro di rete, canary) in un file da portare su un'altra macchina Linux.
//
// Cosa NON viaggia mai: `user` e `interface` (sono della macchina), la sezione `vpn` (endpoint e dati sensibili) e
// tutto cio' che sta nelle cartelle di un utente (/home, /root, /tmp...): un programma in una cartella modificabile
// dall'utente il demone non lo accetterebbe comunque (serve la copia di root in /usr/local/bin).
//
// Rischio dell'importazione: una lista di programmi autorizzati e' un permesso di leggere i segreti. Per questo
// l'import non scrive mai da solo: mostra cosa cambierebbe (PreviewImport), scarta i programmi non di root, per
// impostazione importa le modalita' in sola osservazione, e l'applicazione verifica che il file sia quello
// mostrato (impronta SHA-256). Niente firma: scelta dichiarata per la fase alpha (docs/PROFILO.md).

const (
	// ProfileFormat identifica il file; ProfileVersion cresce solo se il formato cambia in modo incompatibile.
	ProfileFormat  = "zeroshield-profile"
	ProfileVersion = 1
	// ProfileMaxBytes: un profilo e' piccolo; un file enorme e' un errore o un attacco.
	ProfileMaxBytes = 256 << 10
)

// PortableChoice: le scelte di Choice che hanno senso su un'altra macchina (niente Interface).
type PortableChoice struct {
	EnableGroups   []string            `yaml:"enable_groups,omitempty"`
	DisableRules   []string            `yaml:"disable_rules,omitempty"`
	AllowExtra     map[string][]string `yaml:"allow_extra,omitempty"`
	RemoveAllow    map[string][]string `yaml:"remove_allow,omitempty"`
	RuleModes      map[string]string   `yaml:"rule_modes,omitempty"`
	ExtraRules     []CustomRule        `yaml:"extra_rules,omitempty"`
	BlockPoisoning *bool               `yaml:"block_poisoning,omitempty"`
	Canary         *CanaryChoice       `yaml:"canary,omitempty"`
}

// Profile: il file esportato.
type Profile struct {
	Format      string         `yaml:"format"`
	Version     int            `yaml:"version"`
	Name        string         `yaml:"name,omitempty"`
	Note        string         `yaml:"note,omitempty"`
	ExportedBy  string         `yaml:"exported_by,omitempty"` // versione di ZeroShield che l'ha scritto
	ExportedAt  string         `yaml:"exported_at,omitempty"`
	BaseProfile string         `yaml:"base_profile,omitempty"` // `profile:` della macchina di origine (solo informativo)
	Choice      PortableChoice `yaml:"choice"`
}

// Errori che la GUI distingue.
var (
	ErrProfileFormat  = errors.New("non è un profilo di ZeroShield")
	ErrProfileTooBig  = errors.New("il file è troppo grande per essere un profilo")
	ErrProfileNothing = errors.New("non ci sono scelte da esportare: aggiungi prima programmi o protezioni dalle Regole")
)

// userPrefixes: cartelle che non sono portabili e che il demone non accetterebbe per un programma autorizzato.
var userPrefixes = []string{"/home/", "/root/", "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/mnt/", "/media/"}

func userPath(p string) bool {
	for _, pre := range userPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func fromChoice(c Choice) PortableChoice {
	return PortableChoice{EnableGroups: c.EnableGroups, DisableRules: c.DisableRules, AllowExtra: c.AllowExtra,
		RemoveAllow: c.RemoveAllow, RuleModes: c.RuleModes, ExtraRules: c.ExtraRules, BlockPoisoning: c.BlockPoisoning, Canary: c.Canary}
}

func (p PortableChoice) choice() Choice {
	return Choice{EnableGroups: p.EnableGroups, DisableRules: p.DisableRules, AllowExtra: p.AllowExtra,
		RemoveAllow: p.RemoveAllow, RuleModes: p.RuleModes, ExtraRules: p.ExtraRules, BlockPoisoning: p.BlockPoisoning, Canary: p.Canary}
}

// ExportOptions: nome e nota li sceglie chi esporta; Now serve ai test.
type ExportOptions struct {
	Name, Note, Version string
	Now                 time.Time
}

// Export legge le scelte dal config e scrive il profilo. Il secondo valore elenca cio' che e' rimasto fuori e perche'
// (da mostrare a chi esporta: niente sorprese).
func Export(cfgText string, o ExportOptions) ([]byte, []string, error) {
	cur, err := Parse(cfgText)
	if err != nil {
		return nil, nil, err
	}
	if cur.Empty() {
		return nil, nil, ErrProfileNothing
	}
	var left []string
	pc := fromChoice(cur)
	pc.AllowExtra, left = filterAllow(pc.AllowExtra, left, "autorizzato")
	pc.RemoveAllow, left = filterRemove(pc.RemoveAllow, left)
	var rules []CustomRule
	for _, r := range pc.ExtraRules {
		var paths, allow []string
		for _, p := range r.Paths {
			if filepath.IsAbs(p) && userPath(p) {
				left = append(left, fmt.Sprintf("regola «%s»: il percorso %s sta nella cartella di un utente", r.Name, p))
				continue
			}
			paths = append(paths, p)
		}
		for _, a := range r.Allow {
			if userPath(a) {
				left = append(left, fmt.Sprintf("regola «%s»: il programma %s sta nella cartella di un utente", r.Name, a))
				continue
			}
			allow = append(allow, a)
		}
		if len(paths) == 0 || len(allow) == 0 {
			left = append(left, fmt.Sprintf("regola «%s» non esportata: senza percorsi o senza programmi autorizzati non avrebbe senso", r.Name))
			continue
		}
		r.Paths, r.Allow = paths, allow
		rules = append(rules, r)
	}
	pc.ExtraRules = rules
	if pc.Canary != nil {
		cc := &CanaryChoice{Enabled: pc.Canary.Enabled}
		for _, d := range pc.Canary.Dirs {
			if filepath.IsAbs(d) && userPath(d) {
				left = append(left, fmt.Sprintf("canary: la cartella %s è assoluta nella home di un utente (usa un nome relativo, come Documents)", d))
				continue
			}
			cc.Dirs = append(cc.Dirs, d)
		}
		pc.Canary = cc
	}
	if cur.Interface != "" {
		left = append(left, "interfaccia di rete: è della macchina, non si esporta")
	}
	pf := Profile{Format: ProfileFormat, Version: ProfileVersion, Name: strings.TrimSpace(o.Name), Note: strings.TrimSpace(o.Note),
		ExportedBy: o.Version, Choice: pc}
	if !o.Now.IsZero() {
		pf.ExportedAt = o.Now.UTC().Format(time.RFC3339)
	}
	if cfg, err := loadText(cfgText); err == nil {
		pf.BaseProfile = cfg.Profile
	}
	if err := checkProfileText(pf); err != nil {
		return nil, nil, err
	}
	// Anche quello che esce deve poter rientrare: stesse regole di validate().
	if err := validate(pf.Choice.choice()); err != nil {
		return nil, left, fmt.Errorf("le scelte attuali non sono esportabili: %w", err)
	}
	body, err := yaml.Marshal(pf)
	if err != nil {
		return nil, nil, err
	}
	head := "# Profilo ZeroShield (condivisibile). Importalo da Configurazione → Profilo condiviso, oppure:\n" +
		"#   zt-shield profile import FILE\n" +
		"# Non contiene utente, interfaccia, VPN né percorsi nelle cartelle di un utente.\n"
	return append([]byte(head), body...), left, nil
}

func checkProfileText(p Profile) error {
	if len(p.Name) > 80 || len(p.Note) > 2000 {
		return errors.New("nome o nota troppo lunghi (80 e 2000 caratteri)")
	}
	for _, s := range []string{p.Name, p.Note} {
		if strings.ContainsAny(s, "\x00\r") {
			return errors.New("nome o nota contengono caratteri non ammessi")
		}
	}
	return nil
}

func filterAllow(in map[string][]string, left []string, what string) (map[string][]string, []string) {
	if len(in) == 0 {
		return nil, left
	}
	out := map[string][]string{}
	for rule, exes := range in {
		for _, e := range exes {
			if userPath(e) {
				left = append(left, fmt.Sprintf("«%s»: %s %s sta nella cartella di un utente (su ogni macchina serve la copia di root)", rule, what, e))
				continue
			}
			out[rule] = append(out[rule], e)
		}
	}
	if len(out) == 0 {
		return nil, left
	}
	return out, left
}

func filterRemove(in map[string][]string, left []string) (map[string][]string, []string) {
	if len(in) == 0 {
		return nil, left
	}
	out := map[string][]string{}
	for rule, exes := range in {
		for _, e := range exes {
			if userPath(e) {
				left = append(left, fmt.Sprintf("«%s»: il programma tolto %s sta nella cartella di un utente", rule, e))
				continue
			}
			out[rule] = append(out[rule], e)
		}
	}
	if len(out) == 0 {
		return nil, left
	}
	return out, left
}

// ParseProfile legge e controlla il file: dimensione, formato, versione, chiavi sconosciute (un errore di battitura
// o un campo che questa versione non conosce non si ignora in silenzio). Ritorna anche l'impronta SHA-256.
func ParseProfile(data []byte) (Profile, string, error) {
	if len(data) > ProfileMaxBytes {
		return Profile{}, "", ErrProfileTooBig
	}
	sum := sha256.Sum256(data)
	var p Profile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		if errors.Is(err, io.EOF) {
			return Profile{}, "", ErrProfileFormat
		}
		return Profile{}, "", fmt.Errorf("%w: %v", ErrProfileFormat, err)
	}
	if p.Format != ProfileFormat {
		return Profile{}, "", ErrProfileFormat
	}
	if p.Version < 1 {
		return Profile{}, "", fmt.Errorf("%w: versione del formato mancante", ErrProfileFormat)
	}
	if p.Version > ProfileVersion {
		return Profile{}, "", fmt.Errorf("il profilo usa il formato %d, più nuovo di quello che conosce questa versione (%d): aggiorna ZeroShield", p.Version, ProfileVersion)
	}
	if err := checkProfileText(p); err != nil {
		return Profile{}, "", err
	}
	return p, hex.EncodeToString(sum[:]), nil
}

// ImportOptions: Replace sostituisce le scelte attuali (default: unisce). AsAudit porta le modalita' del profilo in
// sola osservazione (consigliato per un pilota). Probe serve ai test (default: il filesystem vero).
type ImportOptions struct {
	Replace, AsAudit bool
	probe            func(path string) (exists bool, trustErr error)
}

// Change: una riga dell'anteprima. Kind: add | remove | change.
type Change struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// ImportResult: l'anteprima di un'importazione. NewText e' il config risultante (non scritto da nessuna parte).
type ImportResult struct {
	Name       string   `json:"name"`
	Note       string   `json:"note"`
	ExportedBy string   `json:"exported_by"`
	ExportedAt string   `json:"exported_at"`
	SHA256     string   `json:"sha256"`
	Changes    []Change `json:"changes"`
	Warnings   []string `json:"warnings"` // da leggere prima di applicare
	Skipped    []string `json:"skipped"`  // cio' che non si importa e perche'
	Unchanged  bool     `json:"unchanged"`
	NewText    string   `json:"-"`
}

func realProbe(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		return false, nil
	}
	return true, Trusted(path)
}

// PreviewImport calcola cosa farebbe l'importazione, senza scrivere niente. Il config risultante e' validato con il
// parser del demone: se lo rifiuterebbe, qui si ottiene un errore chiaro.
func PreviewImport(cfgText string, data []byte, o ImportOptions) (ImportResult, error) {
	pf, sum, err := ParseProfile(data)
	if err != nil {
		return ImportResult{}, err
	}
	cur, err := Parse(cfgText)
	if err != nil {
		return ImportResult{}, err
	}
	probe := o.probe
	if probe == nil {
		probe = realProbe
	}
	res := ImportResult{Name: pf.Name, Note: pf.Note, ExportedBy: pf.ExportedBy, ExportedAt: pf.ExportedAt, SHA256: sum}
	in := pf.Choice.choice()
	if err := validate(in); err != nil {
		return ImportResult{}, fmt.Errorf("il profilo contiene valori non validi: %w", err)
	}
	in = normalize(in)

	// 1. Programmi: solo quelli che il demone accetterebbe. Un percorso di utente o un binario non di root si scarta.
	vet := func(where, exe string) bool {
		if userPath(exe) {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %s sta nella cartella di un utente (serve la copia di root in /usr/local/bin)", where, exe))
			return false
		}
		exists, terr := probe(exe)
		switch {
		case exists && terr != nil:
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %s non è di proprietà di root, il demone lo scarterebbe", where, exe))
			return false
		case !exists:
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %s non è installato su questa macchina (la voce resta, ma non fa nulla finché non c'è)", where, exe))
		}
		return true
	}
	if in.AllowExtra != nil {
		kept := map[string][]string{}
		for rule, exes := range in.AllowExtra {
			for _, e := range exes {
				if vet("«"+rule+"»", e) {
					kept[rule] = append(kept[rule], e)
				}
			}
		}
		in.AllowExtra = kept
	}
	var rulesOK []CustomRule
	for _, r := range in.ExtraRules {
		var allow []string
		for _, a := range r.Allow {
			if vet("regola «"+r.Name+"»", a) {
				allow = append(allow, a)
			}
		}
		if len(allow) == 0 {
			res.Skipped = append(res.Skipped, fmt.Sprintf("regola «%s»: nessun programma autorizzato utilizzabile, non importata", r.Name))
			continue
		}
		r.Allow = allow
		rulesOK = append(rulesOK, r)
	}
	in.ExtraRules = rulesOK

	// 2. Modalita': per un pilota si importa in sola osservazione.
	if o.AsAudit {
		n := 0
		for k, m := range in.RuleModes {
			if m == "enforce" {
				in.RuleModes[k] = "audit"
				n++
			}
		}
		for i := range in.ExtraRules {
			if in.ExtraRules[i].Mode == "enforce" {
				in.ExtraRules[i].Mode = "audit"
				n++
			}
		}
		if n > 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%d protezion%s era in Blocca nel profilo: importata in sola osservazione, come hai scelto", n, ifOne(n, "e", "i")))
		}
	}
	if pf.BaseProfile != "" {
		if cfg, err := loadText(cfgText); err == nil && cfg.Profile != pf.BaseProfile {
			res.Warnings = append(res.Warnings, fmt.Sprintf("il profilo di base della macchina di origine era «%s», questa usa «%s»: le protezioni predefinite possono essere diverse", pf.BaseProfile, cfg.Profile))
		}
	}
	for rule := range in.RuleModes {
		if !knownRule(rule, cfgText, in) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("modalità per «%s»: nessuna protezione con questo nome su questa macchina (non avrà effetto)", rule))
		}
	}

	// 3. Unione o sostituzione. L'interfaccia di rete resta sempre quella di questa macchina.
	next := mergeChoice(cur, in, o.Replace)
	next.Interface = cur.Interface
	next = normalize(next)
	if err := validate(next); err != nil {
		return ImportResult{}, fmt.Errorf("il risultato non è valido: %w", err)
	}
	text, err := Apply(cfgText, next)
	if err != nil {
		return ImportResult{}, err
	}
	if err := Validate(text); err != nil {
		return ImportResult{}, fmt.Errorf("il demone rifiuterebbe questa configurazione: %w", err)
	}
	res.NewText = text
	res.Changes = diffChoice(normalize(cur), next)
	res.Unchanged = text == cfgText || len(res.Changes) == 0
	sort.Strings(res.Warnings)
	sort.Strings(res.Skipped)
	return res, nil
}

func ifOne(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// knownRule: il nome e' un gruppo predefinito, una regola personale del config o una importata.
func knownRule(name, cfgText string, in Choice) bool {
	if _, ok := config.Group(groupIDByName(name)); ok {
		return true
	}
	for _, r := range in.ExtraRules {
		if r.Name == name {
			return true
		}
	}
	if cfg, err := loadText(cfgText); err == nil {
		for _, r := range cfg.AllRules() {
			if r.Name == name {
				return true
			}
		}
	}
	return false
}

// groupName: il nome della regola di un gruppo predefinito (l'id stesso se non lo conosce).
func groupName(id string) string {
	if g, ok := config.Group(id); ok {
		return g.Name
	}
	return id
}

// groupIDByName: il nome (quello dei log) di un gruppo predefinito -> il suo id.
func groupIDByName(name string) string {
	for _, id := range config.GroupOrder {
		if g, _ := config.Group(id); g.Name == name {
			return id
		}
	}
	return ""
}

func union(a, b []string) []string {
	return append(append([]string(nil), a...), b...)
}

// mergeChoice: con replace le scelte del profilo prendono il posto delle attuali; altrimenti si uniscono e, dove
// i due dicono cose opposte, vince il profilo.
func mergeChoice(cur, in Choice, replace bool) Choice {
	if replace {
		return in
	}
	out := Choice{
		EnableGroups: union(cur.EnableGroups, in.EnableGroups),
		DisableRules: union(cur.DisableRules, in.DisableRules),
		AllowExtra:   map[string][]string{},
		RemoveAllow:  map[string][]string{},
		RuleModes:    map[string]string{},
	}
	// Dove il profilo accende, non resta spento; dove spegne, non resta acceso. Attenzione: enable_groups usa gli id
	// dei gruppi («cloud»), disable_rules i nomi delle regole («cloud-creds»): si confrontano per nome.
	out.DisableRules = slices.DeleteFunc(out.DisableRules, func(rule string) bool {
		return slices.ContainsFunc(in.EnableGroups, func(id string) bool { return groupName(id) == rule })
	})
	out.EnableGroups = slices.DeleteFunc(out.EnableGroups, func(id string) bool { return slices.Contains(in.DisableRules, groupName(id)) })
	for k, v := range cur.AllowExtra {
		out.AllowExtra[k] = append(out.AllowExtra[k], v...)
	}
	for k, v := range in.AllowExtra {
		out.AllowExtra[k] = append(out.AllowExtra[k], v...)
	}
	for k, v := range cur.RemoveAllow {
		out.RemoveAllow[k] = append(out.RemoveAllow[k], v...)
	}
	for k, v := range in.RemoveAllow {
		out.RemoveAllow[k] = append(out.RemoveAllow[k], v...)
	}
	maps.Copy(out.RuleModes, cur.RuleModes)
	maps.Copy(out.RuleModes, in.RuleModes) // il profilo vince dove i due dicono cose diverse
	byName := map[string]CustomRule{}
	for _, r := range cur.ExtraRules {
		byName[r.Name] = r
	}
	for _, r := range in.ExtraRules {
		byName[r.Name] = r
	}
	for _, r := range byName {
		out.ExtraRules = append(out.ExtraRules, r)
	}
	out.BlockPoisoning, out.Canary = cur.BlockPoisoning, cur.Canary
	if in.BlockPoisoning != nil {
		out.BlockPoisoning = in.BlockPoisoning
	}
	if in.Canary != nil {
		out.Canary = in.Canary
	}
	return out
}

// diffChoice descrive in italiano cosa cambia da a a b (entrambe normalizzate).
func diffChoice(a, b Choice) []Change {
	var ch []Change
	add := func(kind, f string, args ...any) { ch = append(ch, Change{Kind: kind, Text: fmt.Sprintf(f, args...)}) }
	setDiff := func(x, y []string) (added, removed []string) {
		for _, s := range y {
			if !slices.Contains(x, s) {
				added = append(added, s)
			}
		}
		for _, s := range x {
			if !slices.Contains(y, s) {
				removed = append(removed, s)
			}
		}
		return
	}
	keys := func(ms ...map[string][]string) []string {
		seen := map[string]bool{}
		var out []string
		for _, m := range ms {
			for k := range m {
				if !seen[k] {
					seen[k] = true
					out = append(out, k)
				}
			}
		}
		sort.Strings(out)
		return out
	}
	for _, rule := range keys(a.AllowExtra, b.AllowExtra) {
		ad, rm := setDiff(a.AllowExtra[rule], b.AllowExtra[rule])
		for _, e := range ad {
			add("add", "Autorizza %s per «%s»", e, rule)
		}
		for _, e := range rm {
			add("remove", "Non autorizza più %s per «%s»", e, rule)
		}
	}
	for _, rule := range keys(a.RemoveAllow, b.RemoveAllow) {
		ad, rm := setDiff(a.RemoveAllow[rule], b.RemoveAllow[rule])
		for _, e := range ad {
			add("remove", "Toglie %s dalla lista di base di «%s»", e, rule)
		}
		for _, e := range rm {
			add("add", "Rimette %s nella lista di base di «%s»", e, rule)
		}
	}
	ad, rm := setDiff(a.DisableRules, b.DisableRules)
	for _, r := range ad {
		add("remove", "Spegne la protezione «%s»", r)
	}
	for _, r := range rm {
		add("add", "Riaccende la protezione «%s»", r)
	}
	ad, rm = setDiff(a.EnableGroups, b.EnableGroups)
	for _, r := range ad {
		add("add", "Accende la protezione «%s»", r)
	}
	for _, r := range rm {
		add("remove", "Non accende più la protezione «%s»", r)
	}
	modeName := func(m string) string {
		if m == "enforce" {
			return "Blocca"
		}
		return "Osserva"
	}
	modeKeys := map[string]bool{}
	for k := range a.RuleModes {
		modeKeys[k] = true
	}
	for k := range b.RuleModes {
		modeKeys[k] = true
	}
	var mk []string
	for k := range modeKeys {
		mk = append(mk, k)
	}
	sort.Strings(mk)
	for _, k := range mk {
		am, aok := a.RuleModes[k]
		bm, bok := b.RuleModes[k]
		switch {
		case aok && !bok:
			add("change", "La protezione «%s» torna alla modalità generale", k)
		case bok && (!aok || am != bm):
			add("change", "La protezione «%s» passa in %s", k, modeName(bm))
		}
	}
	rulesOf := func(c Choice) map[string]CustomRule {
		m := map[string]CustomRule{}
		for _, r := range c.ExtraRules {
			m[r.Name] = r
		}
		return m
	}
	ra, rb := rulesOf(a), rulesOf(b)
	var names []string
	for n := range ra {
		names = append(names, n)
	}
	for n := range rb {
		if _, ok := ra[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		x, inA := ra[n]
		y, inB := rb[n]
		switch {
		case !inA:
			add("add", "Aggiunge la regola personale «%s» (%d percorsi, %d programmi)", n, len(y.Paths), len(y.Allow))
		case !inB:
			add("remove", "Toglie la regola personale «%s»", n)
		case !slices.Equal(x.Paths, y.Paths) || !slices.Equal(x.Allow, y.Allow) || x.DenyWrite != y.DenyWrite || x.Mode != y.Mode:
			add("change", "Modifica la regola personale «%s»", n)
		}
	}
	pa, pb := a.BlockPoisoning != nil && !*a.BlockPoisoning, b.BlockPoisoning != nil && !*b.BlockPoisoning
	if pa != pb {
		if pb {
			add("remove", "Spegne il filtro di rete (LLMNR, mDNS, NetBIOS)")
		} else {
			add("add", "Riaccende il filtro di rete (LLMNR, mDNS, NetBIOS)")
		}
	}
	ca, cb := a.Canary != nil && a.Canary.Enabled, b.Canary != nil && b.Canary.Enabled
	switch {
	case !ca && cb:
		add("add", "Accende il canary anti-ransomware su: %s", dirsText(b.Canary.Dirs))
	case ca && !cb:
		add("remove", "Spegne il canary anti-ransomware")
	case ca && cb && !slices.Equal(a.Canary.Dirs, b.Canary.Dirs):
		add("change", "Cambia le cartelle del canary: %s", dirsText(b.Canary.Dirs))
	}
	return ch
}

func dirsText(d []string) string {
	if len(d) == 0 {
		return "la cartella predefinita (Documents)"
	}
	return strings.Join(d, ", ")
}

// ReadProfileFile legge un profilo da disco: solo un file regolare, mai oltre ProfileMaxBytes (un FIFO, un device o
// un file enorme non devono bloccare o riempire la GUI).
func ReadProfileFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s non è un file normale", path)
	}
	if fi.Size() > ProfileMaxBytes {
		return nil, ErrProfileTooBig
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, ProfileMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > ProfileMaxBytes {
		return nil, ErrProfileTooBig
	}
	return data, nil
}

// ApplyPlan ricalcola l'importazione sul config di adesso e ritorna il testo da installare, ma solo se il file e' quello
// mostrato nell'anteprima (impronta uguale): chi ha visto un profilo non ne applica un altro scambiato nel frattempo.
func ApplyPlan(cfgText string, data []byte, o ImportOptions, wantSHA string) (string, error) {
	res, err := PreviewImport(cfgText, data, o)
	if err != nil {
		return "", err
	}
	if wantSHA == "" || res.SHA256 != wantSHA {
		return "", errors.New("il file è cambiato dopo l'anteprima: ripeti l'anteprima prima di applicare")
	}
	if res.Unchanged {
		return "", errors.New("non c'è niente da applicare: questa macchina ha già queste scelte")
	}
	return res.NewText, nil
}
