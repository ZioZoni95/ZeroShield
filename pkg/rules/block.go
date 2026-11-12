// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package rules

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Le scelte fatte dalla GUI vivono in un blocco delimitato in fondo al config. Il resto del
// file (commenti, profilo, canary, VPN...) non viene mai riscritto: si sostituisce solo
// quello che sta tra i due marcatori. Un parser YAML che rigenera il file perderebbe commenti
// e ordine; un blocco gestito no.
const (
	blockBegin = "# >>> ZeroShield GUI: regole scelte dalla finestra Regole (gestito, non modificare a mano) >>>"
	blockEnd   = "# <<< ZeroShield GUI <<<"
)

// ErrManual: le stesse chiavi sono gia' scritte a mano fuori dal blocco. Due definizioni della
// stessa chiave sono un YAML non valido: si rifiuta invece di indovinare quale vale.
var ErrManual = errors.New("allow_extra, disable_rules o enable_groups sono gia' scritte a mano nel config: modificale li' (o spostale)")

// CustomRule: una regola creata dall'utente («Proteggi un mio file»). Stessi campi di config.Rule.
type CustomRule struct {
	Name      string   `yaml:"name" json:"name"`
	Paths     []string `yaml:"paths" json:"paths"`
	Allow     []string `yaml:"allow" json:"allow"`
	DenyWrite bool     `yaml:"deny_write,omitempty" json:"deny_write"`
	Mode      string   `yaml:"mode,omitempty" json:"mode"` // "" = come la modalita' globale
}

// CanaryChoice: anti-ransomware (esche fanotify) acceso dalla GUI. Spento = la chiave non c'e' (il default del
// demone e' spento): scrivere `enabled: false` non serve. Gli altri parametri (nomi delle esche, soglie di
// massa) restano ai default del demone.
type CanaryChoice struct {
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Dirs    []string `yaml:"dirs,omitempty" json:"dirs"` // relative alla home o assolute; vuoto = default del demone (Documents)
}

// Choice: le scelte che la GUI gestisce.
type Choice struct {
	EnableGroups []string            `yaml:"enable_groups,omitempty" json:"enable_groups"`
	DisableRules []string            `yaml:"disable_rules,omitempty" json:"disable_rules"`
	AllowExtra   map[string][]string `yaml:"allow_extra,omitempty" json:"allow_extra"`
	RemoveAllow  map[string][]string `yaml:"remove_allow,omitempty" json:"remove_allow"`
	RuleModes    map[string]string   `yaml:"rule_modes,omitempty" json:"rule_modes"`
	ExtraRules   []CustomRule        `yaml:"extra_rules,omitempty" json:"extra_rules"`
	// Interface: interfacce su cui agganciare il filtro di rete (lista csv, come la chiave `interface` del config).
	// Vuoto = automatica (la rete in uso).
	Interface string `yaml:"interface,omitempty" json:"interface"`
	// BlockPoisoning: nil = come il default del demone (acceso). Solo `false` va scritto: spegne il filtro di rete.
	BlockPoisoning *bool `yaml:"block_poisoning,omitempty" json:"block_poisoning"`
	// Canary: nil = spento.
	Canary *CanaryChoice `yaml:"canary,omitempty" json:"canary"`
}

// Empty: nessuna scelta (il blocco non serve).
func (c Choice) Empty() bool {
	return len(c.EnableGroups) == 0 && len(c.DisableRules) == 0 && len(c.AllowExtra) == 0 &&
		len(c.RemoveAllow) == 0 && len(c.RuleModes) == 0 && len(c.ExtraRules) == 0 && c.Interface == "" &&
		c.BlockPoisoning == nil && c.Canary == nil
}

// uniqKeep toglie i doppioni mantenendo l'ordine (per i percorsi l'ordine e' quello scelto dall'utente).
func uniqKeep(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func normalize(c Choice) Choice {
	uniq := func(in []string) []string {
		seen := map[string]bool{}
		var out []string
		for _, s := range in {
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	}
	out := Choice{EnableGroups: uniq(c.EnableGroups), DisableRules: uniq(c.DisableRules)}
	for rule, exes := range c.AllowExtra {
		if u := uniq(exes); len(u) > 0 {
			if out.AllowExtra == nil {
				out.AllowExtra = map[string][]string{}
			}
			out.AllowExtra[rule] = u
		}
	}
	for rule, exes := range c.RemoveAllow {
		if u := uniq(exes); len(u) > 0 {
			if out.RemoveAllow == nil {
				out.RemoveAllow = map[string][]string{}
			}
			out.RemoveAllow[rule] = u
		}
	}
	for rule, m := range c.RuleModes {
		if m != "" {
			if out.RuleModes == nil {
				out.RuleModes = map[string]string{}
			}
			out.RuleModes[rule] = m
		}
	}
	for _, r := range c.ExtraRules {
		r.Paths, r.Allow = uniqKeep(r.Paths), uniqKeep(r.Allow)
		out.ExtraRules = append(out.ExtraRules, r)
	}
	sort.Slice(out.ExtraRules, func(i, j int) bool { return out.ExtraRules[i].Name < out.ExtraRules[j].Name })
	var ifs []string
	for _, n := range strings.Split(c.Interface, ",") {
		if n = strings.TrimSpace(n); n != "" {
			ifs = append(ifs, n)
		}
	}
	out.Interface = strings.Join(uniqKeep(ifs), ",")
	if c.BlockPoisoning != nil && !*c.BlockPoisoning {
		off := false // acceso = default: non si scrive
		out.BlockPoisoning = &off
	}
	if c.Canary != nil && c.Canary.Enabled {
		out.Canary = &CanaryChoice{Enabled: true, Dirs: uniqKeep(c.Canary.Dirs)}
	}
	return out
}

// validate rifiuta cio' che il demone rifiuterebbe, qui e con un messaggio chiaro, invece di
// scoprirlo al riavvio: percorsi assoluti puliti senza caratteri di controllo o glob, e nomi
// di regola/gruppo in forma semplice.
func validate(c Choice) error {
	name := func(s string) bool {
		if s == "" || len(s) > 64 {
			return false
		}
		for _, r := range s {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
		return true
	}
	for _, n := range append(append([]string(nil), c.EnableGroups...), c.DisableRules...) {
		if !name(n) {
			return fmt.Errorf("nome %q non valido", n)
		}
	}
	for rule, exes := range c.AllowExtra {
		if !name(rule) {
			return fmt.Errorf("regola %q non valida", rule)
		}
		for _, e := range exes {
			if !strings.HasPrefix(e, "/") || strings.ContainsAny(e, "*?[\x00\n\r\t") || e != filepath.Clean(e) {
				return fmt.Errorf("%q: serve un percorso assoluto pulito, senza glob", e)
			}
		}
	}
	for rule, exes := range c.RemoveAllow {
		if !name(rule) {
			return fmt.Errorf("regola %q non valida", rule)
		}
		for _, e := range exes {
			if e == "" || strings.ContainsAny(e, "\x00\n\r\t") || len(e) > 4096 {
				return fmt.Errorf("programma %q non valido", e)
			}
		}
	}
	for rule, m := range c.RuleModes {
		if !name(rule) {
			return fmt.Errorf("regola %q non valida", rule)
		}
		if m != "audit" && m != "enforce" {
			return fmt.Errorf("modalita' %q non valida (audit|enforce)", m)
		}
	}
	if err := ValidateInterfaces(c.Interface); err != nil {
		return err
	}
	if c.Canary != nil {
		if len(c.Canary.Dirs) > 32 {
			return fmt.Errorf("troppe cartelle per il canary (massimo 32)")
		}
		for _, d := range c.Canary.Dirs {
			if d == "" || len(d) > 4096 || strings.ContainsAny(d, "*?[\x00\n\r\t") || strings.Contains(d, "..") {
				return fmt.Errorf("cartella del canary %q non valida", d)
			}
		}
	}
	seen := map[string]bool{}
	for _, r := range c.ExtraRules {
		if err := ValidateCustom(r); err != nil {
			return err
		}
		if seen[r.Name] {
			return fmt.Errorf("regola %q duplicata", r.Name)
		}
		seen[r.Name] = true
	}
	return nil
}

// Render scrive il blocco (stringa vuota se non c'e' nessuna scelta). yaml.Marshal ordina le
// chiavi delle mappe e quota i valori: niente concatenazioni di stringhe.
func Render(c Choice) (string, error) {
	if err := validate(c); err != nil {
		return "", err
	}
	c = normalize(c)
	if c.Empty() {
		return "", nil
	}
	body, err := yaml.Marshal(c)
	if err != nil {
		return "", err
	}
	return blockBegin + "\n" + string(body) + blockEnd + "\n", nil
}

// split separa il testo in (prima, blocco, dopo). found=false se non c'e' un blocco intero.
func split(text string) (before, block, after string, found bool) {
	b := strings.Index(text, blockBegin)
	if b < 0 {
		return text, "", "", false
	}
	e := strings.Index(text[b:], blockEnd)
	if e < 0 {
		return text, "", "", false
	}
	e += b + len(blockEnd)
	if e < len(text) && text[e] == '\n' {
		e++
	}
	return text[:b], text[b:e], text[e:], true
}

func hasManualKeys(rest string) bool {
	var m map[string]any
	if err := yaml.Unmarshal([]byte(rest), &m); err != nil {
		return false // il file e' rotto per altri motivi: lo diranno il parser del demone e Apply
	}
	for _, k := range []string{"allow_extra", "disable_rules", "enable_groups", "remove_allow", "rule_modes"} {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// ErrManualRules: ci sono extra_rules scritte a mano nel config: il blocco gestito non puo' definirne di sue
// (stessa chiave due volte). Il resto della GUI funziona; solo «Proteggi un mio file» resta spento.
var ErrManualRules = errors.New("nel config ci sono gia' extra_rules scritte a mano: le regole personali si modificano li'")

func hasManualExtraRules(rest string) bool {
	var m map[string]any
	if err := yaml.Unmarshal([]byte(rest), &m); err != nil {
		return false
	}
	_, ok := m["extra_rules"]
	return ok
}

// ErrManualInterface: `interface` e' scritta a mano nel config: la GUI non puo' definirla una seconda volta.
var ErrManualInterface = errors.New("nel config c'e' gia' `interface` scritta a mano: modificala li' (o toglila per sceglierla dalla GUI)")

var ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// ValidateInterfaces controlla una lista csv di nomi di interfaccia (stessa regola del demone).
func ValidateInterfaces(list string) error {
	seen := map[string]bool{}
	for _, n := range strings.Split(list, ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !ifaceRe.MatchString(n) {
			return fmt.Errorf("interfaccia %q non valida", n)
		}
		if seen[n] {
			return fmt.Errorf("interfaccia %q ripetuta", n)
		}
		seen[n] = true
	}
	return nil
}

// ErrManualFeature: `block_poisoning` o `canary` sono scritte a mano nel config: la GUI non le puo' definire una seconda volta.
var ErrManualFeature = errors.New("nel config ci sono gia' `block_poisoning` o `canary` scritte a mano: modificale li' (o toglile per usare i pulsanti)")

// ManualKey dice se il config ha la chiave top-level `key` scritta a mano (fuori dal blocco gestito).
func ManualKey(text, key string) bool {
	before, _, after, found := split(text)
	rest := text
	if found {
		rest = before + after
	}
	var m map[string]any
	if err := yaml.Unmarshal([]byte(rest), &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}

// ManualInterface dice se il config ha `interface` scritta a mano (fuori dal blocco gestito).
func ManualInterface(text string) bool {
	before, _, after, found := split(text)
	rest := text
	if found {
		rest = before + after
	}
	var m map[string]any
	if err := yaml.Unmarshal([]byte(rest), &m); err != nil {
		return false
	}
	_, ok := m["interface"]
	return ok
}

// ManualExtraRules dice se il config ha extra_rules scritte a mano (fuori dal blocco gestito).
func ManualExtraRules(text string) bool {
	before, _, after, found := split(text)
	rest := text
	if found {
		rest = before + after
	}
	return hasManualExtraRules(rest)
}

// Parse legge le scelte correnti dal blocco gestito. Se le chiavi stanno a mano fuori dal
// blocco restituisce ErrManual (la GUI mostra il testo e non permette di modificarle).
func Parse(text string) (Choice, error) {
	before, block, after, found := split(text)
	rest := text
	if found {
		rest = before + after
	}
	if hasManualKeys(rest) {
		return Choice{}, ErrManual
	}
	if !found {
		return Choice{}, nil
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(block, blockBegin+"\n"), blockEnd+"\n")
	var c Choice
	if err := yaml.Unmarshal([]byte(inner), &c); err != nil {
		return Choice{}, fmt.Errorf("blocco gestito non leggibile: %w", err)
	}
	return normalize(c), nil
}

// Apply rimpiazza (o toglie, se la scelta e' vuota) il blocco gestito e lascia il resto
// identico byte per byte.
func Apply(text string, c Choice) (string, error) {
	before, _, after, found := split(text)
	rest := text
	if found {
		rest = before + after
	}
	if hasManualKeys(rest) {
		return "", ErrManual
	}
	if len(c.ExtraRules) > 0 && hasManualExtraRules(rest) {
		return "", ErrManualRules
	}
	if c.Interface != "" && ManualInterface(text) {
		return "", ErrManualInterface
	}
	if (c.BlockPoisoning != nil && ManualKey(text, "block_poisoning")) || (c.Canary != nil && ManualKey(text, "canary")) {
		return "", ErrManualFeature
	}
	blk, err := Render(c)
	if err != nil {
		return "", err
	}
	if found {
		// stessa posizione di prima: il diff resta minimo
		return before + blk + after, nil
	}
	if blk == "" {
		return text, nil
	}
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	if text != "" && !bytes.HasSuffix([]byte(text), []byte("\n\n")) {
		text += "\n"
	}
	return text + blk, nil
}
