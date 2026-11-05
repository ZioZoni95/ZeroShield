// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package rules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"zt-shield/internal/config"
)

// Program: l'esito del controllo su un programma da autorizzare. Serve alla GUI per dire
// "si" oppure "no, perche'" e, quando il no si puo' aggirare, il comando per farlo.
type Program struct {
	Input     string `json:"input"`
	Name      string `json:"name"`
	Path      string `json:"path"`       // percorso reale (symlink seguiti)
	Found     bool   `json:"found"`      // esiste sul sistema
	Trusted   bool   `json:"trusted"`    // il demone lo accetterebbe (tutto di root)
	TrustErr  string `json:"trust_err"`  // perche' no
	VerdictOK bool   `json:"verdict_ok"` // tipo di programma sensato da autorizzare
	Why       string `json:"why"`        // perche' no, se VerdictOK e' falso
	Fix       string `json:"fix"`        // comando per renderlo affidabile (da eseguire con sudo)
	OK        bool   `json:"ok"`         // si puo' aggiungere subito
	// Alt: copia affidabile dello stesso programma gia' presente in una cartella di sistema
	// (di solito dopo "Rendi affidabile"). Se esiste ma il terminale lancia ancora l'altra
	// (Path), l'autorizzazione vale per Alt e la GUI avvisa che va usata quella.
	Alt string `json:"alt"`
}

// Check valuta input (nome o percorso) per l'utente con home `home`.
func Check(home, input string) Program {
	p := Program{Input: input, Name: filepath.Base(strings.TrimSpace(input))}
	path, ok := Resolve(home, input)
	if !ok {
		p.Why = "non trovato sul sistema"
		return p
	}
	p.Found, p.Path, p.Name = true, path, filepath.Base(path)
	p.VerdictOK, p.Why = Verdict(path)
	if err := Trusted(path); err != nil {
		p.TrustErr = err.Error()
		// Il verdetto "fuori dai percorsi di sistema" e' la stessa cosa detta in altro modo:
		// qui interessa il rimedio, non una seconda frase.
		if !p.VerdictOK && strings.HasPrefix(p.Why, "fuori dai percorsi") {
			p.VerdictOK, p.Why = true, ""
		}
		// Il rimedio e' una copia di root in /usr/local/bin, proposta solo per programmi
		// installati sotto /home (brew, ~/.local/bin) e mai se il nome esiste gia' li'.
		if p.VerdictOK && !genericOrInterpreter(p.Name) && strings.HasPrefix(path, "/home/") {
			if _, err := os.Lstat("/usr/local/bin/" + p.Name); err != nil {
				p.Fix = fmt.Sprintf("sudo install -m 0755 %q /usr/local/bin/%s", path, p.Name)
			}
		}
		for _, d := range []string{"/usr/local/bin", "/usr/bin"} {
			alt := filepath.Join(d, p.Name)
			if real, err := filepath.EvalSymlinks(alt); err == nil && real != path && Trusted(real) == nil {
				p.Alt = real
				break
			}
		}
	} else {
		p.Trusted = true
	}
	p.OK = p.Found && p.Trusted && p.VerdictOK
	return p
}

func genericOrInterpreter(name string) bool {
	if interpreterNames[name] || genericTools[name] {
		return true
	}
	for _, pre := range interpreterPrefixes {
		if strings.HasPrefix(name, pre) {
			return true
		}
	}
	return false
}

// GroupView: un gruppo di segreti come lo mostra la GUI.
type GroupView struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"` // nome della regola (quello dei log)
	Desc       string   `json:"desc"`
	Paths      []string `json:"paths"`
	Allow      []string `json:"allow"`       // programmi di base
	ExtraAllow []string `json:"extra_allow"` // aggiunti con la GUI
	InProfile  bool     `json:"in_profile"`  // gia' nel config di base (profilo o regole a mano)
	Active     bool     `json:"active"`
	Mode       string   `json:"mode"`     // modalita' effettiva (audit|enforce)
	ModeSet    string   `json:"mode_set"` // scelta esplicita per questa regola ("" = eredita la globale)
	Removed    []string `json:"removed"`  // programmi di base tolti con la GUI
}

// MyRuleView: una regola personale creata con la GUI.
type MyRuleView struct {
	CustomRule
	EffectiveMode string `json:"effective_mode"`
}

// ToolView: un programma del catalogo, con lo stato attuale sul sistema.
type ToolView struct {
	Tool
	Program
	Allowed []string `json:"allowed"` // regole in cui e' gia' autorizzato
}

// Model: tutto cio' che serve a disegnare la schermata Regole.
type Model struct {
	Profile string       `json:"profile"`
	Groups  []GroupView  `json:"groups"`
	Tools   []ToolView   `json:"tools"`
	Custom  []string     `json:"custom"`   // nomi di regole scritte a mano nel config
	MyRules []MyRuleView `json:"my_rules"` // regole personali create con la GUI
	Choice  Choice       `json:"choice"`
	Manual  bool         `json:"manual"` // scelte scritte a mano: la GUI non le modifica
	// ManualRules: extra_rules scritte a mano: «Proteggi un mio file» resta spento (stessa chiave due volte).
	ManualRules bool `json:"manual_rules"`
	// ManualInterface: `interface` scritta a mano (BaseInterface ne e' il valore): la scelta dalla GUI e' spenta.
	ManualInterface bool   `json:"manual_interface"`
	BaseInterface   string `json:"base_interface"`
	GlobalMode      string `json:"global_mode"` // audit | enforce
	Error           string `json:"error"`
}

// BuildModel costruisce il modello dal testo del config. Non scrive nulla.
func BuildModel(cfgText, home string) Model {
	m := Model{}
	choice, perr := Parse(cfgText)
	base := cfgText
	switch {
	case errors.Is(perr, ErrManual):
		m.Manual = true
	case perr != nil:
		m.Error = perr.Error()
	default:
		m.Choice = choice
		if s, err := Apply(cfgText, Choice{}); err == nil {
			base = s
		}
	}
	cfg, err := loadText(base)
	if err != nil {
		m.Error = "configurazione non leggibile: " + err.Error()
		return m
	}
	m.Profile, m.GlobalMode = cfg.Profile, cfg.Mode
	m.ManualRules = ManualExtraRules(cfgText)
	m.ManualInterface = ManualInterface(cfgText)
	m.BaseInterface = cfg.Interface
	byName := map[string]config.Rule{}
	for _, r := range cfg.AllRules() {
		byName[r.Name] = r
	}
	profile := config.ProfileGroups(cfg.Profile)
	groupNames := map[string]bool{}
	for _, id := range config.GroupOrder {
		g, _ := config.Group(id)
		groupNames[g.Name] = true
		gv := GroupView{ID: id, Name: g.Name, Desc: config.GroupDesc[id], Paths: g.Paths, Allow: g.Allow,
			InProfile: slices.Contains(profile, id), ExtraAllow: m.Choice.AllowExtra[g.Name],
			Removed: m.Choice.RemoveAllow[g.Name]}
		if r, present := byName[g.Name]; present {
			gv.InProfile = true // presente senza le scelte della GUI: si accende/spegne con disable_rules
			gv.Paths, gv.Allow = r.Paths, r.Allow
			gv.Active = !slices.Contains(m.Choice.DisableRules, g.Name)
			gv.ModeSet = r.Mode
		} else {
			gv.Active = slices.Contains(m.Choice.EnableGroups, id)
		}
		if v, ok := m.Choice.RuleModes[g.Name]; ok {
			gv.ModeSet = v
		}
		gv.Mode = gv.ModeSet
		if gv.Mode == "" {
			gv.Mode = cfg.Mode
		}
		m.Groups = append(m.Groups, gv)
	}
	for _, r := range m.Choice.ExtraRules {
		eff := r.Mode
		if eff == "" {
			eff = cfg.Mode
		}
		m.MyRules = append(m.MyRules, MyRuleView{CustomRule: r, EffectiveMode: eff})
	}
	for _, r := range cfg.AllRules() {
		if !groupNames[r.Name] {
			m.Custom = append(m.Custom, r.Name)
		}
	}
	for _, t := range Tools {
		tv := ToolView{Tool: t}
		for _, n := range t.Names {
			if c := Check(home, n); c.Found {
				tv.Program = c
				break
			}
		}
		if !tv.Found {
			tv.Name = t.Names[0]
		}
		for _, rn := range t.Rules {
			r, ok := byName[rn]
			if !ok {
				continue
			}
			all := append(append([]string(nil), r.Allow...), m.Choice.AllowExtra[rn]...)
			all = slices.DeleteFunc(all, func(a string) bool {
				return slices.Contains(m.Choice.RemoveAllow[rn], a) || slices.Contains(m.Choice.RemoveAllow[rn], filepath.Base(a))
			})
			for _, a := range all {
				if (tv.Found && a == tv.Path) || slices.Contains(t.Names, filepath.Base(a)) && (a == filepath.Base(a) || a == tv.Path) {
					tv.Allowed = append(tv.Allowed, rn)
					break
				}
			}
		}
		m.Tools = append(m.Tools, tv)
	}
	return m
}

// loadText valida un testo di config con il parser del demone, senza toccare il sistema.
func loadText(text string) (*config.Config, error) {
	dir, err := os.MkdirTemp("", "zt-model-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "shield.yaml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		return nil, err
	}
	return config.Load(p)
}

// Validate controlla che il testo risultante sia accettato dal demone (stesso parser).
func Validate(text string) error {
	_, err := loadText(text)
	return err
}
