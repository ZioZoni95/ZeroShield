// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// customName: nome tecnico di una regola personale (compare nei log). La GUI lo ricava dal titolo scritto
// dall'utente («Wallet crypto» -> wallet-crypto), qui si controlla soltanto.
var customName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$`)

// reserved: nomi dei gruppi predefiniti, per non creare due regole con lo stesso nome.
var reserved = map[string]bool{"ssh-keys": true, "cloud-creds": true, "dev-tokens": true, "gpg-keys": true, "browser-secrets": true}

// tooBroad: percorsi che, protetti, renderebbero il sistema inutilizzabile (ogni programma negato).
var tooBroad = map[string]bool{
	"": true, ".": true, "/": true, "~": true, "*": true, "**": true, "/*": true, "/**": true,
	"/etc": true, "/usr": true, "/bin": true, "/sbin": true, "/lib": true, "/lib64": true, "/var": true,
	"/home": true, "/root": true, "/proc": true, "/sys": true, "/dev": true, "/boot": true, "/run": true, "/tmp": true,
}

// checkPath: vale per un percorso scelto dall'utente. Relativo = sotto la home.
func checkPath(p string) error {
	if strings.ContainsAny(p, "\x00\n\r\t") || len(p) > 4096 {
		return fmt.Errorf("percorso %q non valido", p)
	}
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		if part == ".." {
			return fmt.Errorf("%q: «..» non è ammesso", p)
		}
	}
	c := strings.TrimSuffix(filepath.Clean(strings.TrimPrefix(p, "~/")), "/")
	if tooBroad[c] || tooBroad[p] || strings.HasPrefix(c, "*") {
		return fmt.Errorf("%q è troppo largo: proteggerlo bloccherebbe quasi ogni programma", p)
	}
	return nil
}

// ValidateCustom controlla una regola personale con le stesse regole del demone, ma con messaggi per l'utente.
func ValidateCustom(r CustomRule) error {
	if !customName.MatchString(r.Name) {
		return fmt.Errorf("nome %q non valido (lettere, numeri, - . _ ; massimo 40 caratteri)", r.Name)
	}
	if reserved[r.Name] {
		return fmt.Errorf("il nome %q è già usato da una protezione predefinita", r.Name)
	}
	if len(r.Paths) == 0 {
		return fmt.Errorf("«%s»: scegli almeno un file o una cartella", r.Name)
	}
	if len(r.Paths) > 50 {
		return fmt.Errorf("«%s»: troppi percorsi (massimo 50)", r.Name)
	}
	for _, p := range r.Paths {
		if err := checkPath(p); err != nil {
			return err
		}
	}
	if len(r.Allow) == 0 {
		return fmt.Errorf("«%s»: serve almeno un programma autorizzato, altrimenti non potresti più leggere nemmeno tu quel file", r.Name)
	}
	for _, a := range r.Allow {
		if !strings.HasPrefix(a, "/") || strings.ContainsAny(a, "*?[\x00\n\r\t") || a != filepath.Clean(a) {
			return fmt.Errorf("programma %q: serve un percorso assoluto pulito, senza jolly", a)
		}
	}
	if r.Mode != "" && r.Mode != "audit" && r.Mode != "enforce" {
		return fmt.Errorf("modalità %q non valida", r.Mode)
	}
	return nil
}

// PreviewResult: cosa proteggerebbe una regola personale, per mostrarlo PRIMA di salvare.
type PreviewResult struct {
	Matched  int      `json:"matched"`  // file regolari trovati (tetto 5000)
	Capped   bool     `json:"capped"`   // c'erano piu' file del tetto
	Examples []string `json:"examples"` // primi percorsi trovati
	Missing  []string `json:"missing"`  // percorsi che oggi non esistono (si proteggono se compaiono)
	Warnings []string `json:"warnings"`
	Errors   []string `json:"errors"` // la regola non e' salvabile
}

const (
	previewCap     = 5000
	fsBtrfs        = 0x9123683E
	fsOverlay      = 0x794C7630
	manyFilesLimit = 200
)

// Preview risolve i percorsi come fa il demone (relativi alla home, glob, cartelle ricorsive) e segnala i problemi
// piu' comuni: troppo largo, troppi file, filesystem dove la protezione non funziona.
func Preview(home string, paths []string) PreviewResult {
	res := PreviewResult{}
	seen := map[string]bool{}
	add := func(f string) {
		if seen[f] || res.Matched >= previewCap {
			if res.Matched >= previewCap {
				res.Capped = true
			}
			return
		}
		seen[f] = true
		res.Matched++
		if len(res.Examples) < 5 {
			res.Examples = append(res.Examples, f)
		}
	}
	badFS := map[string]bool{}
	for _, p := range paths {
		if err := checkPath(p); err != nil {
			res.Errors = append(res.Errors, err.Error())
			continue
		}
		abs := p
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(home, strings.TrimPrefix(p, "~/"))
		}
		var targets []string
		if strings.ContainsAny(abs, "*?[") {
			m, err := filepath.Glob(abs)
			if err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%q: schema non valido", p))
				continue
			}
			targets = m
		} else {
			targets = []string{abs}
		}
		found := false
		for _, t := range targets {
			fi, err := os.Lstat(t)
			if err != nil {
				continue
			}
			found = true
			if w := fsWarning(t); w != "" {
				badFS[w] = true
			}
			if fi.IsDir() {
				_ = filepath.WalkDir(t, func(f string, d fs.DirEntry, err error) error {
					if err != nil {
						return nil
					}
					if d.Type().IsRegular() {
						add(f)
					}
					if res.Matched >= previewCap {
						return fs.SkipAll
					}
					return nil
				})
			} else if fi.Mode().IsRegular() {
				add(t)
			}
		}
		if !found {
			res.Missing = append(res.Missing, p)
		}
	}
	for w := range badFS {
		res.Warnings = append(res.Warnings, w)
	}
	if res.Capped {
		res.Warnings = append(res.Warnings, fmt.Sprintf("Più di %d file: il demone ne protegge al massimo 4096 per regola. Scegli una cartella più piccola.", previewCap))
	} else if res.Matched > manyFilesLimit {
		res.Warnings = append(res.Warnings, fmt.Sprintf("Sono %d file: una regola così larga rischia di bloccare programmi legittimi. Restringila se puoi.", res.Matched))
	}
	if res.Matched == 0 && len(res.Errors) == 0 && len(res.Missing) == len(paths) {
		res.Warnings = append(res.Warnings, "Oggi questo percorso non esiste: la regola scatterà se compare (il demone controlla ogni 30 secondi).")
	}
	return res
}

// fsWarning: la protezione funziona solo su ext4/xfs (vedi README, limiti): su btrfs e overlay la chiave
// (dev, inode) del kernel non corrisponde e la regola resterebbe inerte senza alcun errore.
func fsWarning(path string) string {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return ""
	}
	switch int64(st.Type) {
	case fsBtrfs:
		return "Il file sta su btrfs: la protezione non funziona su questo filesystem (la regola resterebbe inerte)."
	case fsOverlay:
		return "Il file sta su overlayfs: la protezione non funziona su questo filesystem (la regola resterebbe inerte)."
	}
	return ""
}
