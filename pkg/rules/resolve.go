// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package rules

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Resolve trova il binario `name` come lo troverebbe l'utente (PATH + posti tipici fuori
// dal PATH di una GUI: snap, brew, ~/.local/bin) e ne segue i symlink. Se name e' gia'
// un percorso assoluto lo usa cosi'. ok=false se non esiste.
//
// Il percorso risolto e' quello che finisce nel config: il demone ragiona su file reali
// (inode), non su nomi, e il suo PATH (sotto systemd) e' diverso da quello dell'utente.
func Resolve(home, name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsRune(name, 0) {
		return "", false
	}
	cand := name
	if !filepath.IsAbs(name) {
		if strings.ContainsRune(name, '/') {
			return "", false // relativo con directory: ambiguo, si chiede il nome o il percorso assoluto
		}
		p, err := exec.LookPath(name)
		if err != nil {
			p = ""
			for _, d := range []string{"/usr/local/bin", "/usr/bin", "/bin", "/snap/bin",
				"/home/linuxbrew/.linuxbrew/bin", filepath.Join(home, ".local/bin"), filepath.Join(home, "bin")} {
				c := filepath.Join(d, name)
				if fi, e := os.Stat(c); e == nil && !fi.IsDir() {
					p = c
					break
				}
			}
			if p == "" {
				return "", false
			}
		}
		cand = p
	}
	real, err := filepath.EvalSymlinks(cand)
	if err != nil {
		return "", false
	}
	if fi, err := os.Stat(real); err != nil || fi.IsDir() {
		return "", false
	}
	return real, true
}
