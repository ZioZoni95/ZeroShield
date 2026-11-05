// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"path/filepath"
	"sort"
	"strings"

	"zt-shield/pkg/rules"
)

// baseName: nome del binario senza directory ne' suffisso " (deleted)" che il kernel
// aggiunge a /proc/PID/exe quando il file e' stato sostituito (tipico dopo apt upgrade).
func baseName(exe string) string {
	exe = strings.TrimSuffix(exe, " (deleted)")
	return filepath.Base(exe)
}

// suggestVerdict dice se ha senso proporre di autorizzare exe; why spiega il no. La logica
// sta in pkg/rules, condivisa con la GUI.
func suggestVerdict(exe string) (ok bool, why string) { return rules.Verdict(exe) }

// blastRow: un binario che attraversa piu' regole.
type blastRow struct {
	Exe   string
	Rules []string
}

// blastRadius calcola, per ogni binario, le regole che raggiunge. Si raggruppa per
// nome base: "git" in una regola e "/usr/bin/git" in un'altra sono lo stesso binario
// (prima venivano contati come due e il rischio risultava sottostimato). Restituisce
// solo i binari in piu' di una regola, ordinati per numero di regole e poi per nome:
// l'ordine e' deterministico, la vista non sfarfalla a ogni ridisegno.
func blastRadius(rules []ruleAllow) []blastRow {
	reach := map[string]map[string]bool{}
	for _, r := range rules {
		for _, a := range r.Allow {
			k := baseName(a)
			if reach[k] == nil {
				reach[k] = map[string]bool{}
			}
			reach[k][r.Name] = true
		}
	}
	var rows []blastRow
	for exe, set := range reach {
		if len(set) < 2 {
			continue
		}
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		rows = append(rows, blastRow{Exe: exe, Rules: names})
	}
	sort.Slice(rows, func(i, j int) bool {
		if len(rows[i].Rules) != len(rows[j].Rules) {
			return len(rows[i].Rules) > len(rows[j].Rules)
		}
		return rows[i].Exe < rows[j].Exe
	})
	return rows
}

// ruleAllow: la parte di una regola che serve al blast-radius (evita di dipendere da ipc nei test).
type ruleAllow struct {
	Name  string
	Allow []string
}
