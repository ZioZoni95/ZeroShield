// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"path/filepath"
	"sort"
	"strings"
)

// systemPrefixes: dove vivono i binari che ha senso autorizzare. Il demone accetta in
// whitelist solo binari di root (lsm.trustedExe); qui si propone solo cio' che puo'
// passare. Una lista di percorsi ammessi, non di vietati: /var/tmp, /run/user, /mnt...
// restano fuori senza doverli elencare uno per uno.
var systemPrefixes = []string{"/usr/", "/bin/", "/sbin/", "/opt/", "/snap/"}

// Shell e interpreti: autorizzarli autorizza OGNI script che li usa (exe_file di uno
// script e' l'interprete). E' il caso che la documentazione vieta in modo esplicito.
var interpreterNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "fish": true, "ksh": true,
	"csh": true, "tcsh": true, "ash": true, "busybox": true, "env": true,
	"node": true, "nodejs": true, "deno": true, "bun": true, "java": true,
	"pwsh": true, "powershell": true, "tclsh": true, "wish": true,
	"awk": true, "gawk": true, "mawk": true,
}

// Prefissi di nome con numero di versione: python3.12, perl5.38, php8.3, ruby3.2, lua5.4.
var interpreterPrefixes = []string{"python", "perl", "ruby", "php", "lua"}

// Lettori, copiatori e trasferitori generici: chi li invoca sceglie il file, quindi
// autorizzarli per una regola significa autorizzare chiunque a leggere quel segreto
// (stesso limite strutturale di `git hash-object ~/.kube/config`).
var genericTools = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true, "tee": true,
	"cp": true, "mv": true, "dd": true, "tar": true, "rsync": true, "install": true,
	"xxd": true, "od": true, "hexdump": true, "strings": true, "base64": true,
	"grep": true, "egrep": true, "fgrep": true, "sed": true, "sort": true, "find": true,
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "socat": true,
	"gzip": true, "bzip2": true, "xz": true, "zip": true, "7z": true,
}

// baseName: nome del binario senza directory ne' suffisso " (deleted)" che il kernel
// aggiunge a /proc/PID/exe quando il file e' stato sostituito (tipico dopo apt upgrade).
func baseName(exe string) string {
	exe = strings.TrimSuffix(exe, " (deleted)")
	return filepath.Base(exe)
}

// suggestVerdict dice se ha senso proporre di autorizzare exe. why spiega il no.
func suggestVerdict(exe string) (ok bool, why string) {
	exe = strings.TrimSuffix(exe, " (deleted)")
	underSystem := false
	for _, p := range systemPrefixes {
		if strings.HasPrefix(exe, p) {
			underSystem = true
			break
		}
	}
	if !underSystem {
		return false, "fuori dai percorsi di sistema (classico bypass per rename/copia)"
	}
	name := baseName(exe)
	if interpreterNames[name] {
		return false, "shell/interprete: autorizzarlo autorizza qualunque script"
	}
	for _, p := range interpreterPrefixes {
		if strings.HasPrefix(name, p) {
			return false, "interprete: autorizzarlo autorizza qualunque script"
		}
	}
	if genericTools[name] {
		return false, "lettore/copiatore generico: chi lo invoca sceglie il file"
	}
	return true, ""
}

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
