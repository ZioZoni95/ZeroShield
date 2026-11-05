// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package rules: tutto cio' che serve a un'interfaccia per scegliere le regole senza
// scrivere YAML a mano: quali programmi si possono autorizzare, perche' alcuni no, e come
// si scrivono le scelte nel config (blocco gestito).
//
// Nessun privilegio e nessun import di eBPF: lo usano GUI, TUI, test e demone.
package rules

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
)

// Trusted verifica che un utente non root non possa sostituire o modificare il binario:
// il file e ogni directory padre devono essere di root, non scrivibili da "others" e
// scrivibili dal gruppo solo se il gruppo e' root. Basta un anello debole (una dir padre
// dell'utente) per riscrivere il binario ed ereditarne l'autorizzazione.
// E' la stessa regola con cui il demone scarta i binari dalla whitelist (internal/lsm).
func Trusted(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			return fmt.Errorf("stat %s: %w", p, err)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s appartiene a uid %d, non a root", p, st.Uid)
		}
		if st.Mode&0o002 != 0 {
			return fmt.Errorf("%s scrivibile da chiunque", p)
		}
		if st.Mode&0o020 != 0 && st.Gid != 0 {
			return fmt.Errorf("%s scrivibile dal gruppo %d", p, st.Gid)
		}
		if p == "/" || p == "." {
			return nil
		}
	}
}

// systemPrefixes: dove vivono i binari che ha senso autorizzare. Una lista di percorsi
// ammessi, non di vietati: /var/tmp, /run/user, /mnt... restano fuori senza elencarli.
var systemPrefixes = []string{"/usr/", "/bin/", "/sbin/", "/opt/", "/snap/"}

// Shell e interpreti: autorizzarli autorizza OGNI script che li usa (exe_file di uno
// script e' l'interprete).
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
// autorizzarli per una regola significa autorizzare chiunque a leggere quel segreto.
var genericTools = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true, "tee": true,
	"cp": true, "mv": true, "dd": true, "tar": true, "rsync": true, "install": true,
	"xxd": true, "od": true, "hexdump": true, "strings": true, "base64": true,
	"grep": true, "egrep": true, "fgrep": true, "sed": true, "sort": true, "find": true,
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "socat": true,
	"gzip": true, "bzip2": true, "xz": true, "zip": true, "7z": true,
}

// Verdict dice se ha senso proporre di autorizzare exe; why spiega il no. Giudica solo il
// tipo di programma: che il demone lo accetti davvero lo dice Trusted.
func Verdict(exe string) (ok bool, why string) {
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
	name := filepath.Base(exe)
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
