// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package ipc

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SafeText neutralizza i caratteri non stampabili di una stringa scelta da un
// processo potenzialmente ostile (comm, path dell'exe, path del file).
//
// comm si imposta con prctl(PR_SET_NAME) senza privilegi e un nome di file puo'
// contenere qualsiasi byte tranne '/' e NUL: senza filtro un malware chiamato
// "\x1b]52;c;..." inietta sequenze ANSI/OSC nel terminale di chi guarda la TUI o
// il log (titolo finestra, clipboard, testo falso sopra gli eventi veri).
// Ogni rune non stampabile (o byte UTF-8 invalido) diventa \xNN / \u{NNNN}.
func SafeText(s string) string {
	clean := true
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case !unicode.IsPrint(r):
			if r < 0x80 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				fmt.Fprintf(&b, `\u{%04x}`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}
