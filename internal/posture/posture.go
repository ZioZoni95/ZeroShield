// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package posture legge alcune impostazioni del kernel che non dipendono da ZeroShield ma ne
// cambiano l'efficacia: ptrace (lettura della memoria di un programma autorizzato) e io_uring
// (percorso che l'hook dei file non vede). Sono limiti noti e dichiarati: qui diventano un
// controllo visibile, con il comando per chiuderli. Non modifica nulla del sistema.
package posture

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Item: un controllo di postura. OK=true significa "nessuna azione consigliata".
type Item struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"` // comando da eseguire con sudo, solo se !OK
}

// ProcSys: percorso della radice di /proc/sys (parametro per i test).
const ProcSys = "/proc/sys"

// Check legge le impostazioni sotto root (di solito ProcSys) e restituisce i controlli.
func Check(root string) []Item {
	return []Item{ptrace(root), ioUring(root)}
}

// readInt legge un intero da root/rel; found=false se il file non esiste o non e' un numero
// (kernel senza quella funzione).
func readInt(root, rel string) (v int, found bool) {
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, false
	}
	return n, true
}

func ptrace(root string) Item {
	it := Item{ID: "ptrace", Title: "Memoria dei programmi protetta da ptrace"}
	v, ok := readInt(root, "kernel/yama/ptrace_scope")
	switch {
	case !ok:
		it.Detail = "Il modulo Yama non è attivo: un programma con il tuo stesso utente può leggere la memoria di ssh e degli altri programmi autorizzati e ricavarne le chiavi."
		it.Fix = "Aggiungi «yama» ai moduli di sicurezza del kernel (parametro lsm=…,yama,bpf)."
	case v == 0:
		it.Detail = "Qualunque programma con il tuo stesso utente può leggere la memoria di ssh e degli altri programmi autorizzati e ricavarne le chiavi."
		it.Fix = "echo 'kernel.yama.ptrace_scope = 1' | sudo tee /etc/sysctl.d/60-zeroshield-ptrace.conf && sudo sysctl --system"
	default:
		it.OK = true
		it.Detail = "Solo un programma può ispezionare i propri discendenti (ptrace_scope=" + strconv.Itoa(v) + ")."
	}
	return it
}

func ioUring(root string) Item {
	it := Item{ID: "io_uring", Title: "Percorso io_uring chiuso"}
	v, ok := readInt(root, "kernel/io_uring_disabled")
	switch {
	case !ok:
		it.Detail = "Questo kernel non permette di spegnere io_uring (serve la versione 6.6 o successiva): un programma ostile può leggere un file protetto senza passare dal controllo."
	case v == 0:
		it.Detail = "io_uring è attivo: un programma ostile può leggere un file protetto senza passare dal controllo. Spegnerlo può rompere pochi programmi (alcuni database e runtime asincroni)."
		it.Fix = "echo 'kernel.io_uring_disabled = 2' | sudo tee /etc/sysctl.d/60-zeroshield-iouring.conf && sudo sysctl --system"
	default:
		it.OK = true
		it.Detail = "io_uring è limitato o spento (io_uring_disabled=" + strconv.Itoa(v) + ")."
	}
	return it
}
