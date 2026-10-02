// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package audit consuma gli eventi del ring buffer e li stampa in formato text o JSON.
//
// Il ring buffer e' l'unico canale dal kernel verso questo processo. Quando il
// demone e' fermo il buffer si riempie e il kernel inizia a scartare eventi
// (bpf_ringbuf_reserve restituisce NULL): si perdono log, ma non si blocca mai
// il sistema. E' il comportamento giusto per un audit log.
package audit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"zt-shield/pkg/ipc"
)

// Event ha lo stesso layout di audit_event in zerotrust.c.
//
//	pid@0 (4) | comm@4 (16) | rule@20 (4) | ino@24 (8) | action@32 (4) | pad@36 (4) = 40 byte
//
// L'allineamento e' quello della struct C, non quello che il compilatore Go
// sceglierebbe per comodo: per questo c'e' `Pad` esplicito. Se i due layout
// divergono i campi vengono letti sfalsati e gli eventi riportano inode e regola
// sbagliati, senza alcun errore. (era esattamente il bug della v1)
type Event struct {
	PID    uint32
	Comm   [16]byte // TASK_COMM_LEN: troncato dal kernel, NON null-terminato
	Rule   uint32
	Inode  uint64
	Action uint32 // 1 = bloccato, 0 = solo audit
	Pad    uint32
}

// jsonEntry e' la forma in log_format: json.
// L'evento non porta il path (per non scrivere path su disco in chiaro), solo
// l'inode; `Exe` e' risolto qui in userspace e puo' fallire.
type jsonEntry struct {
	Time   string `json:"time"`
	Action string `json:"action"`
	PID    uint32 `json:"pid"`
	Comm   string `json:"comm"`
	Exe    string `json:"exe,omitempty"`
	Rule   string `json:"rule"`
	Inode  uint64 `json:"inode"`
}

// decodeEvent legge il payload con offset espliciti little-endian.
// FIX: prima si usava binary.Read sulla struct Go, che funziona solo perche'
// il padding Go coincide per fortuna con quello C (24%8==0). Aggiungere un campo
// o cambiare ordine avrebbe sfasato tutto in silenzio. Ora il layout e' fissato
// qui: pid@0, comm@4(16), rule@20, ino@24(8), action@32, pad@36, sizeof=40.
func decodeEvent(raw []byte) (Event, bool) {
	var ev Event
	if len(raw) < 40 {
		return ev, false
	}
	ev.PID = binary.LittleEndian.Uint32(raw[0:4])
	copy(ev.Comm[:], raw[4:20])
	ev.Rule = binary.LittleEndian.Uint32(raw[20:24])
	ev.Inode = binary.LittleEndian.Uint64(raw[24:32])
	ev.Action = binary.LittleEndian.Uint32(raw[32:36])
	ev.Pad = binary.LittleEndian.Uint32(raw[36:40])
	return ev, true
}

// ParsedEvent: un evento decodificato e arricchito, pronto per log e IPC.
// Introdotto per le UI: il demone lo pubblica sul socket oltre a loggarlo.
type ParsedEvent struct {
	Action string
	PID    uint32
	Comm   string
	Exe    string
	Rule   string
	Inode  uint64
}

// Run legge finche' il reader non viene chiuso. ruleName traduce l'id regola in nome.
// emit, se non nil, riceve ogni evento non soppresso dal rate-limit (per IPC UI).
//
// Va eseguito in una goroutine: il loop e' bloccante per costruzione.
func Run(rd *ringbuf.Reader, format string, ruleName func(uint32) string, emit func(ParsedEvent)) {
	// Encoder riusabile: non va ricreato per ogni evento, altrimenti si perde
	// il buffer interno. Su stdout perche' il log di testo va su stderr (log) e
	// il JSON su stdout: cosi' `zt-shield | jq` funziona senza miscelare i due.
	enc := json.NewEncoder(os.Stdout)
	// Rate-limit: senza, un attaccante spamma open() in loop e riempie
	// journal/disco (ogni deny = un log). Oltre 50 ev/s si sopprime e si
	// riepiloga ogni 5s. Prima: nessun limite, DoS log banale.
	const (
		maxPerSec    = 50
		summaryEvery = 5 * time.Second
		errBackoff   = 50 * time.Millisecond
	)
	windowStart := time.Now()
	inWindow := 0
	suppressed := 0
	lastSummary := time.Now()
	flushSummary := func() {
		if suppressed > 0 {
			log.Printf("⚠️ audit flood: %d eventi soppressi (rate-limit %d/s)", suppressed, maxPerSec)
			suppressed = 0
		}
		lastSummary = time.Now()
	}
	for {
		rec, err := rd.Read()
		if err != nil {
			// ErrClosed = il reader e' stato chiuso da main, chiusura normale.
			// Qualunque altro errore (EBADF, ENOTCONN) e' transitorio: si continua,
			// altrimenti un singolo errore ucciderebbe l'audit per tutta la vita
			// del processo e i blocchi successivi diventerebbero invisibili.
			if errors.Is(err, ringbuf.ErrClosed) {
				flushSummary()
				return
			}
			// FIX: prima `continue` senza attesa: errore persistente = busy loop
			// 100% CPU. Ora backoff breve.
			time.Sleep(errBackoff)
			continue
		}
		// RawSample: payload grezzo, da decodificare con il layout della struct C.
		ev, ok := decodeEvent(rec.RawSample)
		if !ok {
			continue // payload corrotto o di dimensione inattesa: scartato
		}
		// Rate-limit a finestra mobile di 1s.
		now := time.Now()
		if now.Sub(windowStart) >= time.Second {
			windowStart = now
			inWindow = 0
		}
		if inWindow >= maxPerSec {
			suppressed++
			if now.Sub(lastSummary) >= summaryEvery {
				flushSummary()
			}
			continue
		}
		inWindow++
		// comm arriva senza terminatore: va ripulito prima di stampare.
		// SafeText: comm e' scelto dal processo (prctl) e finirebbe grezzo nel
		// terminale/journal con eventuali sequenze ANSI.
		comm := ipc.SafeText(string(bytes.TrimRight(ev.Comm[:], "\x00")))
		// Best effort: il processo potrebbe essere già terminato. Utile per sapere quale binario autorizzare.
		// NOTA: /proc/PID/exe e' racy, se il PID e' stato riusato punta al processo sbagliato.
		// Non e' un problema di sicurezza (decide il kernel, non questo log), solo di affidabilita' del dato.
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", ev.PID))
		exe = ipc.SafeText(exe)
		action := "audit"
		if ev.Action == 1 {
			action = "blocked"
		}
		rule := ruleName(ev.Rule)
		if emit != nil {
			emit(ParsedEvent{Action: action, PID: ev.PID, Comm: comm, Exe: exe, Rule: rule, Inode: ev.Inode})
		}

		if format == "json" {
			enc.Encode(jsonEntry{
				Time: time.Now().UTC().Format(time.RFC3339), Action: action, PID: ev.PID,
				Comm: comm, Exe: exe, Rule: rule, Inode: ev.Inode,
			})
			continue
		}
		// Due icone distinte: in audit l'utente deve capire che NON e' successo niente
		// e che quello che vede e' una prova che il blocco avrebbe funzionato.
		icon := "👁️ [AUDIT]"
		if ev.Action == 1 {
			icon = "🚨 [BLOCCATO]"
		}
		// `exe` e' il path del binario autoreale; vuoto se il processo e' gia' sparito.
		// Comunque compare, perche' e' la pista che dice quale regola va allargata.
		log.Printf("%s regola=%s PID=%d comm='%s' exe=%s inode=%d", icon, rule, ev.PID, comm, exe, ev.Inode)
	}
}
