// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package watchdog: ping systemd (sd_notify WATCHDOG=1).
//
// Perche' non pinning bpffs: mappe/programmi pinnati sopravvivono al demone,
// lasciando hook attivi senza log né rescan — protezione a metà, il caso che
// il fail-closed vuole evitare. Meglio morto-visibile (restart) che mezzo-vivo.
// Il watchdog riavvia un demone hung; ExecStartPre+StartLimit (unit) gestiscono
// il resto. Senza NOTIFY_SOCKET (avvio manuale) e' no-op silenzioso.
package watchdog

import (
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// Liveness ricorda quando il rescan ha battuto l'ultima volta e quanto tempo e' passato, su un orologio MONOTONO.
//
// FIX (2026-11-25): prima l'istante era salvato come ora di calendario (UnixNano). Alla ripresa da una sospensione
// l'ora di calendario salta in avanti di tutto il tempo dormito: il demone vedeva «rescan fermo da 10 minuti»,
// smetteva di avvisare systemd e il watchdog lo uccideva con SIGABRT (visto il 9 e il 23 novembre, a ogni
// sospensione lunga). L'orologio monotono di Go (CLOCK_MONOTONIC) non conta il tempo di sospensione.
// Si conserva percio' un `time.Time` intero e si misura sempre con Sub, mai passando da UnixNano.
type Liveness struct {
	now   func() time.Time
	start time.Time
	last  atomic.Int64 // nanosecondi dall'avvio, misurati con l'orologio monotono
}

// NewLiveness parte da adesso: all'avvio il rescan e' considerato appena battuto.
func NewLiveness() *Liveness { return newLiveness(time.Now) }

func newLiveness(now func() time.Time) *Liveness {
	l := &Liveness{now: now, start: now()}
	l.Touch()
	return l
}

// Touch segna che il rescan e' vivo adesso.
func (l *Liveness) Touch() { l.last.Store(int64(l.now().Sub(l.start))) }

// Since: tempo (monotono) dall'ultimo battito.
func (l *Liveness) Since() time.Duration {
	return l.now().Sub(l.start) - time.Duration(l.last.Load())
}

// Ping avvisa systemd che siamo vivi. Ritorna nil anche senza socket.
func Ping() error { return notify("WATCHDOG=1") }

// Ready segnala a systemd la fine dell'avvio (utile con Type=notify, innocuo altrove).
func Ready() error { return notify("READY=1") }

// Interval: cadenza consigliata dei ping, cioe' meta' di WatchdogSec
// (systemd la passa in WATCHDOG_USEC). 0 = watchdog non attivo.
//
// FIX: prima si pingava a ogni rescan (default 30s) con WatchdogSec=30: il
// ping arrivava al limite o dopo, systemd uccideva il demone ogni ~30s e con
// StartLimitBurst=3 lo lasciava fermo. La regola sd_watchdog_enabled(3) e'
// pingare a meta' intervallo.
func Interval() time.Duration {
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}
	return time.Duration(usec) * time.Microsecond / 2
}

func notify(state string) error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil
	}
	conn, err := net.Dial("unixgram", sock)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}
