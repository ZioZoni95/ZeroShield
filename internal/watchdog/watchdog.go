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
	"time"
)

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
