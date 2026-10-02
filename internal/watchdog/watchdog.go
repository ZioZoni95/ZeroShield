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
)

// Ping avvisa systemd che siamo vivi. Ritorna nil anche senza socket.
func Ping() error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil
	}
	conn, err := net.Dial("unixgram", sock)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("WATCHDOG=1"))
	return err
}
