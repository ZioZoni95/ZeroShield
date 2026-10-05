// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package vpn misura lo stato REALE di tunnel e kill-switch per le UI.
//
// Prima lo stato era "l'interfaccia esiste ed e' UP": un WireGuard senza handshake
// risultava verde e un kill-switch mai applicato era invisibile (il campo YAML
// `enabled` non applica niente, lo fa scripts/vpn_killswitch.sh). Qui si guardano
// tre fatti indipendenti e le UI li combinano:
//
//	Up           l'interfaccia esiste ed e' UP
//	KillSwitch   la tabella nft "inet zt-killswitch" e' caricata adesso
//	HandshakeAge secondi dall'ultimo handshake WireGuard (-1 = sconosciuto o mai)
//
// Il demone gira come root, quindi nft e wg sono eseguibili. Se mancano, il fatto
// resta "falso/sconosciuto": mai un verde non verificato.
package vpn

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"zt-shield/internal/config"
	"zt-shield/pkg/ipc"
)

// Table e' il nome della tabella nft creata da scripts/vpn_killswitch.sh.
const Table = "zt-killswitch"

// Runner esegue un comando e restituisce stdout. Iniettabile per i test.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner esegue davvero il comando, con timeout e ambiente minimo: nessun
// input utente passa di qui (nome interfaccia validato in config).
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.Bytes(), err
}

// ifaceUp: vero se l'interfaccia esiste ed e' UP. Variabile per i test.
var ifaceUp = func(name string) bool {
	if _, err := os.Stat("/sys/class/net/" + name); err != nil {
		return false
	}
	ifc, err := net.InterfaceByName(name)
	return err == nil && ifc.Flags&net.FlagUp != 0
}

var now = time.Now

// Check fotografa lo stato. Con la VPN non configurata restituisce solo Enabled=false.
func Check(cfg config.VpnConfig, run Runner) ipc.VpnStatus {
	st := ipc.VpnStatus{Enabled: cfg.Enabled, Endpoint: cfg.Endpoint, Tunnel: cfg.Tunnel, HandshakeAge: -1}
	if !cfg.Enabled || cfg.Tunnel == "" {
		return st
	}
	ctx := context.Background()
	st.Up = ifaceUp(cfg.Tunnel)
	if _, err := run(ctx, "nft", "list", "table", "inet", Table); err == nil {
		st.KillSwitch = true
	}
	if st.Up {
		if out, err := run(ctx, "wg", "show", cfg.Tunnel, "latest-handshakes"); err == nil {
			st.HandshakeAge = handshakeAge(string(out), now())
		}
	}
	return st
}

// handshakeAge legge l'output di `wg show <if> latest-handshakes`: una riga per peer,
// "<chiave pubblica>\t<unix time>" (0 = mai). Con piu' peer vale l'handshake piu'
// recente. Restituisce -1 se non c'e' nessun handshake valido.
func handshakeAge(out string, t time.Time) int {
	var newest int64
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		ts, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || ts <= 0 {
			continue
		}
		if ts > newest {
			newest = ts
		}
	}
	if newest == 0 {
		return -1
	}
	age := t.Unix() - newest
	if age < 0 {
		age = 0
	}
	return int(age)
}
