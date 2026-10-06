// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package priv

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

// ActionID polkit per le azioni del canale. La policy
// (packaging/org.zeroshield.manage.policy) chiede auth_admin: click in UI
// → dialogo di sistema → allow una tantum. Senza polkit/dbus: negato, mai
// fail-open.
const ActionID = "org.zeroshield.manage"

// authorize: uid 0 passa sempre; gli altri passano da polkit con subject
// unix-process (pid+start-time anti-reuse: un pid riciclato non eredita).
func authorize(uid uint32, pid uint32) error {
	if uid == 0 {
		return nil
	}
	ok, err := polkitCheck(pid)
	if err != nil {
		return fmt.Errorf("permesso negato: %v (serve root o auth polkit)", err)
	}
	if !ok {
		return fmt.Errorf("permesso negato dall'amministratore (polkit)")
	}
	return nil
}

func polkitCheck(pid uint32) (bool, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return false, fmt.Errorf("dbus di sistema non raggiungibile: %w", err)
	}
	defer conn.Close()
	start, err := procStartTime(pid)
	if err != nil {
		return false, fmt.Errorf("pid non verificabile: %w", err)
	}
	obj := conn.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
	var res struct {
		Authorized bool
		Challenge  bool
		Details    map[string]string
	}
	call := obj.Call("org.freedesktop.PolicyKit1.Authority.CheckAuthorization", 0,
		map[string]dbus.Variant{},
		map[string]dbus.Variant{
			"system-bus-name": dbus.MakeVariant(""),
		},
		// subject unix-process: dbus accetta anche via pid diretto qui sotto
		// usando la forma struct(kind, details).
		struct {
			Kind    string
			Details map[string]string
		}{Kind: "unix-process", Details: map[string]string{
			"pid":        strconv.FormatUint(uint64(pid), 10),
			"start-time": strconv.FormatUint(start, 10),
		}},
		ActionID, map[string]string{}, uint32(1), "")
	if call.Err != nil {
		return false, call.Err
	}
	if err := call.Store(&res); err != nil {
		return false, err
	}
	return res.Authorized, nil
}

// procStartTime legge il starttime (campo 22) da /proc/pid/stat: anti-reuse
// del pid tra check e uso. Fallisce se il processo e' gia' uscito.
func procStartTime(pid uint32) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// Il comm puo' contenere spazi e parentesi: prendi dopo l'ultima ')'.
	s := string(data)
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return 0, fmt.Errorf("stat illeggibile")
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return 0, fmt.Errorf("stat corto")
	}
	return strconv.ParseUint(f[19], 10, 64)
}
