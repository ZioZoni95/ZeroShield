// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package priv

import (
	"os"
	"testing"

	"github.com/godbus/dbus/v5"
)

// ZS-004: la chiamata a CheckAuthorization deve avere esattamente la firma D-Bus di polkit:
// (sa{sv}) s a{ss} u s.
func TestCheckAuthorizationSignature(t *testing.T) {
	args := checkAuthorizationArgs(1234, 99)
	want := []string{"(sa{sv})", "s", "a{ss}", "u", "s"}
	if len(args) != len(want) {
		t.Fatalf("%d argomenti, attesi %d", len(args), len(want))
	}
	for i, a := range args {
		if got := dbus.SignatureOf(a).String(); got != want[i] {
			t.Errorf("argomento %d: firma %q, attesa %q", i, got, want[i])
		}
	}
}

// Prova con polkit vero (se c'e' un bus di sistema): per il nostro stesso processo, senza
// interazione (flags=0), polkit deve rispondere senza errori di firma. Il risultato (autorizzato
// o no) dipende dalla policy installata: qui conta solo che la chiamata sia ben formata.
func TestCheckAuthorizationLivePolkit(t *testing.T) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		t.Skipf("nessun bus di sistema: %v", err)
	}
	defer conn.Close()
	pid := uint32(os.Getpid())
	start, err := procStartTime(pid)
	if err != nil {
		t.Skipf("start-time: %v", err)
	}
	args := checkAuthorizationArgs(pid, start)
	args[3] = uint32(0) // niente dialogo durante i test
	obj := conn.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
	var res struct {
		Authorized bool
		Challenge  bool
		Details    map[string]string
	}
	call := obj.Call("org.freedesktop.PolicyKit1.Authority.CheckAuthorization", 0, args...)
	if call.Err != nil {
		t.Skipf("polkit non raggiungibile: %v", call.Err)
	}
	if err := call.Store(&res); err != nil {
		t.Fatalf("risposta non decodificabile: %v", err)
	}
	t.Logf("polkit: authorized=%v challenge=%v", res.Authorized, res.Challenge)
}
