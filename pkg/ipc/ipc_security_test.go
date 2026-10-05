// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package ipc

import (
	"context"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

const esc = "\x1b]52;c;ZXZpbA==\x07"

// Ogni stringa che il demone pubblica deve uscire senza caratteri di controllo,
// anche nei campi aggiunti dopo (Listening, Vpn...). Il test enumera i campi: se ne
// aggiungi uno a Status e non passa da sanitize, qui lo vedi.
func TestStatusSanitizedEverywhere(t *testing.T) {
	withTempSocket(t)
	srv, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.UpdateStatus(Status{
		Profile: "home" + esc, Mode: "audit" + esc, Home: "/home/x" + esc,
		XDP: []string{"eth0" + esc}, BlockSubnets: []string{"10.0.0.0/8" + esc},
		Vpn:        VpnStatus{Enabled: true, Endpoint: "1.2.3.4:5" + esc, Tunnel: "wg0" + esc},
		TopSources: []SourceStat{{IP: "1.2.3.4" + esc}},
		Listening:  []ListenEntry{{Proto: "tcp" + esc, Addr: "0.0.0.0" + esc, Port: 22, Exe: "/tmp/" + esc + "x"}},
		Rules:      []RuleSummary{{Name: "r" + esc, Paths: []string{"p" + esc}, Allow: []string{"a" + esc}}},
	})
	conn, err := dialRaw()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 64*1024)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(buf[:n])
	// Nel JSON un ESC grezzo sarebbe \u001b: non deve comparire in nessuna forma.
	for _, bad := range []string{"\x1b", `\u001b`, "\x07", `\u0007`} {
		if strings.Contains(raw, bad) {
			t.Errorf("carattere di controllo %q arrivato alle UI: %s", bad, raw)
		}
	}
}

func TestEventsSanitized(t *testing.T) {
	withTempSocket(t)
	srv, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan WireEvent, 1)
	canary := make(chan CanaryAlert, 1)
	go func() { _ = Subscribe(ctx, func(ev WireEvent) { got <- ev }) }()
	go func() { _ = SubscribeCanary(ctx, func(a CanaryAlert) { canary <- a }) }()
	time.Sleep(200 * time.Millisecond)
	srv.Publish(WireEvent{Action: "blocked", Comm: "c" + esc, Exe: "/x" + esc, Rule: "r" + esc})
	srv.PublishCanary(CanaryAlert{Action: "alert", Exe: "/x" + esc, Path: "/p" + esc, Kind: "open", Reason: "m" + esc})
	select {
	case ev := <-got:
		if strings.ContainsAny(ev.Comm+ev.Exe+ev.Rule, "\x1b\x07") {
			t.Errorf("evento non sanificato: %+v", ev)
		}
	case <-ctx.Done():
		t.Fatal("evento non ricevuto")
	}
	select {
	case a := <-canary:
		if strings.ContainsAny(a.Exe+a.Path+a.Reason, "\x1b\x07") {
			t.Errorf("alert canary non sanificato: %+v", a)
		}
	case <-ctx.Done():
		t.Fatal("alert non ricevuto")
	}
}

// Il socket del demone e' di proprieta' dell'utente protetto, modo 0600: un altro
// utente locale non puo' collegarsi. Il test usa il proprio uid (chown a se' stessi
// e' sempre permesso, anche senza root).
func TestServerOwnedBy(t *testing.T) {
	withTempSocket(t)
	uid, gid := os.Getuid(), os.Getgid()
	srv, err := NewServerOwnedBy(uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	fi, err := os.Stat(SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("modo socket %o, atteso 0600 (altri utenti non devono collegarsi)", perm)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid {
		t.Errorf("proprietario socket diverso dall'utente protetto")
	}
	srv.UpdateStatus(Status{Profile: "home"})
	if _, err := GetStatus(); err != nil {
		t.Errorf("il proprietario non riesce a leggere il proprio socket: %v", err)
	}
}

func TestNewServerMockIsOpen(t *testing.T) {
	withTempSocket(t)
	srv, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	fi, _ := os.Stat(SocketPath)
	if fi.Mode().Perm() != 0o666 {
		t.Errorf("NewServer (mock/test) deve restare 0666, trovato %o", fi.Mode().Perm())
	}
}

// dialRaw apre una connessione grezza al socket: legge il JSON esattamente come
// esce dal demone, prima di ogni decodifica.
func dialRaw() (net.Conn, error) {
	return net.DialTimeout("unix", SocketPath, 2*time.Second)
}
