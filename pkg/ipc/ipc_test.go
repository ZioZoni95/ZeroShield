// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package ipc

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// withTempSocket sposta il socket in t.TempDir: niente /run, niente root.
func withTempSocket(t *testing.T) {
	t.Helper()
	old := SocketPath
	SocketPath = filepath.Join(t.TempDir(), "api.sock")
	t.Cleanup(func() { SocketPath = old })
}

func TestStatusRoundTrip(t *testing.T) {
	withTempSocket(t)
	srv, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.UpdateStatus(Status{Profile: "home", Mode: "audit", Protected: 3, Allowed: 5})

	st, err := GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if st.Profile != "home" || st.Mode != "audit" || st.Protected != 3 || st.Allowed != 5 {
		t.Errorf("status alterato: %+v", st)
	}
}

func TestEventStream(t *testing.T) {
	withTempSocket(t)
	srv, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.UpdateStatus(Status{Profile: "home", Mode: "enforce"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan WireEvent, 4)
	go func() {
		_ = Subscribe(ctx, func(ev WireEvent) { got <- ev })
	}()
	time.Sleep(200 * time.Millisecond) // lascia connettere il subscriber
	srv.Publish(WireEvent{Action: "blocked", PID: 99, Comm: "cat", Rule: "ssh-keys", Inode: 7})
	srv.Publish(WireEvent{Action: "audit", PID: 100, Comm: "ls", Rule: "ssh-keys", Inode: 8})

	for _, want := range []string{"blocked", "audit"} {
		select {
		case ev := <-got:
			if ev.Action != want {
				t.Errorf("evento %q, atteso %q", ev.Action, want)
			}
		case <-ctx.Done():
			t.Fatalf("timeout aspettando evento %q", want)
		}
	}
}

func TestGetStatusNoDaemon(t *testing.T) {
	withTempSocket(t) // nessun server: deve fallire in fretta, non hangare
	if _, err := GetStatus(); err == nil {
		t.Error("atteso errore senza demone")
	}
}

func TestCanaryStream(t *testing.T) {
	withTempSocket(t)
	srv, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.UpdateStatus(Status{Profile: "home", Mode: "enforce"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan CanaryAlert, 2)
	evs := make(chan WireEvent, 2)
	go func() {
		_ = SubscribeCanary(ctx, func(a CanaryAlert) { got <- a })
	}()
	go func() {
		_ = Subscribe(ctx, func(ev WireEvent) { evs <- ev })
	}()
	time.Sleep(200 * time.Millisecond)
	srv.PublishCanary(CanaryAlert{Action: "killed", PID: 666, Kind: "write", Reason: "tocco esca"})

	select {
	case a := <-got:
		if a.PID != 666 || a.Action != "killed" {
			t.Errorf("alert alterato: %+v", a)
		}
	case <-ctx.Done():
		t.Fatal("timeout alert canary")
	}
	// Il canary non deve inquinare lo stream eventi normale.
	select {
	case ev := <-evs:
		t.Errorf("evento spurio sullo stream wire: %+v", ev)
	case <-time.After(300 * time.Millisecond):
	}
}

// Chi si collega dopo rilegge gli ultimi eventi (marcati replay): la GUI aperta dopo una notifica
// li trova in Eventi. Quelli successivi arrivano in diretta, senza replay e senza doppioni.
func TestEventHistoryOnConnect(t *testing.T) {
	withTempSocket(t)
	srv, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.UpdateStatus(Status{Profile: "home", Mode: "enforce"})
	srv.Publish(WireEvent{Action: "blocked", PID: 1, Comm: "seahorse", Exe: "/usr/bin/seahorse", Rule: "ssh-keys"})
	srv.Publish(WireEvent{Action: "audit", PID: 2, Comm: "x", Rule: "ssh-keys"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := make(chan WireEvent, 8)
	go Subscribe(ctx, func(ev WireEvent) { got <- ev })
	var first, second WireEvent
	select {
	case first = <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("nessun evento riletto dallo storico")
	}
	second = <-got
	if !first.Replay || !second.Replay || first.PID != 1 || second.PID != 2 {
		t.Errorf("storico errato: %+v %+v", first, second)
	}
	time.Sleep(100 * time.Millisecond)
	srv.Publish(WireEvent{Action: "blocked", PID: 3, Comm: "nuovo"})
	live := <-got
	if live.Replay || live.PID != 3 {
		t.Errorf("l'evento in diretta non deve essere replay: %+v", live)
	}
	select {
	case extra := <-got:
		t.Errorf("evento doppio: %+v", extra)
	case <-time.After(200 * time.Millisecond):
	}
}

// Lo storico e' limitato: oltre histMax si butta il piu' vecchio.
func TestEventHistoryIsBounded(t *testing.T) {
	withTempSocket(t)
	srv, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	for i := 0; i < histMax+50; i++ {
		srv.Publish(WireEvent{Action: "audit", PID: uint32(i), Comm: "x"})
	}
	srv.mu.Lock()
	n := len(srv.hist)
	srv.mu.Unlock()
	if n != histMax {
		t.Errorf("storico = %d, atteso %d", n, histMax)
	}
}
