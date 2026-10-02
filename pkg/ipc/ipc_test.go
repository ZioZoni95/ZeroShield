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
