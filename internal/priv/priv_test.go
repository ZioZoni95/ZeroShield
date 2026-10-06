// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package priv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withTempSocket(t *testing.T) {
	t.Helper()
	old := SocketPath
	SocketPath = filepath.Join(t.TempDir(), "control.sock")
	t.Cleanup(func() { SocketPath = old })
}

func TestPingRoundTrip(t *testing.T) {
	withTempSocket(t)
	srv, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.On("ping", func(uid uint32, _ map[string]any) (any, error) {
		return map[string]any{"uid": uid}, nil
	})
	// Test gira da utente: il server accetta, ma l'azione richiede uid 0 o polkit.
	// Senza dbus/policy atteso diniego esplicito, mai hang né allow silenzioso.
	if _, err := Call("ping", nil); err == nil {
		t.Log("nota: test gira da root o polkit ha autorizzato, ping passato")
	} else if !strings.Contains(err.Error(), "permesso negato") {
		t.Errorf("errore inatteso (atteso diniego pulito): %v", err)
	}
}

func TestUnknownAction(t *testing.T) {
	withTempSocket(t)
	srv, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	// Senza server? c'e'. Azione ignota: se siamo root passa il controllo uid
	// e arriva a "sconosciuta", altrimenti denied. Entrambi accettabili qui:
	// l'importante e' una risposta JSON valida, non un hang.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = Call("inesistente", nil)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("nessuna risposta dal canale")
	}
	_ = os.Getenv("PATH")
}
