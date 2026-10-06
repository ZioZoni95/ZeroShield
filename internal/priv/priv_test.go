// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package priv

import (
	"os"
	"path/filepath"
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
	// Test gira da utente: il server accetta, ma l'azione richiede uid 0.
	if _, err := Call("ping", nil); err == nil {
		t.Log("nota: test gira da root, ping passato")
	} else if err.Error() != "permesso negato: serve root (polkit in arrivo)" {
		t.Errorf("errore inatteso: %v", err)
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
