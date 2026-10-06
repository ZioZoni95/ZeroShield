// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package svc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateNeverEmpty(t *testing.T) {
	// Qualunque ambiente (con/senza systemd): stringa non vuota, mai panic.
	if s := State(); s == "" {
		t.Error("stato vuoto")
	}
}

func TestSetModeRejectsGarbage(t *testing.T) {
	// Validazione prima di qualunque shell: injection impossibile anche
	// se il chiamante passa input utente.
	for _, m := range []string{"", "ENFORCE", "audit; rm -rf /", "enforce\nmode: audit"} {
		if err := SetMode(m); err == nil {
			t.Errorf("mode %q accettato", m)
		}
	}
}

func TestCurrentUserNoRoot(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	t.Setenv("USER", "mario")
	t.Setenv("LOGNAME", "mario")
	if u := CurrentUser(); u != "mario" {
		t.Errorf("atteso mario, avuto %q", u)
	}
	_ = filepath.Separator
	_ = os.Getenv("PATH")
}
