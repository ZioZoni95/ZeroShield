// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package lsm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedExeSystemBinary(t *testing.T) {
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("niente /bin/sh")
	}
	if err := trustedExe(sh); err != nil {
		t.Fatalf("binario di sistema rifiutato: %v", err)
	}
}

func TestTrustedExeRejectsWritable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "aws")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Non root: la tempdir e' dell'utente, va rifiutata.
	// Root: la tempdir e' di root ma /tmp e' scrivibile da tutti, idem.
	if err := trustedExe(exe); err == nil {
		t.Fatal("binario in directory utente/temp accettato")
	}
	if os.Geteuid() == 0 {
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := trustedExe(exe); err == nil {
			t.Fatal("binario in directory world-writable accettato")
		}
	}
}
