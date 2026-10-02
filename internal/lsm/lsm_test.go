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

func TestExpandSkipsForeignSymlink(t *testing.T) {
	home := t.TempDir()
	own := filepath.Join(home, ".ssh", "id_ok")
	if err := os.MkdirAll(filepath.Dir(own), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Symlink dell'utente verso un file di sistema: non deve diventare "segreto".
	if err := os.Symlink("/etc/hostname", filepath.Join(home, ".ssh", "id_evil")); err != nil {
		t.Fatal(err)
	}
	uid := int64(os.Getuid())
	if uid == 0 {
		// Da root /etc/hostname e' dello stesso uid: simula un utente diverso.
		uid = 4242
		if err := os.Chown(own, 4242, 4242); err != nil {
			t.Fatal(err)
		}
	}
	got := expand(home, ".ssh/id_*", uid)
	if len(got) != 1 || got[0] != own {
		t.Fatalf("expand = %v, atteso solo %s", got, own)
	}
	// Pattern assoluto (admin): nessun filtro proprietario.
	if got := expand(home, "/etc/hostname", uid); len(got) != 1 {
		t.Fatalf("pattern assoluto filtrato: %v", got)
	}
}
