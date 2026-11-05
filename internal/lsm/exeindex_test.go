// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package lsm

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestExeIndexResolvesByIdentity(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(bin, "mytool")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	notExe := filepath.Join(bin, "dati.txt")
	if err := os.WriteFile(notExe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// symlink: il percorso restituito e' quello reale
	if err := os.Symlink(exe, filepath.Join(bin, "alias")); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(exe, &st); err != nil {
		t.Fatal(err)
	}
	dev := unix.Major(uint64(st.Dev))<<20 | unix.Minor(uint64(st.Dev))
	x := NewExeIndex(home)
	got, ok := x.Resolve(uint64(dev), st.Ino, "")
	want, _ := filepath.EvalSymlinks(exe)
	if !ok || got != want {
		t.Fatalf("identita' -> %q %v, atteso %q", got, ok, want)
	}
	var st2 syscall.Stat_t
	_ = syscall.Stat(notExe, &st2)
	if p, ok := x.Resolve(uint64(dev), st2.Ino, ""); ok {
		t.Errorf("un file non eseguibile non va indicizzato: %q", p)
	}
	if p, ok := x.Resolve(uint64(dev), 1, ""); ok {
		t.Errorf("inode sconosciuto: %q", p)
	}
	// Un binario creato DOPO la prima costruzione si trova alla ricerca successiva (dopo l'intervallo minimo).
	late := filepath.Join(bin, "nuovo")
	_ = os.WriteFile(late, []byte("#!/bin/sh\n"), 0o755)
	var st3 syscall.Stat_t
	_ = syscall.Stat(late, &st3)
	if _, ok := x.Resolve(uint64(dev), st3.Ino, ""); ok {
		t.Error("troppo presto per ricostruire (limite di 10 s): non doveva trovarlo")
	}
	x.built = x.built.Add(-time.Minute)
	if p, ok := x.Resolve(uint64(dev), st3.Ino, ""); !ok || filepath.Base(p) != "nuovo" {
		t.Errorf("dopo l'intervallo va ricostruito: %q %v", p, ok)
	}
}

func TestExeIndexFindsSystemBinary(t *testing.T) {
	var st syscall.Stat_t
	if err := syscall.Stat("/bin/sh", &st); err != nil {
		t.Skip("niente /bin/sh")
	}
	dev := unix.Major(uint64(st.Dev))<<20 | unix.Minor(uint64(st.Dev))
	p, ok := NewExeIndex(t.TempDir()).Resolve(uint64(dev), st.Ino, "")
	if !ok || p == "" {
		t.Fatalf("/bin/sh non trovato nell'indice")
	}
}

// Un binario multi-call (coreutils in Rust): tanti nomi, un solo file. Deve vincere il nome con cui e' stato lanciato.
func TestExeIndexPrefersTheNameItWasRunWith(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	multi := filepath.Join(bin, "coreutils")
	if err := os.WriteFile(multi, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"[", "cat", "ln", "zzz"} {
		if err := os.Link(multi, filepath.Join(bin, n)); err != nil {
			t.Fatal(err)
		}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(multi, &st); err != nil {
		t.Fatal(err)
	}
	dev := unix.Major(uint64(st.Dev))<<20 | unix.Minor(uint64(st.Dev))
	x := NewExeIndex(home)
	for _, want := range []string{"cat", "ln", "zzz"} {
		if got, ok := x.Resolve(uint64(dev), st.Ino, want); !ok || filepath.Base(got) != want {
			t.Errorf("comm=%s -> %q", want, got)
		}
	}
	// Nome sconosciuto o vuoto: il primo in ordine alfabetico, mai un errore.
	if got, ok := x.Resolve(uint64(dev), st.Ino, "altro"); !ok || filepath.Base(got) != "[" {
		t.Errorf("senza corrispondenza: %q", got)
	}
	// comm e' troncato a 15 caratteri dal kernel
	long := filepath.Join(bin, "nome-molto-lungo-xx")
	_ = os.Link(multi, long)
	x = NewExeIndex(home) // indice nuovo: quello vecchio ha gia' il file in cache e non rilegge su un successo
	if got, ok := x.Resolve(uint64(dev), st.Ino, "nome-molto-lung"); !ok || filepath.Base(got) != "nome-molto-lungo-xx" {
		t.Errorf("comm troncato: %q", got)
	}
}
