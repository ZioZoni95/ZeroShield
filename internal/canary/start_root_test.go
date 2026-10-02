// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package canary

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestStartRoot: collaudo reale di fanotify (serve root / CAP_SYS_ADMIN, in CI
// e da utente si salta). In audit: aprire un'esca deve dare un alert canary,
// cancellare file in massa un alert di massa. Prima del fix FAN_REPORT_FID
// Start falliva con EINVAL sul mark delle directory.
func TestStartRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("serve root per fanotify")
	}
	home := t.TempDir()
	hits := make(chan Hit, 16)
	w, err := Start(home, []string{"Documents"}, []string{".canary-test.dat"}, nil, 50, 10, false, func(h Hit) { hits <- h })
	if err != nil {
		t.Fatalf("canary non parte: %v", err)
	}
	defer w.Close()
	docs := filepath.Join(home, "Documents")

	// 1. Tocco esca.
	f, err := os.Open(filepath.Join(docs, ".canary-test.dat"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if h := waitHit(t, hits, func(h Hit) bool { return h.Canary }); h.Verdict != VerdictAlert {
		t.Fatalf("tocco esca in audit: verdetto %v, atteso alert", h.Verdict)
	}

	// 2. Massa: 60 file creati e cancellati (soglia 50 in 10s).
	for i := 0; i < 60; i++ {
		p := filepath.Join(docs, fmt.Sprintf("doc%d.txt", i))
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	waitHit(t, hits, func(h Hit) bool { return !h.Canary && h.Verdict == VerdictAlert })
}

func waitHit(t *testing.T, hits <-chan Hit, match func(Hit) bool) Hit {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case h := <-hits:
			if match(h) {
				return h
			}
		case <-deadline:
			t.Fatal("nessun evento fanotify atteso entro 3s")
		}
	}
}

// TestEnforceKillRoot: in enforce un processo che apre un'esca va ucciso.
// Il figlio apre l'esca e poi dorme: se il kill funziona esce per SIGKILL.
func TestEnforceKillRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("serve root per fanotify")
	}
	home := t.TempDir()
	hits := make(chan Hit, 16)
	w, err := Start(home, []string{"Documents"}, []string{".canary-kill.dat"}, nil, 50, 10, true, func(h Hit) { hits <- h })
	if err != nil {
		t.Fatalf("canary non parte: %v", err)
	}
	defer w.Close()
	bait := filepath.Join(home, "Documents", ".canary-kill.dat")
	cmd := exec.Command("sh", "-c", `exec 3<"$1"; sleep 10`, "sh", bait)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := waitHit(t, hits, func(h Hit) bool { return h.Canary && h.Verdict == VerdictKill })
	if !h.Killed {
		t.Fatalf("kill fallito: %v", h.KillErr)
	}
	err = cmd.Wait()
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("il figlio doveva morire per SIGKILL, invece: %v", err)
	}
}
