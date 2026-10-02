// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package canary

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCanaryKillInEnforce(t *testing.T) {
	d := NewDetector(50, 10, nil, []string{"/home/u/Documents/.canary-01"})
	if v := d.Record(4321, "/usr/bin/python3", "/home/u/Documents/.canary-01", KindWrite, true, time.Now()); v != VerdictKill {
		t.Errorf("tocco esca in enforce: atteso kill, avuto %d", v)
	}
}

func TestCanaryAuditOnlyLogs(t *testing.T) {
	d := NewDetector(50, 10, nil, []string{"/home/u/Documents/.canary-01"})
	if v := d.Record(4321, "/usr/bin/python3", "/home/u/Documents/.canary-01", KindWrite, false, time.Now()); v != VerdictAlert {
		t.Errorf("tocco esca in audit: atteso alert, avuto %d", v)
	}
}

func TestNeverPidOne(t *testing.T) {
	d := NewDetector(1, 10, nil, []string{"/x"})
	for _, pid := range []int{0, 1, -5} {
		if v := d.Record(pid, "init", "/x", KindWrite, true, time.Now()); v != VerdictIgnore {
			t.Errorf("pid %d: mai agire, avuto %d", pid, v)
		}
	}
}

func TestBurstThreshold(t *testing.T) {
	d := NewDetector(5, 10, nil, nil)
	now := time.Now()
	for i := 0; i < 4; i++ {
		if v := d.Record(777, "/usr/bin/evil", "/d/f", KindRename, true, now); v != VerdictIgnore {
			t.Fatalf("hit %d: sotto soglia, avuto %d", i, v)
		}
	}
	if v := d.Record(777, "/usr/bin/evil", "/d/f", KindRename, true, now); v != VerdictAlert {
		t.Errorf("5 rename in finestra: atteso alert, avuto %d", v)
	}
	// Cooldown: subito dopo, silenzio anche sopra soglia.
	if v := d.Record(777, "/usr/bin/evil", "/d/f", KindRename, true, now); v != VerdictIgnore {
		t.Errorf("in cooldown: atteso silenzio, avuto %d", v)
	}
}

func TestBurstWindowExpiry(t *testing.T) {
	d := NewDetector(3, 10, nil, nil)
	old := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		d.Record(888, "/bin/x", "/d/f", KindDelete, true, old)
	}
	if v := d.Record(888, "/bin/x", "/d/f", KindDelete, true, time.Now()); v != VerdictIgnore {
		t.Errorf("hit vecchi scaduti: atteso silenzio, avuto %d", v)
	}
}

func TestExcludeExe(t *testing.T) {
	d := NewDetector(2, 60, []string{"restic", "cc1"}, nil)
	now := time.Now()
	d.Record(999, "/usr/bin/restic", "/d/a", KindRename, true, now)
	if v := d.Record(999, "/usr/bin/restic", "/d/b", KindRename, true, now); v != VerdictIgnore {
		t.Errorf("exe escluso: atteso silenzio, avuto %d", v)
	}
}

func TestReadsDontCount(t *testing.T) {
	d := NewDetector(1, 60, nil, nil)
	if v := d.Record(111, "/bin/cat", "/d/f", KindOpen, true, time.Now()); v != VerdictIgnore {
		t.Errorf("open non conta per massa: avuto %d", v)
	}
}

func TestDeployIdempotent(t *testing.T) {
	home := t.TempDir()
	paths, err := DeployCanaries(home, []string{"Documents"}, []string{".canary-t"})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("atteso 1 path, avuti %d", len(paths))
	}
	marker := []byte("miofile")
	if err := os.WriteFile(paths[0], marker, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := DeployCanaries(home, []string{"Documents"}, []string{".canary-t"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(paths[0]); string(got) != string(marker) {
		t.Error("deploy ha sovrascritto un file esistente")
	}
	_ = filepath.Separator
}
