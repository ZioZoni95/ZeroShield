// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package canary

import (
	"os"
	"path/filepath"
	"syscall"
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
	paths, err := DeployCanaries(home, []string{"Documents"}, []string{".canary-t"}, nil)
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
	if _, err := DeployCanaries(home, []string{"Documents"}, []string{".canary-t"}, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(paths[0]); string(got) != string(marker) {
		t.Error("deploy ha sovrascritto un file esistente")
	}
	_ = filepath.Separator
}

func TestAllowExeIgnoresOnlyExactPath(t *testing.T) {
	bait := "/home/u/Documents/.canary-01"
	d := NewDetector(50, 10, nil, []string{bait})
	d.SetAllowExe([]string{"/usr/bin/tracker-miner-fs-3"})
	now := time.Now()
	if v := d.Record(500, "/usr/bin/tracker-miner-fs-3", bait, KindOpen, true, now); v != VerdictIgnore {
		t.Errorf("exe in allow_exe: atteso Ignore, avuto %d", v)
	}
	// Stesso nome in un percorso diverso (o con suffisso) NON e' esente.
	for _, exe := range []string{"/tmp/tracker-miner-fs-3", "/usr/bin/tracker-miner-fs-3 (deleted)", "/usr/bin/tracker-miner-fs-3x", ""} {
		if v := d.Record(501, exe, bait, KindOpen, true, now); v != VerdictKill {
			t.Errorf("exe %q: atteso Kill, avuto %d", exe, v)
		}
	}
}

func TestExcludeExeDoesNotShieldBait(t *testing.T) {
	bait := "/h/Documents/.canary-01"
	d := NewDetector(50, 10, []string{"rsync"}, []string{bait})
	if v := d.Record(600, "/usr/bin/rsync", bait, KindOpen, true, time.Now()); v != VerdictKill {
		t.Errorf("exclude_exe vale solo per la massa: atteso Kill, avuto %d", v)
	}
}

func TestDeployOwnsCreatedDirsOnly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown richiede root")
	}
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, "pre"), 0o755); err != nil {
		t.Fatal(err)
	}
	o := &Owner{UID: 4242, GID: 4343}
	paths, err := DeployCanaries(home, []string{"pre/new/deep"}, []string{".c"}, o)
	if err != nil {
		t.Fatal(err)
	}
	owner := func(p string) (int, int) {
		st := mustStat(t, p)
		return int(st.Uid), int(st.Gid)
	}
	for _, p := range []string{filepath.Join(home, "pre/new"), filepath.Join(home, "pre/new/deep"), paths[0]} {
		if u, g := owner(p); u != 4242 || g != 4343 {
			t.Errorf("%s: proprietario %d:%d, atteso 4242:4343", p, u, g)
		}
	}
	if u, _ := owner(filepath.Join(home, "pre")); u == 4242 {
		t.Error("una directory preesistente non va riassegnata")
	}
}

func TestDeployDoesNotFollowSymlinkBait(t *testing.T) {
	home := t.TempDir()
	docs := filepath.Join(home, "Documents")
	if err := os.Mkdir(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(home, "victim")
	if err := os.WriteFile(victim, []byte("intatto"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(docs, ".c")); err != nil {
		t.Fatal(err)
	}
	if _, err := DeployCanaries(home, []string{"Documents"}, []string{".c"}, nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "intatto" {
		t.Error("il deploy ha scritto attraverso un symlink")
	}
}

func TestTrustedExe(t *testing.T) {
	dir := t.TempDir() // di proprieta' dell'utente di test, non e' "root fidato" per un non-root
	f := filepath.Join(dir, "bin")
	if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	ok, rej := TrustedExe([]string{"relativo", "/non/esiste", f})
	if len(rej) < 2 {
		t.Errorf("attesi almeno 2 scartati, avuti %v", rej)
	}
	if os.Geteuid() != 0 && len(ok) != 0 {
		t.Errorf("file di un utente non root non e' fidato: %v", ok)
	}
	if _, bad := rej["relativo"]; !bad {
		t.Error("percorso relativo va scartato")
	}
}

func mustStat(t *testing.T, p string) *syscall.Stat_t {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t)
}
