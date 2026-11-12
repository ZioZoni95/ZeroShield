// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package posture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeProc(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, v := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func byID(items []Item, id string) Item {
	for _, it := range items {
		if it.ID == id {
			return it
		}
	}
	return Item{}
}

func TestPtraceLevels(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		ok    bool
		fix   bool
	}{
		{"scope 0 e' aperto", map[string]string{"kernel/yama/ptrace_scope": "0\n"}, false, true},
		{"scope 1 va bene", map[string]string{"kernel/yama/ptrace_scope": "1\n"}, true, false},
		{"scope 3 va bene", map[string]string{"kernel/yama/ptrace_scope": "3\n"}, true, false},
		{"senza Yama", map[string]string{}, false, true},
		{"contenuto illeggibile", map[string]string{"kernel/yama/ptrace_scope": "boh"}, false, true},
	}
	for _, c := range cases {
		it := byID(Check(fakeProc(t, c.files)), "ptrace")
		if it.OK != c.ok || (it.Fix != "") != c.fix {
			t.Errorf("%s: ok=%v fix=%q", c.name, it.OK, it.Fix)
		}
		if it.Detail == "" {
			t.Errorf("%s: dettaglio vuoto", c.name)
		}
	}
}

func TestIoUringLevels(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		ok    bool
		fix   bool
	}{
		{"attivo", map[string]string{"kernel/io_uring_disabled": "0"}, false, true},
		{"solo privilegiati", map[string]string{"kernel/io_uring_disabled": "1"}, true, false},
		{"spento", map[string]string{"kernel/io_uring_disabled": "2"}, true, false},
		{"kernel vecchio: non si puo' spegnere", map[string]string{}, false, false},
	}
	for _, c := range cases {
		it := byID(Check(fakeProc(t, c.files)), "io_uring")
		if it.OK != c.ok || (it.Fix != "") != c.fix {
			t.Errorf("%s: ok=%v fix=%q", c.name, it.OK, it.Fix)
		}
	}
}

func TestFixIsAPersistentSysctl(t *testing.T) {
	for _, it := range Check(fakeProc(t, map[string]string{"kernel/yama/ptrace_scope": "0", "kernel/io_uring_disabled": "0"})) {
		if !strings.Contains(it.Fix, "/etc/sysctl.d/") || !strings.Contains(it.Fix, "sudo sysctl --system") {
			t.Errorf("%s: il rimedio deve restare dopo il riavvio: %q", it.ID, it.Fix)
		}
	}
}

func TestRealProcDoesNotPanic(t *testing.T) {
	if got := Check(ProcSys); len(got) != 2 {
		t.Fatalf("attesi 2 controlli, trovati %d", len(got))
	}
}
