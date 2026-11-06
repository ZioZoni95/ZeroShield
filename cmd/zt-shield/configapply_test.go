// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func writeCfg(t *testing.T, dir, body string) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	p := filepath.Join(dir, "shield.yaml")
	if err := os.WriteFile(p, []byte("profile: home\nuser: "+u.Username+"\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Con il canary acceso il drop-in apre le cartelle delle esche; spento lo toglie; un file scritto a mano non si tocca.
func TestSyncCanaryDropin(t *testing.T) {
	dir := t.TempDir()
	home := dir // le cartelle del canary stanno sotto la home dell'utente di prova
	t.Setenv("HOME", home)
	u, _ := user.Current()
	if err := os.MkdirAll(filepath.Join(u.HomeDir, "Documents"), 0o755); err != nil {
		t.Skip("home non scrivibile: ", err)
	}
	drop := filepath.Join(dir, "d", "canary.conf")

	on := writeCfg(t, dir, "canary:\n  enabled: true\n  dirs: [Documents]\n")
	changed, err := syncCanaryDropin(on, drop)
	if err != nil || !changed {
		t.Fatalf("acceso: changed=%v err=%v", changed, err)
	}
	b, _ := os.ReadFile(drop)
	if !strings.HasPrefix(string(b), dropinMarker) || !strings.Contains(string(b), "ReadWritePaths=") {
		t.Errorf("drop-in inatteso: %q", b)
	}
	if changed, _ := syncCanaryDropin(on, drop); changed {
		t.Error("seconda applicazione identica: non deve cambiare nulla")
	}

	off := writeCfg(t, dir, "")
	changed, err = syncCanaryDropin(off, drop)
	if err != nil || !changed {
		t.Fatalf("spento: changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(drop); !os.IsNotExist(err) {
		t.Error("il drop-in doveva sparire con il canary spento")
	}

	hand := "[Service]\nReadWritePaths=/srv\n"
	if err := os.MkdirAll(filepath.Dir(drop), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(drop, []byte(hand), 0o644)
	if changed, _ := syncCanaryDropin(on, drop); changed {
		t.Error("un drop-in scritto a mano non si deve toccare")
	}
	if b, _ := os.ReadFile(drop); string(b) != hand {
		t.Errorf("drop-in manuale alterato: %q", b)
	}
}
