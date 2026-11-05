// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"errors"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"zt-shield/pkg/ipc"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		st   ipc.Status
		err  error
		want state
	}{
		{"errore socket", ipc.Status{}, errors.New("x"), stDown},
		{"audit", ipc.Status{Mode: "audit", HookLSM: true}, nil, stAudit},
		{"enforce senza hook", ipc.Status{Mode: "enforce"}, nil, stDegraded},
		{"enforce ok", ipc.Status{Mode: "enforce", HookLSM: true}, nil, stOK},
	}
	for _, c := range cases {
		if got := classify(c.st, c.err); got != c.want {
			t.Errorf("%s: %v, atteso %v", c.name, got, c.want)
		}
	}
}

func TestIconDecodesAndDiffersPerState(t *testing.T) {
	seen := map[string]state{}
	for _, s := range []state{stDown, stAudit, stOK} {
		b := iconPNG(s)
		img, err := png.Decode(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("stato %v: PNG non valido: %v", s, err)
		}
		if img.Bounds().Dx() != 64 {
			t.Errorf("dimensione inattesa %v", img.Bounds())
		}
		if _, dup := seen[string(b)]; dup {
			t.Errorf("stato %v ha la stessa icona di un altro", s)
		}
		seen[string(b)] = s
	}
	// Fuori dallo scudo il pixel resta trasparente (angolo).
	img, _ := png.Decode(bytes.NewReader(iconPNG(stOK)))
	if _, _, _, a := img.At(0, 0).RGBA(); a != 0 {
		t.Error("l'angolo dovrebbe essere trasparente")
	}
}

func TestGuiRunning(t *testing.T) {
	root := t.TempDir()
	mk := func(pid, comm string) {
		d := filepath.Join(root, pid)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("100", "bash")
	mk("self", "zt-gui") // non numerico: ignorato
	if guiRunning(root) {
		t.Fatal("nessuna GUI presente, atteso false")
	}
	mk("200", "zt-gui")
	if !guiRunning(root) {
		t.Fatal("GUI presente, atteso true")
	}
	if guiRunning(filepath.Join(root, "nope")) {
		t.Fatal("directory mancante deve dare false")
	}
}
