// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"strings"
	"testing"
)

// L'icona apre la GUI come processo figlio: ogni restrizione dell'unit passa alla GUI. NoNewPrivileges
// rompe pkexec (Applica, Installa, cambio modalita' non chiedono piu' la password); ProtectSystem e
// simili impediscono di raggiungere /run/zt-shield (l'icona direbbe sempre «demone spento»).
func TestTrayUnitHasNoSandboxDirectives(t *testing.T) {
	b, err := os.ReadFile("../../packaging/zeroshield-tray.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		for _, bad := range []string{"NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices", "RestrictSUIDSGID", "CapabilityBoundingSet"} {
			if strings.HasPrefix(line, bad+"=") {
				t.Errorf("l'unit dell'icona non deve avere %s: la GUI figlia la erediterebbe (vedi il commento nell'unit)", bad)
			}
		}
	}
}
