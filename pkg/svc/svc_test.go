// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package svc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateNeverEmpty(t *testing.T) {
	// Qualunque ambiente (con/senza systemd): stringa non vuota, mai panic.
	if s := State(); s == "" {
		t.Error("stato vuoto")
	}
}

func TestSetModeRejectsGarbage(t *testing.T) {
	// Validazione prima di qualunque shell: injection impossibile anche
	// se il chiamante passa input utente.
	for _, m := range []string{"", "ENFORCE", "audit; rm -rf /", "enforce\nmode: audit"} {
		if err := SetMode(m); err == nil {
			t.Errorf("mode %q accettato", m)
		}
	}
}

func TestCurrentUserNoRoot(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	t.Setenv("USER", "mario")
	t.Setenv("LOGNAME", "mario")
	if u := CurrentUser(); u != "mario" {
		t.Errorf("atteso mario, avuto %q", u)
	}
	_ = filepath.Separator
	_ = os.Getenv("PATH")
}

func TestParseUser(t *testing.T) {
	cases := map[string]string{
		"profile: home\nuser: mario\n":             "mario",
		"user: \"mario\"\n":                        "mario",
		"user: 'mario'  # il mio utente\n":         "mario",
		"user: \"\"\n":                             "",
		"# user: mario\nprofile: home\n":           "", // commentata: non conta
		"profile: home\n":                          "",
		"  user: luisa\n":                          "luisa",
		"user:\n":                                  "",
		"username: x\nprofile: home\nuser: sara\n": "sara",
	}
	for in, want := range cases {
		if got := ParseUser(in); got != want {
			t.Errorf("ParseUser(%q) = %q, atteso %q", in, got, want)
		}
	}
}

func TestPickInstaller(t *testing.T) {
	// Con la unit del pacchetto si usa SOLO configure_service.sh, mai install_service.sh:
	// quest'ultimo sovrascriverebbe binario e unit del pacchetto con una seconda copia.
	if got := pickInstaller(true, "/usr/share/zeroshield/scripts/configure_service.sh", "/repo/scripts/install_service.sh"); got != "/usr/share/zeroshield/scripts/configure_service.sh" {
		t.Errorf("con unit del pacchetto atteso configure_service.sh, avuto %q", got)
	}
	if got := pickInstaller(true, "", "/repo/scripts/install_service.sh"); got != "" {
		t.Errorf("con unit del pacchetto e senza configure_service.sh non si ripiega su install_service.sh, avuto %q", got)
	}
	if got := pickInstaller(false, "/x/configure_service.sh", "/repo/scripts/install_service.sh"); got != "/repo/scripts/install_service.sh" {
		t.Errorf("da sorgente atteso install_service.sh, avuto %q", got)
	}
}

func TestInstallRejectsEmptyUser(t *testing.T) {
	if err := Install("", "home"); err == nil {
		t.Error("utente vuoto accettato")
	}
}

func TestPreflightChecks(t *testing.T) {
	var names []string
	for _, c := range Preflight() {
		names = append(names, c.Name)
		if c.Name == "Script install_service.sh" {
			t.Error("il vecchio controllo su install_service.sh non deve tornare: il .deb non lo contiene")
		}
	}
	joined := strings.Join(names, "|")
	for _, want := range []string{"Servizio zt-shield", "Utente protetto"} {
		if !strings.Contains(joined, want) {
			t.Errorf("manca il controllo %q in %v", want, names)
		}
	}
}
