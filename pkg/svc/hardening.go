// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package svc

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Hardening del sistema e kill-switch VPN dalla GUI. Le UI orchestrano, non reimplementano: qui si
// lanciano gli script del pacchetto (scripts/harden_system.sh, scripts/vpn_killswitch.sh), con argomenti
// validati e passati uno per uno (mai in una stringa di shell). Cio' che modifica il sistema passa da pkexec.

// execCombined: punto unico dove si lancia un comando (sostituibile nei test).
var execCombined = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // percorsi di script del pacchetto, argomenti validati
}

// HardenScript e KillSwitchScript: percorso degli script ("" se non trovati).
func HardenScript() string     { return findScript("harden_system.sh") }
func KillSwitchScript() string { return findScript("vpn_killswitch.sh") }

// HardenProfiles: profili accettati da harden_system.sh.
var HardenProfiles = []string{"home", "corporate", "public-wifi", "paranoid"}

func validProfile(p string) bool {
	for _, x := range HardenProfiles {
		if p == x {
			return true
		}
	}
	return false
}

const previewMax = 64 * 1024

// HardenPreview: `harden_system.sh <profilo> --dry-run`, senza privilegi. Non tocca il sistema: mostra il diff e i comandi
// che eseguirebbe. Va mostrato SEMPRE prima di applicare.
func HardenPreview(profile string) (string, error) {
	if !validProfile(profile) {
		return "", fmt.Errorf("profilo %q non valido (%s)", profile, strings.Join(HardenProfiles, ", "))
	}
	script := HardenScript()
	if script == "" {
		return "", fmt.Errorf("harden_system.sh non trovato: da sorgente lancia scripts/harden_system.sh %s --dry-run", profile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out, err := execCombined(ctx, "bash", script, profile, "--dry-run")
	text := string(out)
	if len(text) > previewMax {
		text = text[:previewMax] + "\n… (output troncato)"
	}
	if err != nil {
		return text, fmt.Errorf("l'anteprima non e' riuscita: %w", err)
	}
	return text, nil
}

// HardenApply applica davvero l'hardening (root, via pkexec: dialogo di sistema).
func HardenApply(profile string) error {
	if !validProfile(profile) {
		return fmt.Errorf("profilo %q non valido", profile)
	}
	script := HardenScript()
	if script == "" {
		return fmt.Errorf("harden_system.sh non trovato: da sorgente lancia sudo scripts/harden_system.sh %s", profile)
	}
	el, err := elevator()
	if err != nil {
		return fmt.Errorf("hardening manuale: sudo %s %s", script, profile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if out, err := execCombined(ctx, el, "bash", script, profile); err != nil {
		return fmt.Errorf("hardening fallito: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

var (
	ifNameRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	endpointV4 = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$`)
	endpointV6 = regexp.MustCompile(`^\[([0-9A-Fa-f:]+)\]:(\d{1,5})$`)
)

// ValidateKillSwitch controlla gli argomenti di `vpn_killswitch.sh on`: endpoint IPv4:porta o [IPv6]:porta (mai un nome
// host), interfaccia del tunnel e LAN in CIDR. Stesse regole dello script, qui con un messaggio chiaro.
func ValidateKillSwitch(endpoint, tunnel string, lans []string) error {
	var host, port string
	if m := endpointV4.FindStringSubmatch(endpoint); m != nil {
		host, port = m[1], m[2]
	} else if m := endpointV6.FindStringSubmatch(endpoint); m != nil {
		host, port = m[1], m[2]
	} else {
		return fmt.Errorf("endpoint %q non valido: serve IPv4:porta o [IPv6]:porta (mai un nome host: senza tunnel non c'e' DNS)", endpoint)
	}
	if ip := net.ParseIP(host); ip == nil {
		return fmt.Errorf("endpoint %q: indirizzo non valido", endpoint)
	}
	if p, _ := strconv.Atoi(port); p < 1 || p > 65535 {
		return fmt.Errorf("endpoint %q: porta fuori intervallo", endpoint)
	}
	if !ifNameRe.MatchString(tunnel) {
		return fmt.Errorf("interfaccia del tunnel %q non valida", tunnel)
	}
	for _, l := range lans {
		if _, _, err := net.ParseCIDR(l); err != nil {
			return fmt.Errorf("LAN %q non valida (serve un CIDR, per esempio 192.168.1.0/24)", l)
		}
	}
	return nil
}

func killSwitch(args ...string) error {
	script := KillSwitchScript()
	if script == "" {
		return fmt.Errorf("vpn_killswitch.sh non trovato: da sorgente lancia sudo scripts/vpn_killswitch.sh %s", strings.Join(args, " "))
	}
	el, err := elevator()
	if err != nil {
		return fmt.Errorf("kill-switch manuale: sudo %s %s", script, strings.Join(args, " "))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if out, err := execCombined(ctx, el, append([]string{"bash", script}, args...)...); err != nil {
		return fmt.Errorf("kill-switch: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// KillSwitchOn accende il kill-switch (root, pkexec). Se il tunnel cade, la rete si ferma: e' voluto.
func KillSwitchOn(endpoint, tunnel string, lans []string) error {
	if err := ValidateKillSwitch(endpoint, tunnel, lans); err != nil {
		return err
	}
	return killSwitch(append([]string{"on", endpoint, tunnel}, lans...)...)
}

// KillSwitchOff toglie la sola tabella `inet zt-killswitch` (root, pkexec).
func KillSwitchOff() error { return killSwitch("off") }
