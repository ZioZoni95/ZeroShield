// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"zt-shield/internal/config"
)

const unitName = "zt-shield.service"

// canaryDropinPath: drop-in che apre in scrittura le cartelle delle esche (la unit ha ProtectHome=read-only).
const canaryDropinPath = "/etc/systemd/system/zt-shield.service.d/canary.conf"

// dropinMarker: prima riga di un drop-in generato da noi; un file diverso (scritto a mano) non si tocca mai.
const dropinMarker = "# Generato da `zt-shield dropin`"

// syncCanaryDropin allinea il drop-in al config installato: con il canary acceso apre le cartelle delle esche
// in scrittura (altrimenti il watcher non parte: «sotto systemd la home e' in sola lettura»), spento lo toglie.
// Senza questo passo i pulsanti della GUI accenderebbero un canary che non parte. Ritorna se qualcosa e' cambiato.
func syncCanaryDropin(cfgPath, dropinPath string) (bool, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return false, err
	}
	acct, err := cfg.Account()
	if err != nil {
		return false, err
	}
	want := cfg.SystemdDropin(acct.HomeDir)
	cur, rerr := os.ReadFile(dropinPath)
	if rerr == nil && !strings.HasPrefix(string(cur), dropinMarker) {
		return false, nil // scritto a mano da qualcuno: non si tocca
	}
	if want == string(cur) {
		return false, nil
	}
	if want == "" {
		if err := os.Remove(dropinPath); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		return rerr == nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(dropinPath), 0o755); err != nil { //nolint:gosec // directory di systemd, leggibile da tutti
		return false, err
	}
	return true, os.WriteFile(dropinPath, []byte(want), 0o644) //nolint:gosec // come un file di unit: leggibile da tutti
}

// reloadCanaryDropin: sync + daemon-reload se serve. Un errore non e' fatale (si scrive un avviso): il resto del config e' gia' installato.
func reloadCanaryDropin() {
	changed, err := syncCanaryDropin(config.DefaultPath, canaryDropinPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config-apply: drop-in del canary non aggiornato:", err)
		return
	}
	if changed {
		_ = exec.Command("systemctl", "daemon-reload").Run()
		fmt.Println("drop-in del canary aggiornato")
	}
}

// runConfigApply: `zt-shield config-apply [-no-restart] FILE` (root).
//
// Lo usa la GUI (via pkexec) per applicare le regole scelte dall'utente: valida FILE con il
// parser del demone, tiene una copia di sicurezza del config, lo sostituisce in modo atomico
// e riavvia il servizio. Se il servizio girava e dopo il riavvio non e' piu' attivo, ripristina
// il config precedente e riavvia di nuovo: una scelta sbagliata non deve lasciare il PC senza
// protezione. Ritorna il codice di uscita del processo.
func runConfigApply(args []string) int {
	noRestart := false
	var src string
	for _, a := range args {
		switch {
		case a == "-no-restart" || a == "--no-restart":
			noRestart = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintln(os.Stderr, "uso: zt-shield config-apply [-no-restart] FILE")
			return 2
		case src == "":
			src = a
		default:
			fmt.Fprintln(os.Stderr, "uso: zt-shield config-apply [-no-restart] FILE")
			return 2
		}
	}
	if src == "" {
		fmt.Fprintln(os.Stderr, "uso: zt-shield config-apply [-no-restart] FILE")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "config-apply: serve root (usa sudo o la GUI)")
		return 1
	}
	wasActive := exec.Command("systemctl", "is-active", "--quiet", unitName).Run() == nil
	backup, err := config.Install(src, config.DefaultPath, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "config-apply:", err)
		return 1
	}
	fmt.Println("config aggiornato:", config.DefaultPath)
	if backup != "" {
		fmt.Println("copia di sicurezza:", backup)
	}
	reloadCanaryDropin()
	if noRestart {
		return 0
	}
	if out, err := exec.Command("systemctl", "restart", unitName).CombinedOutput(); err != nil {
		return rollback(backup, wasActive, "il servizio non riparte: "+strings.TrimSpace(string(out)))
	}
	// restart ritorna quando l'unit e' avviata; si ricontrolla dopo un attimo perche' un
	// demone che muore subito (hook non agganciato, config rifiutato) risulta attivo per poco.
	time.Sleep(3 * time.Second)
	if exec.Command("systemctl", "is-active", "--quiet", unitName).Run() != nil {
		return rollback(backup, wasActive, "il servizio si è fermato subito dopo l'avvio")
	}
	fmt.Println("servizio riavviato e attivo")
	return 0
}

func rollback(backup string, wasActive bool, why string) int {
	fmt.Fprintln(os.Stderr, "config-apply:", why)
	if backup == "" || !wasActive {
		fmt.Fprintf(os.Stderr, "controlla: journalctl -u %s -n 30\n", unitName)
		return 1
	}
	old, err := os.ReadFile(backup)
	if err == nil {
		err = os.WriteFile(config.DefaultPath, old, 0o644) //nolint:gosec // config di sistema, leggibile da tutti come l'originale
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ripristino fallito:", err, "— copia di sicurezza in", backup)
		return 1
	}
	reloadCanaryDropin() // il drop-in segue il config ripristinato
	_ = exec.Command("systemctl", "restart", unitName).Run()
	fmt.Fprintln(os.Stderr, "ripristinato il config precedente e riavviato il servizio. Dettagli: journalctl -u", unitName, "-n 30")
	return 1
}
