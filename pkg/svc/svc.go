// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package svc: avvio/stop/stato del servizio systemd, condiviso da TUI/GUI/CLI.
//
// Le UI girano da utente: per i comandi privilegiati si usa pkexec (dialogo
// grafico di sistema) o sudo in terminale. Niente password maneggiate dal codice,
// niente demone avviato di nascosto: ogni azione e' esplicita e loggata.
// Senza systemd/pkfunc: errore che dice il comando manuale equivalente.
package svc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Unit del demone installata da scripts/install_service.sh.
const Unit = "zt-shield.service"

// State: active, inactive, missing (unit non installata), unknown.
func State() string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "unknown"
	}
	out, err := exec.Command("systemctl", "is-active", Unit).Output()
	if err != nil {
		s := strings.TrimSpace(string(out))
		if s == "" {
			s = "inactive"
		}
		if missing() {
			return "missing"
		}
		return s
	}
	return strings.TrimSpace(string(out))
}

func missing() bool {
	out, err := exec.Command("systemctl", "list-unit-files", Unit).Output()
	if err != nil {
		return true
	}
	return !strings.Contains(string(out), Unit)
}

// elevator: pkexec se c'e' (GUI/ambiente grafico), altrimenti errore con
// comando manuale (il chiamante lo mostra: mai prompt password custom).
func elevator() (string, error) {
	if _, err := exec.LookPath("pkexec"); err == nil {
		return "pkexec", nil
	}
	return "", fmt.Errorf("pkexec assente: esegui nel terminale: sudo systemctl enable --now %s", Unit)
}

// Start abilita+avvia il servizio (chiede auth di sistema via pkexec).
func Start() error {
	el, err := elevator()
	if err != nil {
		return err
	}
	if out, err := exec.Command(el, "systemctl", "enable", "--now", Unit).CombinedOutput(); err != nil {
		return fmt.Errorf("avvio fallito: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Stop ferma (non disabilita) il servizio. ATTENZIONE: da qui protezione spenta.
func Stop() error {
	el, err := elevator()
	if err != nil {
		return fmt.Errorf("stop manuale: sudo systemctl stop %s (protezione spenta!)", Unit)
	}
	if out, err := exec.Command(el, "systemctl", "stop", Unit).CombinedOutput(); err != nil {
		return fmt.Errorf("stop fallito: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// packagedUnit: la unit che installa il pacchetto .deb. Se c'e', il servizio e' gia' sul
// sistema con binario e unit del pacchetto: resta solo da configurare (utente e profilo).
const packagedUnit = "/usr/lib/systemd/system/zt-shield.service"

// findScript cerca uno script del progetto: prima installato di sistema
// (/usr/share/zeroshield, da .deb), poi sorgente accanto al binario GUI/TUI.
// Ritorna "" se assente: il chiamante mostra il comando manuale.
func findScript(name string) string {
	cands := []string{
		"/usr/share/zeroshield/scripts/" + name,
		"/usr/local/share/zeroshield/scripts/" + name,
	}
	// Dev: risali dall'eseguibile (es. zt-gui/build/bin/zt-gui o bin/zt-tui)
	// fino a trovare scripts/<name> nel tree sorgente.
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		for i := 0; i < 5; i++ {
			cands = append(cands, filepath.Join(d, "scripts", name))
			d = filepath.Dir(d)
		}
	}
	for _, p := range cands {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// InstallScript: install_service.sh, per chi compila dai sorgenti (copia il binario in
// /usr/local/sbin e scrive una propria unit).
func InstallScript() string { return findScript("install_service.sh") }

// ConfigureScript: configure_service.sh, per chi ha installato il .deb (scrive solo
// user/profile nel config e avvia il servizio del pacchetto).
func ConfigureScript() string { return findScript("configure_service.sh") }

// pickInstaller sceglie lo script giusto. Con la unit del pacchetto si usa SOLO
// configure_service.sh: install_service.sh sovrascriverebbe binario e unit del pacchetto
// con una seconda copia in /usr/local/sbin. Senza unit del pacchetto vale il percorso da sorgente.
func pickInstaller(packaged bool, configure, install string) string {
	if packaged {
		return configure
	}
	return install
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// Install configura e avvia il servizio via pkexec: configure_service.sh se il servizio e'
// quello del pacchetto .deb, install_service.sh se si compila dai sorgenti. In entrambi i casi
// scrive utente e profilo nel config e parte in audit. Ritorna l'output per debug.
func Install(user, profile string) error {
	packaged := fileExists(packagedUnit)
	script := pickInstaller(packaged, ConfigureScript(), InstallScript())
	if script == "" {
		if packaged {
			return fmt.Errorf("configure_service.sh non trovato: imposta user: in %s e lancia: sudo systemctl enable --now %s", ConfigPath, Unit)
		}
		return fmt.Errorf("install_service.sh non trovato: da sorgente lancia scripts/install_service.sh nel repo")
	}
	if user == "" {
		return fmt.Errorf("utente vuoto: serve l'utente da proteggere")
	}
	if profile == "" {
		profile = "home"
	}
	el, err := elevator()
	if err != nil {
		return fmt.Errorf("installazione manuale: sudo %s %s %s", script, user, profile)
	}
	if out, err := exec.Command(el, script, user, profile).CombinedOutput(); err != nil {
		return fmt.Errorf("install fallita: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// CurrentUser: l'utente da proteggere (SUDO_USER > USER > whoami).
func CurrentUser() string {
	for _, k := range []string{"SUDO_USER", "USER", "LOGNAME"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" && v != "root" {
			return v
		}
	}
	if out, err := exec.Command("whoami").Output(); err == nil {
		if u := strings.TrimSpace(string(out)); u != "" && u != "root" {
			return u
		}
	}
	return ""
}

// Check: un prerequisito con esito e suggerimento.
type Check struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Hint string `json:"hint,omitempty"`
}

// Preflight verifica l'ambiente prima di installare: la UI mostra semafori,
// non un bottone cieco che fallisce a metà. Mai root richiesto per leggere.
func Preflight() []Check {
	kver, kerr := exec.Command("uname", "-r").Output()
	kernel := strings.TrimSpace(string(kver))
	// Confronto numerico major.minor (lessicografico direbbe 5.9 > 5.15).
	kOK := false
	if kerr == nil {
		var maj, min int
		if _, err := fmt.Sscanf(kernel, "%d.%d", &maj, &min); err == nil {
			kOK = maj > 5 || (maj == 5 && min >= 15)
		}
	}
	btfOK := false
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		btfOK = true
	}
	lsmOK := false
	if data, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		for _, m := range strings.Split(strings.TrimSpace(string(data)), ",") {
			if m == "bpf" {
				lsmOK = true
			}
		}
	}
	_, ufwErr := exec.LookPath("ufw")
	return []Check{
		{Name: "Kernel ≥ 5.15 (" + kernel + ")", OK: kOK, Hint: ifThen(!kOK, "serve kernel recente con eBPF")},
		{Name: "BTF (/sys/kernel/btf/vmlinux)", OK: btfOK, Hint: ifThen(!btfOK, "kernel senza debug info: cambia kernel")},
		{Name: "BPF negli LSM attivi", OK: lsmOK, Hint: ifThen(!lsmOK, "append lsm=...,bpf in GRUB + reboot (README)")},
		{Name: "ufw (firewall)", OK: ufwErr == nil, Hint: ifThen(ufwErr != nil, "sudo apt install ufw (opzionale ma consigliato)")},
		serviceCheck(),
		userCheck(),
	}
}

// serviceCheck: il servizio c'e' gia' (unit del pacchetto o di una installazione precedente)
// oppure si puo' installare da uno script. Prima controllava solo install_service.sh, che il
// .deb non contiene: su una macchina installata dal pacchetto risultava rosso a torto.
func serviceCheck() Check {
	installed := fileExists(packagedUnit) || fileExists("/etc/systemd/system/"+Unit)
	installable := InstallScript() != "" || ConfigureScript() != ""
	return Check{
		Name: "Servizio zt-shield (installato o installabile)",
		OK:   installed || installable,
		Hint: ifThen(!(installed || installable), "installa il pacchetto .deb, o da sorgente lancia scripts/install_service.sh"),
	}
}

// userCheck: senza user: nel config il demone, come servizio, si ferma (sotto systemd non
// esiste SUDO_USER). Il config e' leggibile da tutti (0644): niente root per controllarlo.
func userCheck() Check {
	data, err := os.ReadFile(ConfigPath)
	u := ""
	if err == nil {
		u = ParseUser(string(data))
	}
	return Check{
		Name: "Utente protetto (user:) nel config",
		OK:   u != "",
		Hint: ifThen(u == "", "lo imposta l'installazione guidata, oppure: sudoedit "+ConfigPath),
	}
}

// ParseUser rende il valore della riga attiva "user:" (ignora le righe commentate),
// "" se manca o e' vuoto (user: "").
func ParseUser(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "user:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "user:"))
		if i := strings.Index(v, " #"); i >= 0 { // commento a fine riga
			v = strings.TrimSpace(v[:i])
		}
		return strings.Trim(v, `"'`)
	}
	return ""
}

func ifThen(c bool, s string) string {
	if c {
		return s
	}
	return ""
}

// ConfigPath del demone di sistema.
const ConfigPath = "/etc/zt-shield/shield.yaml"

// ReadConfig rende il testo del config (o il motivo per cui manca).
func ReadConfig() string {
	data, err := os.ReadFile(ConfigPath)
	if err != nil {
		return "config assente (" + ConfigPath + "): installa prima il servizio."
	}
	return string(data)
}

// Ritorna "" se illeggibile: la UI mostra "sconosciuta", non inventa.
func ReadMode() string {
	data, err := os.ReadFile(ConfigPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "mode:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "mode:"))
		}
	}
	return ""
}

// SetMode scrive mode: (solo audit|enforce, validato qui: niente injection
// verso shell) e riavvia il servizio. Via pkexec: dialogo di sistema.
// Il cambio a enforce senza log puliti blocca i tuoi tool: la UI deve
// confermare prima (doppio gesto come per lo stop).
func SetMode(mode string) error {
	if mode != "audit" && mode != "enforce" {
		return fmt.Errorf("mode %q non valido (audit|enforce)", mode)
	}
	el, err := elevator()
	if err != nil {
		return fmt.Errorf("cambio manuale: mode: %s in %s + sudo systemctl restart %s", mode, ConfigPath, Unit)
	}
	// sed con pattern fisso + mode validato sopra: nessun input utente in shell.
	script := fmt.Sprintf("grep -q '^mode:' %s && sed -i 's/^mode:.*/mode: %s/' %s || printf 'mode: %s\\n' >> %s; systemctl restart %s",
		ConfigPath, mode, ConfigPath, mode, ConfigPath, Unit)
	if out, err := exec.Command(el, "sh", "-c", script).CombinedOutput(); err != nil {
		return fmt.Errorf("cambio mode fallito: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
