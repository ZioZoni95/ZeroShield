// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gen2brain/beeep"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"zt-shield/pkg/ipc"
	"zt-shield/pkg/rules"
	"zt-shield/pkg/svc"
)

// App struct: backend GUI sopra lo stesso socket IPC della TUI.
// Nessun privilegio qui: legge stato/eventi, non tocca eBPF né mappe.
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup lancia i poll verso il demone: stato ogni 2s + stream eventi live.
// Se il demone non gira, il frontend riceve errori e mostra la diagnosi.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		push := func() {
			st, err := ipc.GetStatus()
			if err != nil {
				runtime.EventsEmit(a.ctx, "shield:status-error", err.Error())
				return
			}
			runtime.EventsEmit(a.ctx, "shield:status", st)
		}
		push()
		for range ticker.C {
			select {
			case <-ctx.Done():
				return
			default:
			}
			push()
		}
	}()

	go func() {
		// Notifiche desktop sui blocchi (non sugli audit: troppo rumore).
		// Throttle 1/10s con conteggio soppressi: senza, un flood di open()
		// riempie il centro notifiche come riempiva i log prima del rate-limit.
		var last time.Time
		suppressed := 0
		notify := func(ev ipc.WireEvent) {
			if ev.Action != "blocked" {
				return
			}
			now := time.Now()
			if now.Sub(last) < 10*time.Second {
				suppressed++
				return
			}
			// notifyText: exe scelto dal processo osservato; i server di notifica
			// con body-markup interpretano <a href>/<img>, quindi escape HTML.
			msg := fmt.Sprintf("%s (pid %d) negato su %s", notifyText(ev.Exe), ev.PID, notifyText(ev.Rule))
			if suppressed > 0 {
				msg += fmt.Sprintf(" (+%d altri)", suppressed)
				suppressed = 0
			}
			last = now
			// Errore ignorato: su server senza notify-send non c'e' centro
			// notifiche, la tabella Eventi resta la fonte primaria.
			_ = beeep.Notify("ZeroShield — accesso bloccato", msg, "")
		}
		for {
			err := ipc.Subscribe(ctx, func(ev ipc.WireEvent) {
				runtime.EventsEmit(a.ctx, "shield:event", ev)
				notify(ev)
			})
			if ctx.Err() != nil {
				return
			}
			// Demone assente: riprova ogni 3s senza morire.
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			_ = err
		}
	}()

	// Canary: stesso retry, evento dedicato + notifica desktop sempre
	// (anche in audit: un tocco esca merita attenzione anche solo loggato).
	go func() {
		for {
			err := ipc.SubscribeCanary(ctx, func(al ipc.CanaryAlert) {
				runtime.EventsEmit(a.ctx, "shield:canary", al)
				title := "ZeroShield — esca canary toccata"
				if al.Action != "killed" {
					title += " (audit)"
				}
				_ = beeep.Notify(title,
					fmt.Sprintf("pid %d (%s) %s %s — %s", al.PID, notifyText(al.Exe), notifyText(al.Kind), notifyText(al.Path), notifyText(al.Reason)), "")
			})
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			_ = err
		}
	}()
}

// GetStatus per il primo paint sincrono (poi arrivano gli eventi push).
func (a *App) GetStatus() (ipc.Status, error) {
	return ipc.GetStatus()
}

// Version e' la versione del binario, valorizzata dal build (non scritta a mano nel JS).
func (a *App) Version() string {
	return version
}

// SocketPath dice al frontend dove guarda (debug finestre offline).
func (a *App) SocketPath() string {
	return ipc.SocketPath
}

// ServiceState per la UI: active/inactive/missing/unknown. Mai root richiesto.
func (a *App) ServiceState() string {
	return svc.State()
}

// ServiceInstall esegue install_service.sh via pkexec (dialogo di sistema).
// Dopo l'installazione il servizio parte in audit: mai enforce di default.
func (a *App) ServiceInstall() error {
	return svc.Install(svc.CurrentUser(), "home")
}

// ServiceInstallAs come sopra ma con utente e profilo espliciti (wizard).
func (a *App) ServiceInstallAs(user, profile string) error {
	if profile == "" {
		profile = "home"
	}
	return svc.Install(user, profile)
}

// ServiceStart abilita+avvia via pkexec (dialogo di sistema, mai password nostre).
func (a *App) ServiceStart() error {
	return svc.Start()
}

// ServiceStop ferma il servizio. La UI deve mostrare l'avviso: protezione spenta.
func (a *App) ServiceStop() error {
	return svc.Stop()
}

// ConfigMode legge mode: dal config di sistema ("" se illeggibile).
func (a *App) ConfigMode() string {
	return svc.ReadMode()
}

// Preflight per l'out-of-box: semafori prerequisiti prima di installare.
func (a *App) Preflight() []svc.Check {
	return svc.Preflight()
}

// SetConfigMode cambia audit|enforce + restart via pkexec. La UI conferma prima:
// enforce con log sporchi blocca i tool legittimi.
func (a *App) SetConfigMode(mode string) error {
	return svc.SetMode(mode)
}

// ConfigText rende il config di sistema (sola lettura qui; la scrittura passa
// da SetConfigMode con auth). Persiste su disco: ogni boot lo rilegge.
func (a *App) ConfigText() string {
	return svc.ReadConfig()
}

// RulesModel: gruppi di segreti, programmi noti e scelte correnti, dal config di sistema.
func (a *App) RulesModel() rules.Model {
	home, _ := os.UserHomeDir()
	return rules.BuildModel(svc.ReadConfig(), home)
}

// CheckProgram dice se un programma (nome o percorso) si puo' autorizzare e, se no, perche'.
func (a *App) CheckProgram(input string) rules.Program {
	home, _ := os.UserHomeDir()
	return rules.Check(home, input)
}

// ApplyRules scrive le scelte nel blocco gestito del config e riavvia il servizio (auth di
// sistema). Il testo risultante e' validato qui e di nuovo dal demone prima di sostituire il file.
func (a *App) ApplyRules(c rules.Choice) error {
	cur := svc.ReadConfig()
	if _, err := os.Stat(svc.ConfigPath); err != nil {
		return fmt.Errorf("config di sistema assente: installa prima il servizio")
	}
	// La scelta delle interfacce non e' di questa schermata: si conserva quella gia' salvata.
	if have, perr := rules.Parse(cur); perr == nil {
		c.Interface = have.Interface
	}
	next, err := rules.Apply(cur, c)
	if err != nil {
		return err
	}
	if err := rules.Validate(next); err != nil {
		return fmt.Errorf("il demone rifiuterebbe questa configurazione: %w", err)
	}
	return svc.ApplyConfig(next)
}

// ApplyInterfaces salva le interfacce su cui filtrare (vuoto = automatica) e riavvia il servizio (auth di
// sistema). Le altre scelte (regole, modalita') restano com'erano.
func (a *App) ApplyInterfaces(names []string) error {
	cur := svc.ReadConfig()
	if _, err := os.Stat(svc.ConfigPath); err != nil {
		return fmt.Errorf("config di sistema assente: installa prima il servizio")
	}
	have, err := rules.Parse(cur)
	if err != nil {
		return err
	}
	have.Interface = strings.Join(names, ",")
	next, err := rules.Apply(cur, have)
	if err != nil {
		return err
	}
	if err := rules.Validate(next); err != nil {
		return fmt.Errorf("il demone rifiuterebbe questa configurazione: %w", err)
	}
	return svc.ApplyConfig(next)
}

// PreviewPaths: cosa proteggerebbe una regola con questi percorsi (file trovati, avvisi, errori).
func (a *App) PreviewPaths(paths []string) rules.PreviewResult {
	home, _ := os.UserHomeDir()
	return rules.Preview(home, paths)
}

// PickPath apre il selettore di file (kind "file") o di cartelle (kind "dir") del sistema. Restituisce
// il percorso relativo alla home se sta li' dentro, altrimenti assoluto; "" se l'utente annulla.
func (a *App) PickPath(kind string) (string, error) {
	home, _ := os.UserHomeDir()
	var p string
	var err error
	if kind == "dir" {
		p, err = runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{Title: "Scegli la cartella da proteggere", DefaultDirectory: home})
	} else {
		p, err = runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{Title: "Scegli il file da proteggere", DefaultDirectory: home})
	}
	if err != nil || p == "" {
		return "", err
	}
	if rel, e := filepath.Rel(home, p); e == nil && rel != "." && !strings.HasPrefix(rel, "..") {
		return rel, nil
	}
	return p, nil
}

// MakeTrusted rende affidabile un programma (copia di root in /usr/local/bin) solo se il
// controllo lo ritiene sensato: la GUI non puo' farlo per shell, interpreti o lettori generici.
func (a *App) MakeTrusted(input string) (rules.Program, error) {
	home, _ := os.UserHomeDir()
	p := rules.Check(home, input)
	if !p.Found || p.Fix == "" {
		return p, fmt.Errorf("questo programma non si può rendere affidabile da qui")
	}
	if err := svc.InstallTrusted(p.Path, p.Name); err != nil {
		return p, err
	}
	return rules.Check(home, "/usr/local/bin/"+p.Name), nil
}

// notifyText rende innocua una stringa esterna per il corpo della notifica:
// niente sequenze di controllo, niente markup interpretato dal notification server.
func notifyText(s string) string { return html.EscapeString(ipc.SafeText(s)) }
