// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"html"
	"time"

	"github.com/gen2brain/beeep"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"zt-shield/pkg/ipc"
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

// SocketPath dice al frontend dove guarda (debug finestre offline).
func (a *App) SocketPath() string {
	return ipc.SocketPath
}

// notifyText rende innocua una stringa esterna per il corpo della notifica:
// niente sequenze di controllo, niente markup interpretato dal notification server.
func notifyText(s string) string { return html.EscapeString(ipc.SafeText(s)) }
