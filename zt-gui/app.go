// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"time"

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
		for {
			err := ipc.Subscribe(ctx, func(ev ipc.WireEvent) {
				runtime.EventsEmit(a.ctx, "shield:event", ev)
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
}

// GetStatus per il primo paint sincrono (poi arrivano gli eventi push).
func (a *App) GetStatus() (ipc.Status, error) {
	return ipc.GetStatus()
}

// SocketPath dice al frontend dove guarda (debug finestre offline).
func (a *App) SocketPath() string {
	return ipc.SocketPath
}
