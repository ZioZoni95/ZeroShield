// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// zt-tray: icona nella barra di sistema (StatusNotifierItem) per ZeroShield.
//
// Gira come utente, senza privilegi, e legge solo il socket IPC in sola lettura.
// Non fa parte della protezione: se la chiudi il demone continua a proteggere.
// Serve a vedere a colpo d'occhio se il demone e' acceso e a ricevere le
// notifiche anche quando la GUI e' chiusa.
//
// Su GNOME la barra mostra queste icone solo con l'estensione AppIndicator
// (pacchetto gnome-shell-extension-appindicator); KDE, XFCE e Cinnamon le
// mostrano da sole.
package main

import (
	"context"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"fyne.io/systray"
	"github.com/godbus/dbus/v5"

	"zt-shield/pkg/ipc"
)

var version = "dev"

const pollEvery = 3 * time.Second

// iconRefresh: ogni quanto riaffermare l'icona anche se lo stato non cambia.
const iconRefresh = 30 * time.Second

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println("zt-tray", version)
		return
	}
	// Una sola icona per sessione: l'autostart e un avvio a mano non devono
	// produrne due.
	if unlock, ok := singleInstance(); !ok {
		return
	} else {
		defer unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t := &tray{ctx: ctx}
	systray.Run(t.onReady, cancel)
}

type tray struct {
	ctx    context.Context
	mStat  *systray.MenuItem
	mOpen  *systray.MenuItem
	mu     sync.Mutex
	cur    state
	known  bool      // abbiamo gia' letto almeno uno stato
	iconAt time.Time // ultima volta che l'icona e' stata impostata
	lastEv time.Time
	supp   int
}

func (t *tray) onReady() {
	systray.SetTitle("ZeroShield")
	t.mStat = systray.AddMenuItem("Controllo…", "")
	t.mStat.Disable()
	systray.AddSeparator()
	t.mOpen = systray.AddMenuItem("Apri ZeroShield", "Apre la finestra con stato ed eventi")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Chiudi l'icona", "La protezione resta attiva")
	// Clic sull'icona = apri la finestra (dove la barra lo consente).
	systray.SetOnTapped(t.openGUI)

	go func() {
		for {
			select {
			case <-t.mOpen.ClickedCh:
				t.openGUI()
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			case <-t.ctx.Done():
				return
			}
		}
	}()
	go t.pollLoop()
	go t.eventLoop()
	go t.canaryLoop()
}

func (t *tray) pollLoop() {
	tick := time.NewTicker(pollEvery)
	defer tick.Stop()
	for {
		st, err := ipc.GetStatus()
		t.apply(classify(st, err), st)
		select {
		case <-t.ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// apply aggiorna icona e menu; notifica solo i cambi che contano per l'utente:
// demone caduto e demone tornato. Il primo stato letto non notifica se e' buono.
func (t *tray) apply(s state, st ipc.Status) {
	t.mu.Lock()
	prev, had := t.cur, t.known
	t.cur, t.known = s, true
	t.mu.Unlock()

	line := s.label()
	if s != stDown && st.Profile != "" {
		line += " — profilo " + st.Profile
	}
	t.mStat.SetTitle(line)
	systray.SetTooltip("ZeroShield: " + line)
	// L'icona si reimposta anche a stato invariato, ogni iconRefresh: se la prima chiamata
	// arriva prima che la barra abbia registrato l'elemento, l'immagine resta vuota (icona
	// invisibile, visto dopo un doppio riavvio da `apt install`) e non si sistemerebbe piu'.
	if !had || prev != s || time.Since(t.iconAt) >= iconRefresh {
		systray.SetIcon(iconPNG(s))
		t.iconAt = time.Now()
	}
	switch {
	case s == stDown && (!had || prev != stDown):
		notify("ZeroShield — demone spento", "Il sistema non è protetto. Controlla: systemctl status zt-shield")
	case had && prev == stDown && s != stDown:
		notify("ZeroShield — di nuovo attivo", s.label())
	}
}

// eventLoop e canaryLoop notificano solo a GUI chiusa: con la GUI aperta lo
// fa lei, e due notifiche per lo stesso evento sono rumore.
func (t *tray) eventLoop() {
	for t.ctx.Err() == nil {
		_ = ipc.Subscribe(t.ctx, func(ev ipc.WireEvent) {
			if ev.Action != "blocked" || guiRunning("/proc") {
				return
			}
			t.mu.Lock()
			now := time.Now()
			if now.Sub(t.lastEv) < 10*time.Second {
				t.supp++
				t.mu.Unlock()
				return
			}
			supp := t.supp
			t.supp, t.lastEv = 0, now
			t.mu.Unlock()
			msg := fmt.Sprintf("%s (pid %d) negato su %s", clean(ev.Exe), ev.PID, clean(ev.Rule))
			if supp > 0 {
				msg += fmt.Sprintf(" (+%d altri)", supp)
			}
			notify("ZeroShield — accesso bloccato", msg)
		})
		sleepCtx(t.ctx, 3*time.Second)
	}
}

func (t *tray) canaryLoop() {
	for t.ctx.Err() == nil {
		_ = ipc.SubscribeCanary(t.ctx, func(al ipc.CanaryAlert) {
			if guiRunning("/proc") {
				return
			}
			title := "ZeroShield — esca canary toccata"
			if al.Action != "killed" {
				title += " (audit)"
			}
			notify(title, fmt.Sprintf("pid %d (%s) %s %s — %s",
				al.PID, clean(al.Exe), clean(al.Kind), clean(al.Path), clean(al.Reason)))
		})
		sleepCtx(t.ctx, 3*time.Second)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// clean: i campi arrivano da processi osservati; i server di notifica con
// markup nel corpo interpretano <a>/<img>, quindi testo sicuro + escape HTML.
func clean(s string) string { return html.EscapeString(ipc.SafeText(s)) }

// openGUI avvia zt-gui se non gira gia'. Se manca (installazione --no-install-recommends)
// avvisa invece di fallire in silenzio.
func (t *tray) openGUI() {
	if guiRunning("/proc") {
		return
	}
	cmd := guiCommand()
	if err := cmd.Start(); err != nil {
		notify("ZeroShield", "La finestra non è installata (zt-gui). Lo stato resta visibile dall'icona e con zt-tui.")
		return
	}
	go func() { _ = cmd.Wait() }() // evita lo zombie
}

// guiCommand: sotto systemd la GUI parte in uno scope proprio. Come figlia del servizio finirebbe
// nello stesso cgroup e chiuderebbe con lui a ogni riavvio dell'icona (aggiornamento incluso).
func guiCommand() *exec.Cmd {
	if os.Getenv("INVOCATION_ID") != "" {
		if p, err := exec.LookPath("systemd-run"); err == nil {
			return exec.Command(p, "--user", "--scope", "--quiet", "--collect", "zt-gui") //nolint:gosec // percorsi fissi
		}
	}
	return exec.Command("zt-gui")
}

// notify usa direttamente org.freedesktop.Notifications: niente dipendenza in piu'.
// Errori ignorati: senza server di notifiche (server, sessione remota) l'icona resta.
func notify(title, body string) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return
	}
	obj := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	obj.Call("org.freedesktop.Notifications.Notify", 0,
		"ZeroShield", uint32(0), "zeroshield", title, body,
		[]string{}, map[string]dbus.Variant{}, int32(8000))
}

// singleInstance prende un flock non bloccante nella runtime dir dell'utente.
func singleInstance() (func(), bool) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.OpenFile(filepath.Join(dir, "zt-tray.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, true // meglio due icone che nessuna
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, false
	}
	return func() { _ = f.Close() }, true
}
