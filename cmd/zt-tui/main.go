// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// zt-tui: interfaccia terminale per Local Zero-Trust Shield.
//
// Legge stato ed eventi dal socket IPC del demone (/run/zt-shield/api.sock):
// non richiede root, non tocca eBPF. Se il demone non gira mostra la diagnosi
// invece di fallire in silenzio.
//
// Uso: ./bin/zt-tui   (demone attivo: sudo ./bin/zt-shield oppure servizio)
package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"zt-shield/pkg/ipc"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	tabActive  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Underline(true)
	tabIdle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	badgeAudit = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11"))
	badgeBlock = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	badgeOK    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	badgeOff   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	dimStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	evBlock    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	evAudit    = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	helpStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

const (
	tabStatus = iota
	tabEvents
	tabRules
	tabNet
)

var tabNames = []string{"Stato", "Eventi", "Regole", "Rete"}

// --- messaggi ----------------------------------------------------------------

type statusMsg struct {
	st  ipc.Status
	err error
}

type eventMsg struct{ ev ipc.WireEvent }

type tickMsg struct{}

// --- modello -----------------------------------------------------------------

type model struct {
	tab      int
	st       ipc.Status
	connErr  error
	events   []ipc.WireEvent
	paused   bool
	offset   int // scroll lista eventi (0 = fondo/live)
	width    int
	height   int
	quitting bool
}

func initialModel() model { return model{tab: tabStatus} }

func (m model) Init() tea.Cmd { return tea.Batch(fetchStatus, tickStatus) }

func fetchStatus() tea.Msg {
	st, err := ipc.GetStatus()
	return statusMsg{st: st, err: err}
}

func tickStatus() tea.Msg {
	time.Sleep(2 * time.Second)
	st, err := ipc.GetStatus()
	return statusMsg{st: st, err: err}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "tab", "l", "right":
			m.tab = (m.tab + 1) % len(tabNames)
			m.offset = 0
		case "shift+tab", "h", "left":
			m.tab = (m.tab + len(tabNames) - 1) % len(tabNames)
			m.offset = 0
		case "1", "2", "3", "4":
			m.tab = int(msg.String()[0] - '1')
			m.offset = 0
		case "r":
			return m, fetchStatus
		case " ":
			if m.tab == tabEvents {
				m.paused = !m.paused
			}
		case "up", "k":
			if m.tab == tabEvents {
				m.paused = true
				m.offset++
			}
		case "down", "j":
			if m.tab == tabEvents && m.offset > 0 {
				m.offset--
				if m.offset == 0 {
					m.paused = false
				}
			}
		case "G", "end":
			if m.tab == tabEvents {
				m.offset = 0
				m.paused = false
			}
		}
		return m, nil
	case statusMsg:
		if msg.err == nil {
			m.st = msg.st
			m.connErr = nil
		} else if m.st.Profile == "" {
			// Mai connesso: mostra errore. Se era connesso, tiene ultimo stato.
			m.connErr = msg.err
		}
		return m, tickStatus
	case tickMsg:
		return m, fetchStatus
	case eventMsg:
		m.events = append(m.events, msg.ev)
		if len(m.events) > 200 {
			m.events = m.events[len(m.events)-200:]
		}
		return m, nil
	}
	return m, nil
}

// --- vista -------------------------------------------------------------------

func (m model) View() string {
	if m.quitting {
		return ""
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("🛡️ zt-shield") + "  " + m.modeBadge() + "\n")
	b.WriteString(m.tabBar() + "\n\n")
	if m.connErr != nil && m.st.Profile == "" {
		b.WriteString(m.offlineView())
	} else {
		switch m.tab {
		case tabStatus:
			b.WriteString(m.statusView())
		case tabEvents:
			b.WriteString(m.eventsView())
		case tabRules:
			b.WriteString(m.rulesView())
		case tabNet:
			b.WriteString(m.netView())
		}
	}
	b.WriteString("\n" + helpStyle.Render("tab cambia · 1-4 vai · r aggiorna · q esci") +
		helpStyle.Render("   |   eventi: spazio pausa · ↑/↓ scorri · fine torna live"))
	return b.String()
}

func (m model) modeBadge() string {
	if m.st.Profile == "" {
		return badgeOff.Render("● demone non raggiungibile")
	}
	if m.st.Mode == "enforce" {
		return badgeBlock.Render("● ENFORCE (blocca)")
	}
	return badgeAudit.Render("● AUDIT (logga)")
}

func (m model) tabBar() string {
	var parts []string
	for i, n := range tabNames {
		label := fmt.Sprintf("%d %s", i+1, n)
		if i == m.tab {
			parts = append(parts, tabActive.Render("["+label+"]"))
		} else {
			parts = append(parts, tabIdle.Render(" "+label+" "))
		}
	}
	extra := ""
	if m.tab == tabEvents && len(m.events) > 0 {
		extra = dimStyle.Render(fmt.Sprintf("  %d eventi", len(m.events)))
		if m.paused {
			extra += badgeAudit.Render("  ⏸ in pausa")
		}
	}
	return strings.Join(parts, " ") + extra
}

func (m model) offlineView() string {
	return "Demone non raggiungibile via " + ipc.SocketPath + ".\n\n" +
		"Avvialo prima (profilo audit, non blocca nulla):\n" +
		"  sudo SHIELD_USER=$USER ./bin/zt-shield\n\n" +
		"oppure come servizio:\n" +
		"  sudo bash scripts/install_service.sh $USER home\n" +
		"  journalctl -u zt-shield -f\n\n" +
		dimStyle.Render(fmt.Sprintf("ultimo errore: %v", m.connErr))
}

func hookDot(ok bool) string {
	if ok {
		return badgeOK.Render("● attivo")
	}
	return badgeOff.Render("● spento")
}

func (m model) statusView() string {
	s := m.st
	rows := []string{
		fmt.Sprintf("Profilo:  %s   Modalità: %s", s.Profile, s.Mode),
		fmt.Sprintf("Home:     %s", s.Home),
		fmt.Sprintf("LSM hook: %s   (fail-closed: se manca, il demone si ferma)", hookDot(s.HookLSM)),
		fmt.Sprintf("File protetti: %d   Binari autorizzati: %d", s.Protected, s.Allowed),
		fmt.Sprintf("Aggiornato: %s", s.Time),
	}
	return strings.Join(rows, "\n")
}

func (m model) eventsView() string {
	if len(m.events) == 0 {
		return dimStyle.Render("Nessun evento ancora. In audit gli accessi legittimi compaiono qui;\npassa a enforce solo quando i log sono puliti.")
	}
	// Altezza visibile: terminale meno header/footer, con margine.
	height := m.height - 10
	if height < 5 {
		height = 10
	}
	if height > len(m.events) {
		height = len(m.events)
	}
	start := len(m.events) - height - m.offset
	if start < 0 {
		start = 0
	}
	end := start + height
	if end > len(m.events) {
		end = len(m.events)
	}
	var rows []string
	for _, ev := range m.events[start:end] {
		icon := evAudit.Render("👁 AUDIT  ")
		if ev.Action == "blocked" {
			icon = evBlock.Render("🚨 BLOCCO ")
		}
		exe := ev.Exe
		if exe == "" {
			exe = dimStyle.Render("(processo uscito)")
		}
		rows = append(rows, fmt.Sprintf("%s %s  %-14s pid=%-6d %s %s",
			icon, ev.Time[11:19], ev.Rule, ev.PID, ev.Comm, exe))
	}
	if m.offset > 0 {
		rows = append(rows, dimStyle.Render(fmt.Sprintf("… +%d sopra (fine = torna live)", m.offset)))
	}
	return strings.Join(rows, "\n")
}

func (m model) rulesView() string {
	if len(m.st.Rules) == 0 {
		return dimStyle.Render("Nessuna regola caricata.")
	}
	var rows []string
	for _, r := range m.st.Rules {
		rows = append(rows, badgeOK.Render("■ "+r.Name))
		rows = append(rows, "  file: "+strings.Join(r.Paths, ", "))
		rows = append(rows, "  exe:  "+strings.Join(r.Allow, ", ")+"\n")
	}
	return strings.Join(rows, "\n")
}

func (m model) netView() string {
	s := m.st
	xdp := "(spento)"
	if len(s.XDP) > 0 {
		xdp = strings.Join(s.XDP, ", ")
	}
	rows := []string{
		fmt.Sprintf("XDP su: %s", xdp),
		fmt.Sprintf("Drop poisoning (5355/5353/137/138): %v", s.BlockPoisoning),
		"Subnet bloccate:",
	}
	if len(s.BlockSubnets) == 0 {
		rows = append(rows, "  (nessuna — solo drop poisoning + UFW)")
	} else {
		for _, c := range s.BlockSubnets {
			rows = append(rows, "  🚫 "+c)
		}
		rows = append(rows, dimStyle.Render("  (il drop scarta anche le risposte da queste reti)"))
	}
	return strings.Join(rows, "\n")
}

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;?]*[a-zA-Z]")

// dump rende ogni tab con dati di esempio e li stampa senza ANSI,
// per anteprime in chat/log dove i colori non vengono interpretati.
func dump() string {
	m := initialModel()
	m.width, m.height = 100, 30
	m.st = ipc.Status{
		Profile: "home", Mode: "audit", Home: "/home/utente",
		HookLSM: true, XDP: []string{"enp0s3"},
		Protected: 42, Allowed: 18,
		BlockPoisoning: true, BlockSubnets: []string{"192.168.100.0/24"},
		Rules: []ipc.RuleSummary{
			{Name: "ssh-keys", Paths: []string{".ssh/id_*"}, Allow: []string{"ssh", "ssh-add", "ssh-agent"}},
			{Name: "cloud-creds", Paths: []string{".kube/config", ".aws/credentials"}, Allow: []string{"kubectl", "helm"}},
			{Name: "dev-tokens", Paths: []string{".git-credentials", ".docker/config.json"}, Allow: []string{"git", "gh"}},
		},
		Time: "2026-10-02T10:35:01Z",
	}
	m.events = []ipc.WireEvent{
		{Time: "2026-10-02T10:35:02Z", Action: "audit", PID: 4211, Comm: "cat", Exe: "/usr/bin/cat", Rule: "cloud-creds", Inode: 9740993},
		{Time: "2026-10-02T10:35:04Z", Action: "audit", PID: 4220, Comm: "python3", Exe: "/usr/bin/python3.12", Rule: "ssh-keys", Inode: 112345},
		{Time: "2026-10-02T10:35:05Z", Action: "blocked", PID: 48921, Comm: "cat", Exe: "/usr/bin/cat", Rule: "cloud-creds", Inode: 9740993},
		{Time: "2026-10-02T10:35:07Z", Action: "blocked", PID: 5317, Comm: "ssh", Exe: "/tmp/ssh", Rule: "ssh-keys", Inode: 112345},
	}
	var b strings.Builder
	for i, n := range tabNames {
		m.tab = i
		b.WriteString(fmt.Sprintf("===== TAB %d %s =====\n", i+1, n))
		b.WriteString(ansiRe.ReplaceAllString(m.View(), ""))
		b.WriteString("\n\n")
	}
	return b.String()
}

func main() {
	// --dump: anteprima statica senza TTY (screenshot/docs). Dati inventati,
	// niente demone, niente root. Es: ./bin/zt-tui --dump
	if len(os.Args) > 1 && os.Args[1] == "--dump" {
		fmt.Print(dump())
		return
	}
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	// Stream eventi in background: i messaggi viaggiano via p.Send, il loop
	// resta reattivo anche senza demone (solo status in errore).
	go func() {
		_ = ipc.Subscribe(context.Background(), func(ev ipc.WireEvent) {
			p.Send(eventMsg{ev: ev})
		})
		// Se il demone non c'e' o cade, Subscribe ritorna: riprova ogni 3s
		// finche' il programma vive.
		for {
			time.Sleep(3 * time.Second)
			if err := ipc.Subscribe(context.Background(), func(ev ipc.WireEvent) {
				p.Send(eventMsg{ev: ev})
			}); err == nil {
				return
			}
		}
	}()
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui:", err)
		os.Exit(1)
	}
}
