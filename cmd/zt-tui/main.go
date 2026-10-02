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
	"hash/fnv"
	"math"
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
	tabRadar
)

var tabNames = []string{"Stato", "Eventi", "Regole", "Rete", "Radar"}

// --- messaggi ----------------------------------------------------------------

type statusMsg struct {
	st  ipc.Status
	err error
}

type eventMsg struct{ ev ipc.WireEvent }

type canaryMsg struct{ a ipc.CanaryAlert }

type tickMsg struct{}

// sweepMsg avanza la spazzata del radar (solo eye-candy: i dati restano eBPF).
type sweepMsg struct{}

// --- modello -----------------------------------------------------------------

type model struct {
	tab      int
	st       ipc.Status
	connErr  error
	events   []ipc.WireEvent
	canaries []ipc.CanaryAlert
	paused   bool
	offset   int // scroll lista eventi (0 = fondo/live)
	sweep    int // angolo spazzata radar, gradi
	width    int
	height   int
	quitting bool
}

func initialModel() model { return model{tab: tabStatus} }

func (m model) Init() tea.Cmd { return tea.Batch(fetchStatus, tickStatus, tickSweep) }

func fetchStatus() tea.Msg {
	st, err := ipc.GetStatus()
	return statusMsg{st: st, err: err}
}

func tickStatus() tea.Msg {
	time.Sleep(2 * time.Second)
	st, err := ipc.GetStatus()
	return statusMsg{st: st, err: err}
}

func tickSweep() tea.Msg {
	time.Sleep(300 * time.Millisecond)
	return sweepMsg{}
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
		case "1", "2", "3", "4", "5":
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
	case sweepMsg:
		m.sweep = (m.sweep + 15) % 360
		return m, tickSweep
	case eventMsg:
		m.events = append(m.events, msg.ev)
		if len(m.events) > 200 {
			m.events = m.events[len(m.events)-200:]
		}
		return m, nil
	case canaryMsg:
		m.canaries = append(m.canaries, msg.a)
		if len(m.canaries) > 50 {
			m.canaries = m.canaries[len(m.canaries)-50:]
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
		case tabRadar:
			b.WriteString(m.radarView())
		}
	}
	b.WriteString("\n" + helpStyle.Render("tab cambia · 1-5 vai · r aggiorna · q esci") +
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
	if m.tab == tabEvents && len(m.events)+len(m.canaries) > 0 {
		extra = dimStyle.Render(fmt.Sprintf("  %d eventi", len(m.events)+len(m.canaries)))
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

// clock estrae hh:mm:ss da un timestamp RFC3339 senza panic su stringhe corte
// (prima ev.Time[11:19] andava in panic con un time malformato dal socket).
func clock(ts string) string {
	if len(ts) < 19 {
		return "--:--:--"
	}
	return ts[11:19]
}

// SafeText su comm/exe/path: li sceglie il processo osservato, quindi
// potenzialmente un attaccante che inietta sequenze ANSI nel terminale.
func (m model) eventsView() string {
	var rows []string
	// Canary in testa: kill/allarmi anti-ransomware meritano visibilita' massima.
	for _, a := range m.canaries {
		icon := evAudit.Render("🐤 CANARY ")
		if a.Action == "killed" {
			icon = evBlock.Render("🐤 KILL    ")
		}
		rows = append(rows, fmt.Sprintf("%s %s  pid=%-6d %s %s (%s)",
			icon, clock(a.Time), a.PID, ipc.SafeText(a.Exe), ipc.SafeText(a.Path), ipc.SafeText(a.Reason)))
	}
	if len(m.events) == 0 && len(rows) == 0 {
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
	for _, ev := range m.events[start:end] {
		icon := evAudit.Render("👁 AUDIT  ")
		if ev.Action == "blocked" {
			icon = evBlock.Render("🚨 BLOCCO ")
		}
		exe := ipc.SafeText(ev.Exe)
		if exe == "" {
			exe = dimStyle.Render("(processo uscito)")
		}
		rows = append(rows, fmt.Sprintf("%s %s  %-14s pid=%-6d %s %s",
			icon, clock(ev.Time), ipc.SafeText(ev.Rule), ev.PID, ipc.SafeText(ev.Comm), exe))
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

// radarAngle distribuisce un IP sul giro a partire dall'hash: stabile tra frame,
// cosi' ogni sorgente tiene la sua posizione mentre la spazzata gira.
func radarAngle(ip string) float64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ip))
	return float64(h.Sum32()%360) * math.Pi / 180
}

// radarView: sweep ASCII + blip per sorgente droppata da XDP.
// Raggio dal totale drop (scala log: 1 pacchetto si vede, 1000 non esplodono).
// Colori: blip rosso se domina subnet, ambra se domina poisoning.
func (m model) radarView() string {
	src := m.st.TopSources
	if len(src) == 0 {
		return dimStyle.Render("Radar vuoto: XDP non ha droppato nulla da ultimo avvio.\nGenera traffico di poisoning in lab per vedere i blip.")
	}
	const W, H = 27, 13
	cx, cy := W/2, H/2
	rx, ry := float64(W/2-1), float64(H/2-1)
	grid := make([][]rune, H)
	for y := range grid {
		grid[y] = []rune(strings.Repeat(" ", W))
	}
	// Anelli.
	for deg := 0; deg < 360; deg += 3 {
		a := float64(deg) * math.Pi / 180
		for _, f := range []float64{0.33, 0.66, 1.0} {
			x := int(math.Round(float64(cx) + math.Cos(a)*rx*f))
			y := int(math.Round(float64(cy) + math.Sin(a)*ry*f))
			if x >= 0 && x < W && y >= 0 && y < H && grid[y][x] == ' ' {
				grid[y][x] = '·'
			}
		}
	}
	// Spazzata.
	sa := float64(m.sweep) * math.Pi / 180
	for f := 0.0; f <= 1.0; f += 0.05 {
		x := int(math.Round(float64(cx) + math.Cos(sa)*rx*f))
		y := int(math.Round(float64(cy) + math.Sin(sa)*ry*f))
		if x >= 0 && x < W && y >= 0 && y < H {
			grid[y][x] = '∙'
		}
	}
	grid[cy][cx] = '+'
	// Blip: max totale per scala.
	var max uint32 = 1
	for _, s := range src {
		if s.Total > max {
			max = s.Total
		}
	}
	type blip struct{ x, y int }
	blips := map[blip]ipc.SourceStat{}
	for _, s := range src {
		frac := math.Log10(float64(s.Total)+1) / math.Log10(float64(max)+1)
		r := 0.15 + 0.85*frac
		a := radarAngle(s.IP)
		x := int(math.Round(float64(cx) + math.Cos(a)*rx*r))
		y := int(math.Round(float64(cy) + math.Sin(a)*ry*r))
		if x < 0 {
			x = 0
		}
		if x >= W {
			x = W - 1
		}
		if y < 0 {
			y = 0
		}
		if y >= H {
			y = H - 1
		}
		blips[blip{x, y}] = s
	}
	var sb strings.Builder
	for y := 0; y < H; y++ {
		for x := 0; x < W; x++ {
			if s, ok := blips[blip{x, y}]; ok {
				if s.Subnet >= s.Poison {
					sb.WriteString(evBlock.Render("●"))
				} else {
					sb.WriteString(evAudit.Render("●"))
				}
				continue
			}
			c := grid[y][x]
			if c == '∙' {
				sb.WriteString(dimStyle.Render(string(c)))
			} else {
				sb.WriteRune(c)
			}
		}
		sb.WriteString("\n")
	}
	// Legenda + top con barre.
	sb.WriteString(dimStyle.Render("● subnet  ") + evBlock.Render("●") + dimStyle.Render("  ● poisoning  ") + evAudit.Render("●") + "\n")
	barMax := 18
	for _, s := range src {
		n := 1
		if max > 0 {
			n = int(math.Round(float64(s.Total) / float64(max) * float64(barMax)))
			if n < 1 {
				n = 1
			}
		}
		bar := strings.Repeat("█", n)
		kind := "poisoning"
		if s.Subnet >= s.Poison {
			kind = "subnet"
		}
		sb.WriteString(fmt.Sprintf("%-15s %5d  %s %s (visto %s)\n", s.IP, s.Total, evBlock.Render(bar), kind, s.LastSeen[11:19]))
	}
	return sb.String()
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
		TopSources: []ipc.SourceStat{
			{IP: "192.168.100.7", Poison: 34, Subnet: 0, Total: 34, LastSeen: "2026-10-02T10:35:01Z"},
			{IP: "192.168.100.23", Poison: 0, Subnet: 128, Total: 128, LastSeen: "2026-10-02T10:35:00Z"},
			{IP: "10.201.50.99", Poison: 5, Subnet: 0, Total: 5, LastSeen: "2026-10-02T10:34:12Z"},
		},
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
	m.canaries = []ipc.CanaryAlert{
		{Time: "2026-10-02T10:35:09Z", Action: "killed", PID: 6666, Exe: "/usr/bin/python3", Path: "/home/utente/Documents/.canary-accounts.xlsx", Kind: "write", Reason: "tocco esca canary"},
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
	// Stream eventi + canary in background: i messaggi viaggiano via p.Send,
	// il loop resta reattivo anche senza demone (solo status in errore).
	// retryLoop: se il demone non c'e' o cade, riprova ogni 3s per sempre.
	retryLoop := func(sub func(context.Context) error) {
		if err := sub(context.Background()); err == nil {
			return
		}
		for {
			time.Sleep(3 * time.Second)
			if err := sub(context.Background()); err == nil {
				return
			}
		}
	}
	go retryLoop(func(ctx context.Context) error {
		return ipc.Subscribe(ctx, func(ev ipc.WireEvent) { p.Send(eventMsg{ev: ev}) })
	})
	go retryLoop(func(ctx context.Context) error {
		return ipc.SubscribeCanary(ctx, func(a ipc.CanaryAlert) { p.Send(canaryMsg{a: a}) })
	})
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "tui:", err)
		os.Exit(1)
	}
}
