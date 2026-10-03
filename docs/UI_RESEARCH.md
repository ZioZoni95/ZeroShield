# UI_RESEARCH — interfaccia per zt-shield

> **Stato (2026-10-02):** ricerca conclusa e implementata. TUI `cmd/zt-tui`
> (Bubble Tea), GUI `zt-gui` (Wails + WebKitGTK, pacchetto `zeroshield-gui`),
> mock `cmd/zt-mockd`, IPC `pkg/ipc` con testo sanificato (`ipc.SafeText`).
> Il resto del documento è la ricerca originale che ha portato a queste scelte.

Stile target: GNOME (libadwaita) / macOS. Due superfici: TUI da terminale + GUI
desktop. Ricerca web 2026, sintesi sotto. Niente codice implementato in questo
passo, solo decisione documentata.

## 1. TUI — raccomandata: Bubble Tea v2 + Lip Gloss + Bubbles

Fonti: Charm `bubbletea` ~43k stars, `tview` ~14k e manutenzione rallentata
(ultimo commit ~mar 2026, K9s usa fork), GitLab valuta migrazione tview→Tea.

- **Bubble Tea v2** (Elm `Model/Update/View`): un solo punto dove lo stato
  cambia, snapshot test con `tea.TestProgram`, SSH serve via `Wish`,
  output sincronizzato 2026, clipboard nativa. Ecosistema: `Bubbles`
  (liste/tabelle/input), `Lip Gloss` (styling CSS-like), `Huh` (form).
- **tview**: widget pronti e battle-tested, ma imperativo/callback: con stato
  complesso (profili+mappe+log live) diventa fragile. Solo se serve prototipo
  in giorni, non base a lungo termine.
- Scelta: **Bubble Tea v2**. Schermate: stato hook (LSM/XDP), eventi live con
  filtro, profili/mode, `block_subnets`, code di sblocco guidato (exe da
  autorizzare). Binario singolo, zero runtime, gira su SSH senza auth extra.

## 2. GUI — tre strade, una raccomandata per stile GNOME/macOS

| Strada | Pro | Contro | Stile |
|---|---|---|---|
| **Wails** (Go + WebView sistema) | Design illimitato (React/Vue), hot reload, costi bassi se sai web | 30–50MB RAM, avvio 100–200ms, serve skill web | macOS-like facile: replica HIG Apple con CSS |
| **Fyne** (Go puro, OpenGL) | 5–15MB, avvio 30–50ms, single binary, v2.8 con GPU shapes/RichText | Look Material, non nativo GNOME; theming Adwaita manuale | Neutro moderno, non GNOME vero |
| **gotk4 + libadwaita** (binding GTK4) | Vero GNOME HIG: `AdwHeaderBar`, dark/high-contrast gratis, HIG ufficiale | CGo, packaging pesante (Flatpak/SDK), tray assente, API instabile a tratti | GNOME nativo perfetto |

Raccomandazione doppia, in fasi:
- **Fase 1 (stile macOS, multipiattaforma mentale): Wails.** UI curata tipo
  System Settings macOS: sidebar (Stato, Eventi, Regole, Rete, Identità),
  toggle audit/enforce, grafici eventi. Web stack = iterazione rapida.
- **Fase 2 (GNOME nativo, se serve integrazione): gotk4-adwaita** seguendo
  `developer.gnome.org/hig` (header bar, `AdwPreferencesWindow`, toast, dark).
  Solo se accetti costo packaging Flatpak.

## 3. Nodo critico GNOME: niente tray

GNOME 40+ ha rimosso la tray; AppIndicator è obsoleto, GTK4 non ha StatusIcon.
Via ufficiale: **Background Portal + Notifiche** (icona in quick settings, non
nel pannello). Alternative: estensione Shell di terze parti (non garantita) o
implementazione SNI pura via D-Bus stile Fyne (senza Gtk, solo
`org.kde.StatusNotifierItem`). Decisione: niente icona persistente; notifiche
desktop sugli eventi bloccati + finestra principale. Su KDE/XFCE la stessa base
D-Bus può esporre icona senza costo extra.

## 4. Architettura obbligata (sicurezza prima del pixel)

Il demone gira root (eBPF/XDP/LSM). La UI **mai root**:

- demone root espone socket Unix `/run/zt-shield/api.sock` sola lettura per
  stato/eventi + endpoint scrittura (cambio mode, rescan) via **polkit**:
  solo admin autorizza le azioni privilegiate, la UI gira come utente.
- TUI/GUI = client thin: leggono eventi (oggi stdout/stderr, domani socket
  JSON), non toccano mappe eBPF direttamente.
- Azioni pericolose (passare a `enforce`, modificare `block_subnets`) con
  conferma esplicita + dry-run `audit` di 24h (come da README: prima audit,
  poi enforce).
- Log sensibili (`exe`, path) restano locali, mai telemetria.

## 5. Piano proposto (quando si implementa, non ora)

1. IPC: socket Unix + protocollo JSON eventi/stato (sostituisce parse stdout).
2. TUI Bubble Tea: `zt-shield tui` — stato, eventi live, toggle mode via polkit.
3. GUI Wails stile macOS: dashboard + notifiche.
4. Opzionale GNOME nativo gotk4-adwaita + portal background.
5. Packaging: `.deb` + Flatpak manifest, icone/screenshot HIG.

## 6. Fonti

- Charm Bubble Tea / Bubbles / Lip Gloss (GitHub, 40k+ stars, v2 2026).
- Confronto TUI 2026 (tview rolling, Textual, Ratatui, Ink/OpenTUI).
- Proposta GitLab migrazione tview→Bubbletea (rischi/mitigazioni).
- Fyne vs Wails (perf: 5–15MB vs 30–50MB), Fyne v2.8 2026.
- GNOME HIG + libadwaita, gotk4/gotk4-adwaita, thread AppIndicator/GTK4.
