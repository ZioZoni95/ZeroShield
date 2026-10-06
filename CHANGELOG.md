# Changelog — ZeroShield

Formato: aggiunte, cambiati, corretti. Versioni `0.0.x` = alpha solo-lab.

## [0.0.3] — 2026-10-06

### Aggiunte
- Pacchetto `zeroshield-gui` autonomo: demone, TUI, GUI, servizio, script e
  docs in un solo `.deb` (incompatibile con `zeroshield` puro).
- Wizard primo avvio con utente + profilo e installazione mirata (GUI).
- Preflight prerequisiti in GUI e TUI prima di installare.
- Canale di controllo privilegiato (peer-cred + polkit): ping/rescan per CLI/UI.

### Cambiati
- Offline contestuale per tab (setup solo su Stato) + badge DISATTIVO.
- README: installazione o-l'uno-o-l'altro, limiti riscritti, diagrammi mermaid.

## [0.0.2] — 2026-10-06

### Aggiunte
- VPN kill-switch nftables + auto-VPN su BSSID + helper ProtonVPN.
- Stato VPN nelle UI, porte in ascolto (netstat) in tab Rete.
- TUI: filtro eventi, contatori, blast-radius, auto-suggest anti-bypass.
- GUI PRO: sidebar a sezioni, dashboard sessione, ricerca, radar canvas.

## [0.0.1] — 2026-10-06

### Aggiunte
- Prima pre-release ⚠️ ALPHA: demone eBPF (XDP + LSM), canary fanotify,
  TUI/GUI/mock, IPC, pacchetti `.deb`, CI + release workflow.
- Verdetto onesto: XDP e canary su kernel reale; LSM mai agganciato.
