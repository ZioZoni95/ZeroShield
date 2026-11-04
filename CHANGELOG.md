# Changelog — ZeroShield

Formato: aggiunte, cambiati, corretti. Versioni `0.0.x` = alpha solo-lab.

## [Non rilasciato]

### Aggiunte
- `canary.allow_exe`, sottocomando `zt-shield dropin`, watcher inotify sulle directory dei segreti.
- XDP: doppio tag VLAN e poisoning IPv6. Hook opzionale `lsm/file_truncate` (kernel ≥ 6.2).
- `harden_system.sh --dry-run` e `scripts/test_harden.sh`.
- Test del parser XDP con pacchetti sintetici (`bpf/xdp_prog_test.go`).

### Cambiati
- README riscritto da zero e allineato alla repo: stato verificato per componente, contenuto e
  indipendenza di ogni release, configurazione, test e CI.
- Selezione dei file protetti con tetto per regola e priorità ai file nominati.
- Canary: cartelle ed esche di proprietà dell'utente protetto, scritte con `O_EXCL|O_NOFOLLOW`.
- Il demone root ignora `ZT_SOCKET` e `ZT_CONTROL`.
- Unit systemd con sandboxing aggiuntivo a basso rischio.

### Corretti
- `harden_system.sh` abortiva se il profilo UFW `OpenSSH` non esisteva.
- `setup_fido2.sh` con `sudo` configurava l'utente root.
- Note di release e README dicevano di installare entrambi i `.deb`: dalla v0.0.3 sono alternativi
  (`zeroshield-gui` ha `Conflicts: zeroshield`).
- `test_harden.sh` da utente normale lanciava l'hardening vero via `sudo` (che azzera PATH e
  override): ora salta la sezione prima di chiamarlo, e `harden_system.sh` rifiuta `sudo` quando
  ha gli override di test.

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
