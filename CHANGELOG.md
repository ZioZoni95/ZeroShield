# Changelog — ZeroShield

Formato: aggiunte, cambiati, corretti. Versioni `0.0.x` = alpha solo-lab.

## [Non rilasciato]

### Aggiunte
- `canary.allow_exe`, sottocomando `zt-shield dropin`, watcher inotify sulle directory dei segreti.
- XDP: doppio tag VLAN e poisoning IPv6. Hook opzionale `lsm/file_truncate` (kernel ≥ 6.2).
- `harden_system.sh --dry-run` e `scripts/test_harden.sh`.
- Test del parser XDP con pacchetti sintetici (`bpf/xdp_prog_test.go`).
- GUI: verdetto «Protezione attiva / parziale / non attiva» in cima a Stato; tab Configurazione a
  sezioni (protezione, rete) con file ripiegato e copiabile; vista Eventi raggruppabile per exe;
  pulsanti «copia» sui comandi della Guida; scorciatoie da tastiera 1-7; dialogo di conferma che
  spiega le conseguenze (stop servizio, passaggio a enforce).

- GUI, Radar: ogni sorgente è classificata in *rumore probabile*, *da verificare*, *bloccata* o *nota*
  (tasso sostenuto, volume, rete diversa dalle altre, subnet bloccate da te), con il motivo, i comandi
  copiabili per verificarla (`ip neigh`, `tcpdump`) e «segna come noto». La classificazione è una stima:
  il kernel non distingue richieste normali da risposte avvelenate. Legenda «Come leggerlo» riscritta.
- GUI, Guida a schede (Per iniziare, Le schermate, Glossario, Problemi comuni), con punti di controllo
  dal vivo (demone, hook LSM, XDP, modalità, VPN).

### Cambiati
- **Un solo pacchetto `.deb`**, `zeroshield`, con demone, TUI e GUI. Sostituisce `zeroshield-gui`
  (`Replaces`/`Conflicts`); GTK e WebKit sono `Recommends` (server: `--no-install-recommends`).
  **Migrazione:** chi ha `zeroshield-gui` installa il nuovo `zeroshield_*.deb` e apt lo sostituisce;
  la config in `/etc/zt-shield/shield.yaml` non viene toccata. `make package-gui` non esiste più.
- La CI costruisce e verifica il `.deb` unico nel job GUI (contiene demone, TUI e GUI).
- README riscritto da zero e allineato alla repo: stato verificato per componente, contenuto e
  indipendenza di ogni release, configurazione, test e CI.
- Selezione dei file protetti con tetto per regola e priorità ai file nominati.
- Canary: cartelle ed esche di proprietà dell'utente protetto, scritte con `O_EXCL|O_NOFOLLOW`.
- Il demone root ignora `ZT_SOCKET` e `ZT_CONTROL`.
- Unit systemd con sandboxing aggiuntivo a basso rischio.
- GUI: menu riordinato (Monitoraggio, Protezione, Sistema) con numeri progressivi; una icona per
  pagina; radar con tabella compatta ordinata invece di una scheda per IP; orari in ora locale
  (prima UTC, un'ora indietro rispetto al journal); «Regola più attiva» conta anche gli accessi in
  audit; cambio audit/enforce con etichetta esplicita sulla direzione.

### Corretti
- GUI: «dati fermi da <epoch>s» all'apertura, perché il primo `GetStatus` non registrava l'istante
  di arrivo dello stato.
- GUI: la tab Configurazione, con lettura lenta del file, poteva sovrascrivere la tab aperta dopo.
- GUI: la Configurazione non segnalava che il file e il demone in esecuzione avessero modalità
  diverse (modifica non ancora applicata).

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
