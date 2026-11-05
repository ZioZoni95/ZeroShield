# Changelog — ZeroShield

Formato: aggiunte, cambiati, corretti. Versioni `0.0.x` = alpha solo-lab.

## [Non rilasciato]

### Aggiunte
- **Modalità per singola protezione**: ogni regola può stare in `audit` o `enforce` indipendentemente dalle altre (chiave `mode` nella regola,
  oppure `rule_modes` per quelle predefinite). Nel kernel è una nuova mappa `rule_modes` (0 = eredita la modalità globale, 1 = audit,
  2 = enforce): senza voci il comportamento è identico a prima. `ipc.RuleSummary` riporta `mode` e `deny_write`; `ipc.Status` la `version` del demone.
- **«Proteggi un mio file»** nella scheda Regole: selettore di file/cartelle (anche schemi come `Documents/*.kdbx`), anteprima di quanti file
  protegge, avvisi (troppo largo, troppi file, btrfs/overlayfs dove la protezione non funziona), scelta dei programmi autorizzati con le stesse
  verifiche di sicurezza, nome, modalità e blocco delle scritture. Modifica ed eliminazione dalla stessa scheda.
- **Togliere programmi** dalle liste delle protezioni predefinite (`remove_allow`).
- **Nuova pagina Stato**: una frase e un solo pulsante con la prossima azione, tre tessere (Segreti, Rete, Attività), lista «Da fare»,
  ultimi eventi in italiano, dettagli tecnici ripiegati; avviso se demone e finestra hanno versioni diverse.
- Config: `rule_modes`, `remove_allow` e `mode` per regola (additivi, formato esistente invariato); massimo 255 regole; i nomi delle regole non
  possono contenere a-capo o caratteri di controllo (finiscono nei log).

### Cambiati
- I riquadri «Dettagli» della scheda Regole restano aperti quando la pagina si ridisegna.

## [0.0.4] — 2026-11-05

Prima release con un **unico pacchetto** `.deb` (demone, TUI, GUI e icona nella barra). Alpha: solo lab.
Aggiornamento dal 0.0.3: `apt` sostituisce `zeroshield-gui`; nessuna modifica al formato del config
(le nuove chiavi `allow_extra`, `disable_rules`, `enable_groups` sono facoltative).

### Aggiunte
- GUI: popup «Novità» al primo avvio dopo ogni aggiornamento (una sola volta per versione, si riapre cliccando la versione in fondo alla barra laterale). Il testo sta in `zt-gui/frontend/src/whatsnew.js`: a ogni release si aggiunge la voce, e un test fallisce se il file `VERSION` non ne ha una.
- Versione: il file `VERSION` (0.0.4) e' la prossima da rilasciare; le build locali diventano `0.0.4~dev+<commit>` invece di `0.0.0~dev+...`. La GUI la mostra sempre in fondo alla barra laterale; `zt-gui -version` la stampa.
- GUI, scheda **Regole** riscritta per chi non conosce il progetto: percorso guidato in 3 passi (osserva, autorizza, blocca)
  con l'indicatore «sei pronto per Enforce?», interruttori per i gruppi di segreti, catalogo di programmi noti
  (k3d, helm, k9s, oh-my-posh, kubectx, stern, flux, argocd, kind, minikube, skaffold, lazydocker, gh, glab),
  «Autorizza i pronti», elenco dei programmi visti in audit con il motivo quando non si possono autorizzare,
  «Rendi affidabile» (copia di root in `/usr/local/bin` per i binari che l'utente può modificare) e barra «Applica»
  con conferma. Nessun YAML da scrivere.
- Config: `allow_extra`, `disable_rules`, `enable_groups` (additivi, formato invariato).
- `zt-shield config-apply FILE` (root): valida con il parser del demone, copia di sicurezza, sostituzione atomica,
  riavvio e ripristino automatico se il servizio non riparte. La GUI lo chiama via pkexec.
- `pkg/rules`: verifica «affidabile» e giudizio sui programmi condivisi da demone, GUI e TUI.
- `zt-tray`: icona nella barra di sistema (verde/gialla/rossa), servizio utente systemd (`zeroshield-tray.service`: parte con la sessione, riparte da solo, il pacchetto lo riavvia dopo un aggiornamento), notifiche di demone caduto/tornato e di blocchi/canary anche a GUI chiusa (con la GUI aperta se ne occupa lei, niente doppioni). Nel `.deb` unico; `gnome-shell-extension-appindicator` come Recommends.
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

- `scripts/configure_service.sh <utente> [profilo]`, incluso nel pacchetto: scrive `user:` e `profile:` nel
  config (con copia di sicurezza, senza perdere i commenti), parte sempre in `audit` e avvia il servizio
  del pacchetto, senza copiare binari né scrivere un'altra unit. La GUI lo usa al posto di
  `install_service.sh` quando la unit del pacchetto esiste (`install_service.sh` resta per chi compila dai
  sorgenti). Test con comandi finti in `scripts/test_configure.sh`.
- GUI: sezione demo unica e con comandi copiabili (mock, GUI collegata al mock, arresto), uguale al primo
  avvio, a demone spento e nella Guida.

### Cambiati
- **Un solo pacchetto `.deb`**, `zeroshield`, con demone, TUI e GUI. Sostituisce `zeroshield-gui`
  (`Replaces`/`Conflicts`); GTK e WebKit sono `Recommends` (server: `--no-install-recommends`).
  **Migrazione:** chi ha `zeroshield-gui` installa il nuovo `zeroshield_*.deb` e apt lo sostituisce;
  la config in `/etc/zt-shield/shield.yaml` non viene toccata. `make package-gui` non esiste più.
- Controlli preliminari della GUI: il vecchio «Script install_service.sh» (assente dal `.deb`, quindi rosso
  a torto sulle macchine installate dal pacchetto) è sostituito da «Servizio zt-shield (installato o
  installabile)» e «Utente protetto (`user:`) nel config».
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
