# Changelog — ZeroShield

Formato: aggiunte, cambiati, corretti. Versioni `0.0.x` = alpha solo-lab.

## [Non rilasciato]

- **Release**: la pagina di ogni tag mostra le «Novità» prese dalla sezione del `CHANGELOG.md` per quella versione (prima era un testo fisso, fermo alla 0.0.9). Nessuna modifica al prodotto.

## [0.0.17] — 2026-11-06

- **XDP, IPv6 con extension header**: prima un pacchetto con una extension header passava senza controllo (aggirabile di proposito). Ora si attraversano fino a 6 header noti (hop-by-hop, routing, destination options, fragment solo se primo frammento, AH) fino all'UDP; ESP, header sconosciute, catene più lunghe e frammenti non-primi passano. Test `TestXDPIPv6ExtensionHeaders` (14 casi, sul vero programma, in CI come root). **Non ancora visto con il verifier del kernel in questa sessione: lo esegue la CI (`zt-probe`).**
- **Watcher**: test di stress (300 sostituzioni atomiche in 2 s → 3 rescan, e sempre un rescan dopo l'ultima).
- **Docs**: `docs/COLLAUDO_HARDENING.md`, procedura per VM (rename ZS-005, `deny_write`, truncate, frammenti, IPv6, fd ereditati).

## [0.0.16] — 2026-11-06

Dalla seconda revisione statica del codice (commit `8a0dd93`), verificata sul sorgente.

- **ZS-005 (medio) — `inode_rename`**: se il sorgente era protetto e il processo autorizzato per la sua regola, l'hook usciva senza controllare la destinazione, che può appartenere a un'altra regola. Ora il sorgente nega subito se non autorizzato; se autorizzato si controlla comunque la destinazione, con la **sua** regola. Compila e passa i test Go; **non provato a runtime su un kernel** (gli hook LSM non si eseguono con `BPF_PROG_TEST_RUN`): resta da collaudare (vedi `PUNTI_APERTI.md`).
- **Mappe eBPF**: gli errori di scrittura (`Put`) erano solo loggati e il demone annunciava comunque «File protetti: N». Ora `Sync` restituisce i conteggi davvero scritti e logga `⚠️ mappe eBPF incomplete … la protezione è parziale`. Non coperto da un test unitario (servono privilegi BPF).

## [0.0.15] — 2026-11-06

- **Falsi blocchi**: `seahorse` («Password e chiavi», lanciato anche dalla ricerca del menu applicazioni) e `/usr/libexec/gcr-ssh-agent` entrano nella lista di base di `ssh-keys`. Visto il 2026-11-06: in enforce venivano negati mentre leggevano `~/.ssh/id_*` (log: `Error reading file … to check for SSH key`). Compromesso dichiarato: due programmi di sistema di root in più possono leggere le chiavi. Se mancano (KDE, server) nessun avviso «non risolto».
- **Eventi**: il demone ricorda gli ultimi 200 eventi e alert canary e li rilegge a chi si collega (campo `replay`, compatibile con i client vecchi). Prima la GUI aperta dopo una notifica non mostrava il blocco. Tray: i replay non notificano; GUI: scarta i replay già presenti. Test di storico, limite e assenza di doppioni.

## [0.0.14] — 2026-11-06

- **Catalogo**: aggiunto `gcr-ssh-agent` (agente SSH del portachiavi di GNOME, `/usr/libexec/gcr-ssh-agent`) per la regola `ssh-keys`. In enforce senza questa autorizzazione l'agente non legge le chiavi (`couldn't read file … Permission denied`, `ssh-add -l` vuoto), mentre `ssh` da solo continua a funzionare perché è già in lista. Visto sul PC il 2026-11-06. Dopo Applica: `systemctl --user restart gcr-ssh-agent`.

## [0.0.21] — 2026-11-06

- **Postura del sistema** (`internal/posture`): il demone legge `kernel.yama.ptrace_scope` e `kernel.io_uring_disabled`, due impostazioni del kernel che non dipendono da ZeroShield ma ne aggirano i controlli se restano aperte (ptrace: un programma dello stesso utente legge la memoria di `ssh`; io_uring: i thread di lavoro non passano dall'hook dei file). Sono limiti già dichiarati: ora sono **visibili**. Un avviso nel journal all'avvio, il campo `posture` nello stato IPC e, nella GUI, due voci nella lista «Da fare» con il comando per chiuderli (sysctl persistente in `/etc/sysctl.d/`). **Non cambia nulla da solo.**
- Limiti che **restano** (strutturali o da provare su un kernel reale): fd già aperti/ereditati/`SCM_RIGHTS` (servirebbe `file_permission` su ogni lettura, con costo e rischio di falsi blocchi), IPv6 oltre 6 extension header o con ESP, btrfs/overlayfs (la chiave dev+inode non coincide; già con avviso). Vedi `docs/PUNTI_APERTI.md`.

## [0.0.20] — 2026-11-06

- **Audit delle connessioni in uscita** (`docs/EGRESS.md`): nuovo hook `lsm/socket_connect`, **solo registro, non blocca mai**. Il kernel ricorda per 60 s i processi che hanno letto un segreto (mappa `touched`, scritta da `check_access`); a ogni `connect()` IPv4/IPv6 non loopback di uno di essi scrive un evento in un ring buffer dedicato (`egress_logs`, 64 byte per evento). Il demone segnala la **prima volta** di ogni coppia (programma, destinazione), con tetto di 20/s, e la classifica `lan`/`internet`. Evento IPC `action: "egress"` con `dest` e `scope`; GUI: tag «uscita», filtro dedicato, Internet in evidenza; TUI: riga «📤 USCITA».
- Hook **opzionale**: un errore di caricamento o di aggancio non ferma lo scudo. Le mappe `touched`/`egress_logs` sono condivise con il resto tramite `MapReplacements`.
- Test: decodifica del layout (v4, v6, payload corto), classificazione dell'ambito, «solo la prima volta» con tetto, evento IPC, e 4 controlli nel browser. **Non provato su un kernel reale**: compila e lo verifica la CI; procedura in `docs/COLLAUDO_HARDENING.md` (sezione 7).

## [0.0.19] — 2026-11-06

- **Pagina Funzioni**: schede per **hardening del sistema** (profilo a scelta; l'anteprima è `harden_system.sh <profilo> --dry-run` senza privilegi, mostrata prima di ogni applicazione; annullare non cambia nulla), **kill-switch VPN** (acceso/spento con endpoint e tunnel letti dal demone, solo se `vpn:` è nel config; conferma che avvisa che la rete si ferma se il tunnel cade) e **chiave FIDO2** (solo istruzioni: è interattiva).
- `pkg/svc`: `HardenPreview/HardenApply/KillSwitchOn/KillSwitchOff`; argomenti validati (profilo noto, endpoint `IPv4:porta` o `[IPv6]:porta` mai un nome host, interfaccia, CIDR) e passati uno per uno, mai in una stringa di shell; azioni sul sistema via `pkexec`. Test di validazione, anteprima (comando e troncamento) e rifiuto prima di eseguire.
- **Non provato su un sistema vero**: gli script restano `--dry-run` + comandi finti, e il kill-switch solo in un network namespace. Vale per i pulsanti.

## [0.0.18] — 2026-11-06

- **Pagina «Funzioni»** (tasto 4; Regole, Rete, Configurazione e Guida scalano a 5-8): una scheda con pulsante per ogni funzione — protezione dei segreti (solo osserva/blocca), filtro di rete (`block_poisoning`), **anti-ransomware (canary)**, avvio all'accensione, icona nella barra — più il monitor VPN solo in lettura. Ogni scheda mostra lo stato **reale** del demone, non solo quello del file.
- **Canary dalla GUI**: nuovo campo `canary` nello stato (`enabled`, `active`, `dirs`): «voluto ma non partito» è un avviso, non un finto «attivo». Le cartelle si scelgono tra quelle comuni che esistono nella home. La scelta finisce nel blocco gestito del config (`block_poisoning: false` solo se spento, `canary:` solo se acceso); se le stesse chiavi sono scritte a mano la GUI non le tocca.
- **`config-apply` e il drop-in systemd**: con il canary acceso crea `/etc/systemd/system/zt-shield.service.d/canary.conf` (`ReadWritePaths=` solo per le cartelle delle esche, perché la unit ha `ProtectHome=read-only`) e fa `daemon-reload`; spento lo toglie; un drop-in scritto a mano non si tocca; dopo un ripristino il drop-in segue il config. Prima il canary andava abilitato a mano con `zt-shield dropin | sudo install …`.
- **Icona nella barra** attivabile da GUI (`systemctl --user enable/disable --now`, senza password). `ApplyRules` conserva ora anche `block_poisoning` e `canary`.
- Test: scrittura/lettura della scelta, chiavi manuali, modello, drop-in, e 13 controlli nel browser per la pagina.

## [0.0.17] — 2026-11-06

- **XDP, IPv6 con extension header**: prima un pacchetto con una extension header passava senza controllo (aggirabile di proposito). Ora si attraversano fino a 6 header noti (hop-by-hop, routing, destination options, fragment solo se primo frammento, AH) fino all'UDP; ESP, header sconosciute, catene più lunghe e frammenti non-primi passano. Test `TestXDPIPv6ExtensionHeaders` (14 casi, sul vero programma, in CI come root). **Non ancora visto con il verifier del kernel in questa sessione: lo esegue la CI (`zt-probe`).**
- **Watcher**: test di stress (300 sostituzioni atomiche in 2 s → 3 rescan, e sempre un rescan dopo l'ultima).
- **Docs**: `docs/COLLAUDO_HARDENING.md`, procedura per VM (rename ZS-005, `deny_write`, truncate, frammenti, IPv6, fd ereditati).

## [0.0.16] — 2026-11-06

Dalla seconda revisione statica del codice (commit `8a0dd93`), verificata sul sorgente.

- **ZS-005 (medio) — `inode_rename`**: se il sorgente era protetto e il processo autorizzato per la sua regola, l'hook usciva senza controllare la destinazione, che può appartenere a un'altra regola. Ora il sorgente nega subito se non autorizzato; se autorizzato si controlla comunque la destinazione, con la **sua** regola. Compila e passa i test Go; **non provato a runtime su un kernel** (gli hook LSM non si eseguono con `BPF_PROG_TEST_RUN`): resta da collaudare (vedi `PUNTI_APERTI.md`).
- **Mappe eBPF**: gli errori di scrittura (`Put`) erano solo loggati e il demone annunciava comunque «File protetti: N». Ora `Sync` restituisce i conteggi davvero scritti e logga `⚠️ mappe eBPF incomplete … la protezione è parziale`. Non coperto da un test unitario (servono privilegi BPF).

## [0.0.15] — 2026-11-06

- **Falsi blocchi**: `seahorse` («Password e chiavi», lanciato anche dalla ricerca del menu applicazioni) e `/usr/libexec/gcr-ssh-agent` entrano nella lista di base di `ssh-keys`. Visto il 2026-11-06: in enforce venivano negati mentre leggevano `~/.ssh/id_*` (log: `Error reading file … to check for SSH key`). Compromesso dichiarato: due programmi di sistema di root in più possono leggere le chiavi. Se mancano (KDE, server) nessun avviso «non risolto».
- **Eventi**: il demone ricorda gli ultimi 200 eventi e alert canary e li rilegge a chi si collega (campo `replay`, compatibile con i client vecchi). Prima la GUI aperta dopo una notifica non mostrava il blocco. Tray: i replay non notificano; GUI: scarta i replay già presenti. Test di storico, limite e assenza di doppioni.

## [0.0.14] — 2026-11-06

- **Catalogo**: aggiunto `gcr-ssh-agent` (agente SSH del portachiavi di GNOME, `/usr/libexec/gcr-ssh-agent`) per la regola `ssh-keys`. In enforce senza questa autorizzazione l'agente non legge le chiavi (`couldn't read file … Permission denied`, `ssh-add -l` vuoto), mentre `ssh` da solo continua a funzionare perché è già in lista. Visto sul PC il 2026-11-06. Dopo Applica: `systemctl --user restart gcr-ssh-agent`.

## [0.0.13] — 2026-11-05

- **GUI**: i riquadri a tendina (`<details>`) non si richiudono più da soli a ogni aggiornamento dello stato, in nessuna schermata. Si ricorda lo stato per schermata, titolo e posizione. Test in Guida e Configurazione.

## [0.0.12] — 2026-11-05

Hardening dopo una revisione statica del codice (commit `633bdec`); ogni punto è stato verificato sul sorgente prima di correggerlo.

- **ZS-001 (alto) — bypass XDP con frammentazione IPv4**: la maschera `0x3FFF` includeva il flag MF e saltava il primo frammento UDP; ora `0x1FFF` (solo l'offset). Test `TestXDPFragments` (esegue il vero programma con `BPF_PROG_TEST_RUN`, in CI come root).
- **ZS-004 — chiamata polkit**: `CheckAuthorization` riceveva 7 argomenti con il subject di tipo errato e falliva sempre. Ora 5 argomenti, firma `(sa{sv}) s a{ss} u s`; provata anche con il polkit vero del sistema (prima: «Type of message … does not match expected type»).
- **ZS-003 — finestra di rescan**: `watchDebounce` 400→100 ms e `watchMinGap` 3→1 s. Test di latenza (< 500 ms a riposo).
- **`deny_write`**: nessun cambio di comportamento; corretti i testi (commento in `zerotrust.c`, README, config d'esempio, GUI): chi è in lista scrive, gli altri (root compreso) no.
- **GUI**: in Regole, se la copia protetta è autorizzata ma il terminale lancia un altro percorso, compare l'avviso con l'alias suggerito.
- **GUI adattiva**: contenuto fluido (non più 920 px), barra laterale a sole icone sotto 900 px, radar a risoluzione doppia e ridimensionabile, larghezza minima 480 px; 28 controlli di layout nel browser (4 larghezze × 7 schermate).

## [0.0.11] — 2026-11-05

- **Avvio all'accensione**: interruttore in Configurazione (`systemctl enable/disable zt-shield` via pkexec, senza avviare/fermare adesso; spegnerlo chiede conferma).
- Il pacchetto, se `/etc/zt-shield/shield.yaml` ha già `user:`, abilita il demone all'avvio e lo riavvia (`try-restart`) dopo l'aggiornamento. Su una prima installazione non fa nulla (senza `user:` il demone si fermerebbe).
- Icona nella barra: reimpostata ogni 30 s anche a stato invariato (restava invisibile dopo due riavvii ravvicinati).
- Regole → guida: in enforce anche il passo 3 «Blocca» risulta completato (prima restava «in corso») e la guida si aggiorna al cambio di modalità.

## [0.0.10] — 2026-11-05

- Icona nella barra: **blu** in enforce con hook attivo (prima verde), arancione in audit. Dopo `apt install` riavvia l'icona: `systemctl --user restart zeroshield-tray`.

## [0.0.9] — 2026-11-05

Prima release dopo la 0.0.4. Raccoglie anche le versioni interne 0.0.5, 0.0.6, 0.0.7 e 0.0.8, che non sono state pubblicate: le loro novità sono qui sotto e il
popup «Novità» le mostra tutte insieme a chi aggiorna dalla 0.0.4. **Alpha: solo lab.**

Aggiornando dalla 0.0.4: nessuna modifica al formato del config (le chiavi nuove sono facoltative). Il kernel e il demone vanno aggiornati insieme (l'evento del kernel
è cambiato): dopo `apt install` riavvia `zt-shield` e l'icona (`systemctl --user restart zeroshield-tray`), poi riapri la GUI.

### Corretti (difetti emersi dal collaudo del 2026-11-05)
- **`exe=` vuoto negli eventi di blocco**: l'evento del kernel ora porta (dev, inode) del binario (`audit_event` 56 byte invece di 40) e il demone ne ricava il percorso
  con un indice delle cartelle dei programmi quando `/proc/<pid>/exe` non c'è più; tra più nomi dello stesso file (coreutils in Rust è un solo binario con decine di nomi) sceglie quello con cui è stato lanciato il processo. Se nemmeno l'indice lo conosce il log scrive `exe=(sconosciuto, inode N)`.
- **Hard link**: nuovo hook `lsm/inode_link`: creare un secondo nome di un file protetto da un programma non autorizzato è negato in enforce (prima l'alias restava
  leggibile se il nome originale veniva cancellato da un programma autorizzato e il rescan toglieva l'inode dalla mappa).
- **Radar**: si rilegge ogni 5 secondi (prima a ogni rescan, 30 s) e mostra anche le sorgenti **IPv6** (mappa `xdp_stats6`), raggruppate per /64; IPv4 e IPv6 hanno
  ciascuna la propria «rete delle altre sorgenti».
- **Aggancio del filtro di rete**: si riallinea subito a ogni evento di rete (netlink) oltre che ogni 2 secondi.
- **Indicizzatore di GNOME**: la procedura «Proteggi un mio file» lo suggerisce (un clic) quando è presente e affidabile.

### Aggiunte
- **Il filtro di rete segue le interfacce a caldo** (`internal/xdp/manager.go`): ogni 2 secondi il demone riallinea l'aggancio XDP. Un adattatore USB collegato,
  il Wi-Fi acceso o un'interfaccia ricollegata (indice nuovo) vengono filtrati senza riavviare; una scomparsa rilascia il link. In **automatico** (`interface` vuota)
  il filtro copre ora **tutte le interfacce fisiche accese** (cavo, USB, Wi-Fi) più la rotta predefinita, anche se è un tunnel, invece della sola rotta in uso all'avvio:
  è più protettivo, e chi vuole l'elenco esatto sceglie «Scelgo io». In manuale le interfacce nominate si agganciano appena esistono. `block_subnets` si carica sempre
  (prima solo se XDP era attivo all'avvio). Test con interfacce finte (collegamento, scollegamento, indice cambiato, aggancio fallito con un solo avviso).
- **Scelta delle interfacce da filtrare** (scheda Rete): elenco con tipo (cavo, USB, Wi-Fi, VPN, bridge, container, loopback) e stato «filtrata / non filtrata»,
  modalità *Automatica* (la rete in uso al riavvio) o *Scelgo io* (fisiche consigliate preselezionate, anche se spente), virtuali ripiegate con l'avviso sui rischi,
  bozza + *Applica* con riavvio del servizio. Il demone riporta `interfaces` e `iface_auto` nello stato; `interface` nel config è validata (nomi e doppioni).
  Il log avvisa una sola volta e solo per interfacce fisiche o VPN accese ma non filtrate (prima ~15 righe a ogni avvio per veth e bridge).
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

### Collaudo
- **Radar con volume alto, visto dal vivo** (2026-11-05): con `lo` aggiunto alle interfacce filtrate, 250 pacchetti UDP verso `127.0.0.1:5355` sono stati contati dal kernel
  (`127.0.0.1` = 250 drop nello stato del demone) e il radar li classifica «da verificare» oltre la soglia di 100. Il radar si aggiorna a ogni rescan (30 s), non in tempo reale.
  Aggiungere e togliere `lo` con `config-apply` via `pkexec` ha funzionato (backup, riavvio, filtro agganciato a `lo`).
- Primo blocco reale degli hook LSM, visto su un PC con kernel 7.0 (file finto): `file_open`, rinomina, cancellazione e troncamento negati, identità del
  binario rispettata, modalità per regola e `config-apply` via `pkexec` funzionanti. Dettagli e limiti in `docs/COLLAUDO_LSM_2026-11-05.md`.

### Corretti
- L'unit `zeroshield-tray.service` aveva `NoNewPrivileges=yes`: la GUI aperta dall'icona lo ereditava e `pkexec` rispondeva «must be setuid root», quindi Applica, Installa e il cambio modalità non chiedevano la password. Tolto, con un test che impedisce di rimetterlo. **Riguarda anche il .deb 0.0.4**: chi lo ha installato deve aggiornare e riavviare l'icona (`systemctl --user restart zeroshield-tray`) e riaprire la GUI.

### Cambiati
- I riquadri «Dettagli» della scheda Regole restano aperti quando la pagina si ridisegna.

## [0.0.4] — 2026-11-05

Prima release con un **unico pacchetto** `.deb` (demone, TUI, GUI e icona nella barra). Alpha: solo lab.
Aggiornamento dal 0.0.3: `apt` sostituisce `zeroshield-gui`; nessuna modifica al formato del config
(le nuove chiavi `allow_extra`, `disable_rules`, `enable_groups` sono facoltative).

### Aggiunte
- GUI: popup «Novità» al primo avvio dopo ogni aggiornamento (una sola volta per versione; chi salta una versione vede le novità di tutte quelle di mezzo, si riapre cliccando la versione in fondo alla barra laterale). Il testo sta in `zt-gui/frontend/src/whatsnew.js`: a ogni release si aggiunge la voce, e un test fallisce se il file `VERSION` non ne ha una.
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
