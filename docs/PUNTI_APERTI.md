# Punti aperti — ZeroShield

Aggiornato: 2026-10-26. Storico delle correzioni in [`FIX_APPLICATI.md`](FIX_APPLICATI.md),
esiti dei test reali in [`TEST_SANDBOX.md`](TEST_SANDBOX.md),
piano feature unificato in [`ROADMAP.md`](ROADMAP.md).

## Stato in una riga

Compila, CI verde (lint, test `-race`, test degli script, eBPF, GUI nel browser, sicurezza,
pacchetti `.deb`). **XDP, canary e hook LSM collaudati su un kernel reale** (un PC, file finto, 2026-11-05:
[`COLLAUDO_LSM_2026-11-05.md`](COLLAUDO_LSM_2026-11-05.md)); restano da provare `file_truncate`, `deny_write`, le protezioni predefinite con i
programmi veri e una VM isolata. Lo stack
VPN è provato solo in un network namespace e con comandi finti.

| Componente | Stato |
|---|---|
| XDP anti-poisoning + radar | ✅ kernel reale (drop verificato su loopback) |
| Canary fanotify | ✅ kernel reale (esca, massa, kill in enforce) |
| Hook LSM (`file_open`, `unlink`, `rename`, troncamento) | 🟢 visti negare su un kernel reale (un PC, file finto) · 🟡 `file_truncate` e `deny_write` mai provati |
| TUI / GUI / mock / IPC | ✅ GUI vera contro il demone reale come utente protetto + 152 controlli nel browser contro un demone simulato; socket provato con utenti reali |
| Demone `zt-shield` end-to-end | 🟢 gira su un PC con BPF LSM (installato dal `.deb`, 2026-11-05): XDP, hook, canary, IPC con GUI e icona, `config-apply`; mai in una VM isolata né per giorni di fila |
| Pacchetti `.deb` | ✅ costruiti e installati su un PC (aggiornamento 0.0.4 → 0.0.6 con `apt`) · release v0.0.1–v0.0.4 e v0.0.9 pubblicate (pre-release; 0.0.5–0.0.8 sono versioni interne) · pacchetto unico dalla v0.0.4 |
| Kill-switch VPN | 🟡 provato in un network namespace (54 controlli); mai su rete reale |
| Auto-VPN + helper Proton | 🟡 provati con comandi finti; mai con NetworkManager o Proton veri |
| `harden_system.sh` | 🟡 `--dry-run` + 21 controlli con comandi finti; mai su un sistema vero |
| `setup_fido2.sh` | ⚠️ mai eseguito (solo shellcheck) |
| Hook `lsm/file_truncate` (≥ 6.2), inotify sulle dir protette | 🟡 inotify testato; `file_truncate` non confermato: nel journal compare solo «Hook LSM 'file_open' attivo», da verificare con `zt-probe` come root |

## Origine e scopo

Progetto personale nato dopo uno zero-day con ransomware, attacco ad Active
Directory e GitLab, furto di token, ingresso da VM Windows Server 2013.
La bonifica enterprise è compito di altri: qui si protegge solo la postazione
personale. Lezione tradotta: i token piatti rubati fanno il disastro, quindi
priorità a segreti locali, token brevi, firma FIDO2.

**È:** anti-furto-segreti locali (LSM dev+inode), anti-poisoning (XDP +
resolved/UFW), esche anti-ransomware (fanotify), monitor e kill-switch VPN, hardening, FIDO2.
**Non è:** antivirus, firewall completo (niente egress per processo), EDR, backup.
Root locale, keylogger e disco non cifrato restano fuori scopo.

## Da fare — collaudo

- [ ] **VM Ubuntu 24.04 con `lsm=...,bpf`**: `make probe`, poi collaudo completo di
  [`TESTING_LAB.md`](TESTING_LAB.md) in `enforce`. Il blocco di base è già stato visto su un PC (vedi sopra): in VM servono le protezioni
  predefinite con i programmi veri (`ssh`, `kubectl`, `git`), `deny_write`, `file_truncate`, l'aggiornamento di un binario autorizzato (inode che cambia)
  e giorni di uso continuo in `audit` prima di `enforce`.
- [x] ~~**`exe=` vuoto negli eventi `[BLOCCATO]`**~~ — corretto in 0.0.9: il kernel porta nell'evento (dev, inode) del binario e il demone ne ricava il percorso
  da un indice delle cartelle dei programmi (`internal/lsm/exeindex.go`) quando `/proc/<pid>/exe` non c'è più; se nemmeno l'indice lo conosce
  (una copia in `/tmp`) il log dice `exe=(sconosciuto, inode N)`. **Visto sul PC (2026-11-05)**: `cat` e `ln` negati con il percorso nel log; per i binari multi-call (coreutils in Rust) si sceglie il nome uguale a `comm`.
- [x] ~~**Indicizzatori e programmi di sistema**~~ — nella procedura «Proteggi un mio file» compare il suggerimento «Indicizzatore di GNOME (localsearch)», che aggiunge
  in un clic i suoi percorsi (solo se presenti e di root). Gli altri programmi in background (backup) restano da autorizzare uno a uno.
- [x] ~~**Creazione di hard link non bloccata**~~ — nuovo hook `lsm/inode_link` (0.0.9): `ln` su un file protetto da un programma non autorizzato è negato in
  enforce. Motivo: se il nome originale spariva (un programma autorizzato lo cancellava), il rescan toglieva l'inode dalla mappa e l'alias restava
  leggibile. **Da verificare sul PC** (`ln` su `~/zs-test/segreto.txt` deve dare *Permission denied*).
- [x] ~~**Avviare il demone end-to-end** con `bpf` attivo~~ — fatto il 2026-11-05 su un PC (IPC con GUI e icona, porte in ascolto, hook, canary). Resta da rifare in una VM isolata e con VPN reale.
- [ ] **VPN in VM con snapshot**, con un tunnel vero: kill-switch (tunnel killato → `tcpdump`
  muto 60 s), `portal`, auto-VPN con NetworkManager, helper Proton. Procedura in
  [`VPN_SETUP.md`](VPN_SETUP.md).
- [ ] **Socket IPC con GUI e TUI vere da DUE utenti diversi.** Provato con l'utente protetto (GUI e icona leggono il demone vero);
  manca la prova con un secondo utente locale che deve ricevere *permission denied* (il controllo è già provato con un client minimale).
- [x] ~~**Watchdog systemd** stabile oltre 2 minuti~~ — il demone è rimasto attivo 9 minuti con `WatchdogSec=30` senza riavvii (poi riavviato di proposito); `NRestarts=0`. Da ripetere per ore/giorni.
- [ ] **Percorsi dei browser** in `audit` (deb/snap; Flatpak non è coperto) prima di `public-wifi` in enforce.
- [ ] **`zt-probe` su un kernel con BPF LSM**: deve accettare anche `zt_file_truncate` (nuovo, mai caricato).
- [ ] **Unit systemd**: provare `ProtectSystem=strict` e `CapabilityBoundingSet` in VM. Le direttive a basso rischio già presenti girano su un PC vero (il demone parte e resta attivo).
- [ ] **Script** `harden_system.sh` (prima con `--dry-run`) e `setup_fido2.sh` in VM con snapshot.
- [ ] **Test furto-token** in VM isolata: infostealer simulato, reverse shell host-only.
- [ ] **Pentest LAN** da macchina esterna ([`TESTING.md`](TESTING.md), Test 5).

## Da fare — codice

Da fare dopo la revisione del codice (2026-11-05, analisi statica del commit `633bdec`; ogni punto è stato controllato a mano sul sorgente). Previsti per la 0.0.12:

- [x] ~~**ZS-001 — bypass XDP con frammentazione IPv4 (alto, confermato).**~~ **Corretto in 0.0.12** (maschera `0x1FFF`, test `TestXDPFragments` in CI; non ancora visto su un kernel reale con traffico frammentato). In `bpf/zerotrust.c` (~riga 387) la maschera `0x3FFF` include il flag MF: il primo
  frammento di un datagramma UDP (offset 0, MF=1) porta l'header UDP ma non viene ispezionato, quindi una risposta LLMNR/mDNS frammentata di proposito passa e
  lo stack IP la ricompone. Correzione: maschera `0x1FFF` (solo l'offset). Servono test: non frammentato, primo frammento con MF, frammenti successivi, drop effettivo.
- [x] ~~**ZS-004 — chiamata Polkit non conforme (medio, fail-closed).**~~ **Corretto in 0.0.12** (firma verificata col polkit vero). Resta da provare l'autorizzazione di un client non-root con il dialogo reale. `internal/priv/polkit.go` passa 7 argomenti a `CheckAuthorization`, che ne vuole 5, e il subject ha il tipo
  sbagliato (`a{ss}` invece di `a{sv}`): la chiamata fallisce sempre. Non è un bypass e oggi non pesa (la GUI usa `pkexec`, per root il controllo è saltato), ma i client non-root
  del socket privilegiato non possono autorizzarsi. Correzione sulla firma ufficiale + test con servizio Polkit reale.
- [x] ~~**ZS-003 — finestra fino a ~3 s dopo una sostituzione atomica (basso/medio, noto).**~~ **Ridotta in 0.0.12** (≈100 ms a riposo, al massimo 1 s in una raffica); non azzerata: il nuovo inode resta libero fino al rescan. Se un programma autorizzato sostituisce un file protetto con un rename, il nuovo inode
  resta fuori dalla mappa finché non scatta il rescan (`watchDebounce` 400 ms, `watchMinGap` 3 s). L'inotify sulle cartelle la riduce, non la elimina. Da fare: percorso di
  aggiornamento prioritario per i file protetti e test di rename ripetuti.
- [x] ~~**`deny_write`: chiarire il testo, non il codice.**~~ Fatto in 0.0.12. Un programma in whitelist per la regola può comunque scrivere: è voluto. `deny_write` nega la scrittura ai programmi
  *non* autorizzati. La frase in `bpf/zerotrust.c` («anche ssh-keygen e i backup vengono negati») e la documentazione vanno riscritte. Una modalità «nessuno scrive, nemmeno gli autorizzati» sarebbe una funzione nuova.
- [x] ~~**GUI, Regole: avvisare quando il programma in uso non è quello autorizzato.**~~ Fatto in 0.0.12 (avviso con alias suggerito). Visto sul PC (2026-11-05): «Rendi affidabile» autorizza la copia di root in `/usr/local/bin`, ma nel `PATH` viene prima la copia
  in `~/.local/bin` (inode diverso, di proprietà dell'utente) e il blocco continua. Anche lo script di init di oh-my-posh in cache aveva il percorso scritto dentro. Il messaggio deve dire quale copia gira davvero e come usare quella autorizzata.
- [ ] **Roadmap — audit delle connessioni in uscita dai programmi che toccano i segreti.** Hook `lsm/socket_connect`: logga «il programma X ha letto la regola R e poi si è connesso a IP:porta»
  (solo audit, nessun blocco, con eccezioni per `kubectl`/`git`/`aws`). Non vede il contenuto cifrato né i byte. Non esiste oggi: il radar guarda il traffico in ingresso e ZeroShield non è un firewall in uscita per processo. Dopo il collaudo in VM.
- [x] ~~**ZS-005 — `inode_rename` non controllava la destinazione dopo aver autorizzato il sorgente (medio, confermato).**~~ **Corretto in 0.0.16.** Da collaudare su kernel reale: due regole A e B, un programma autorizzato solo per A che sposta un file di A sopra uno di B deve avere *Permission denied*; autorizzato per entrambe passa; sorgente non protetto verso destinazione protetta negato; sorgente protetto verso non protetto consentito se autorizzato (anche con `RENAME_EXCHANGE`).
- [x] ~~**Errori `Put` sulle mappe solo loggati (medio, confermato).**~~ **Corretto in 0.0.16** (conteggi reali + avviso di protezione parziale); senza test unitario.
- [ ] **Descrittori di file già aperti, ereditati o passati (`SCM_RIGHTS`) (alto come limite, strutturale).** `lsm/file_open` controlla solo l'apertura: un fd ottenuto prima, da un programma autorizzato e poi ereditato da un figlio o inviato via socket, continua a leggere. Non c'è una correzione economica; da documentare e, se serve, da attenuare con `file_permission`.
- [x] ~~**IPv6 con extension header non analizzate da XDP (medio).**~~ **Corretto in 0.0.17** (fino a 6 header noti); test sul vero programma in CI; da provare con traffico vero (`docs/COLLAUDO_HARDENING.md`, sezione 4).
- [x] ~~**Stress test del watcher.**~~ Fatto in 0.0.17 (`TestWatcherStressRapidRenames`).
- [ ] **Collaudo su kernel reale degli hook** (rename ZS-005, `deny_write`, truncate, `file_truncate`): procedura pronta in `docs/COLLAUDO_HARDENING.md`, da eseguire in VM.
- [ ] **Polkit con un utente non-root**: la firma della chiamata è verificata con il polkit vero (risposta `challenge`), manca la concessione interattiva.
- [x] ~~**Audit delle connessioni in uscita dai programmi che toccano i segreti**~~ — fatto in 0.0.20 (solo registro, `docs/EGRESS.md`). **Visto scattare sul PC di prova dal 2026-11-06** (72 eventi in 6 giorni, solo `kubectl`/`k9s`/`helm`/`gh`; l'hook si carica e non dà problemi). Restano da provare altri kernel, un programma che legge un segreto e poi esce verso Internet, e il tetto di 20 eventi/s; i figli dei processi non sono seguiti. Dalla 0.0.23 `0.0.0.0` e `::` non si segnalano più (sono localhost).
- [ ] **Hardening e kill-switch dalla GUI (0.0.19): collaudo in VM.** I pulsanti usano gli script già esistenti; mai provati su un sistema vero (anteprima, applicazione, ripristino dopo `off`, comportamento con NetworkManager). Da fare con snapshot prima di togliere l'etichetta «sperimentale».
- [ ] **Profilo condiviso (0.0.22): autenticità del file.** Nessuna firma né checksum distribuito: chi riceve un profilo deve fidarsi del canale. Da aggiungere prima di usarlo su molte macchine (firma o impronta SHA-256 pubblicata a parte; l'impronta c'è già nell'anteprima). Da collaudare: finestre native di file nell'app vera, applicazione con `pkexec` su una seconda macchina, compatibilità fra versioni del formato (oggi solo la 1). Dettagli e rischi: `docs/PROFILO.md`.
- [x] ~~**ptrace e io_uring aperti in silenzio**~~ — **resi visibili in 0.0.21** (`internal/posture`: avviso nel journal, voce in «Da fare» nella GUI, comando sysctl persistente). Non sono chiusi: lo decide l'utente. Il bypass io_uring e la lettura della memoria restano possibili finché il sysctl non è applicato.
- [ ] **Aree da approfondire** (dalla stessa revisione, non vulnerabilità confermate): tetto di sicurezza di io_uring fail-open, IPv6 con extension header, ptrace, btrfs/overlayfs,
  descrittori di file ereditati o trasferiti, servizio fermo = nessuna protezione (già segnalata in Stato). Tre livelli di maturità da usare nelle tabelle: *implementato → verificato → resistente (test avversariali)*.

Chiusi il 2026-11-05 (release 0.0.4–0.0.6): modalità per singola protezione nel kernel e nel config; scheda Regole guidata con catalogo,
«Rendi affidabile», «Applica» e **«Proteggi un mio file»**; azione «autorizza questo programma» dagli eventi in audit; avvisi nel journal
una sola volta per binario; `zt-shield config-apply` provato con `pkexec`; icona nella barra come servizio utente; versione e popup Novità; unità dell'icona
senza `NoNewPrivileges` (rompeva `pkexec`); build eBPF senza warning; dipendenze aggiornate (Dependabot svuotato).

Chiusi il 2026-10-26 (dettagli in [`FIX_APPLICATI.md`](FIX_APPLICATI.md)): canary sotto systemd
(`zt-shield dropin`), canary `chown` e `allow_exe`, `ZT_SOCKET` ignorato dal demone root, QinQ a
doppio tag, IPv6 in XDP, `ftruncate` ≥ 6.2, tetto per regola sulle mappe, inotify contro la
finestra di rescan, preset `glab`.

- [x] ~~**IPv6 nel radar**~~ — 0.0.9: seconda mappa `xdp_stats6` (chiave a 16 byte), le sorgenti IPv6 compaiono nel radar e si raggruppano per /64
  (ogni famiglia ha la sua «rete delle altre sorgenti»). **Da verificare dal vivo** con traffico IPv6 vero.
- [ ] **IPv6 con extension header**: il poisoning dietro extension header passa (si guarda solo
  il next-header diretto).
- [ ] **Flatpak** nel preset `browsers`: serve il percorso del binario visto dal kernel, da
  verificare in audit su una macchina con Flatpak.
- [ ] **Browser snap/apt aggiornati**: dopo un aggiornamento l'inode del binario cambia e il
  browser resta fuori whitelist fino al rescan (inotify osserva i segreti, non i binari).
- [x] ~~**Modalità per regola nel kernel**~~ — vista su un PC (2026-11-05): `prova` in `enforce` nega, le altre regole in `audit` registrano soltanto.
- [ ] **GUI, regole editabili: collaudo parziale.** *Applica* con `pkexec`, backup e riavvio sono provati su un PC (2026-11-05).
  Restano da provare con un sistema vero: il **ripristino automatico dopo un riavvio fallito** (oggi solo test) e «Rendi affidabile» (copia in `/usr/local/bin`). Limite noto: se il terminale lancia ancora la copia di brew/`~/.local/bin`
  (stesso nome, PATH precedente) l'autorizzazione vale solo per la copia protetta; la GUI lo avvisa.
- [ ] **GUI, configurazione editabile** (interfaccia, subnet, canary, VPN): le **regole** si modificano dalla GUI, il resto della tab
  Configurazione mostra un riepilogo e il file e si cambia solo `mode`. Un editor a campi (interfaccia, subnet, canary, VPN) con validazione e anteprima
  della differenza richiede scritture sul canale privilegiato (`internal/priv` + polkit): da fare
  con il collaudo in VM, non prima.
- [x] ~~**GUI/IPC, interfacce non coperte**~~ — `ipc.Status.interfaces` e la scelta nella scheda Rete (0.0.7). Il **seguire a caldo** è in 0.0.8 (`internal/xdp/manager.go`) e dalla 0.0.9 si riallinea **subito** a ogni evento di rete del kernel (netlink), con il controllo ogni 2 secondi come rete di sicurezza. Provato con interfacce finte e con un evento netlink reale (spegnendo e riaccendendo il Wi-Fi); **non** con un adattatore vero collegato mentre il demone gira come root.
- [x] ~~**GUI, audit → enforce**: azione «autorizza questo exe»~~ — nella scheda Regole, «Visti da quando hai aperto la finestra» con *Autorizza*, *Rendi affidabile* e l'indicatore di prontezza per Blocca.
- [ ] **Radar, richieste contro risposte**: la mappa del kernel conta solo `poison` per IP. XDP scarta
  sia le richieste degli altri host (porta di destinazione 5355/5353/137/138, sottofondo normale) sia le
  risposte avvelenate (porta di origine 5355), senza distinguerle né dire il protocollo. Oggi la GUI
  classifica con euristiche dichiarate (tasso, volume, rete). Per un verdetto vero servono due contatori
  separati (richieste/risposte) e il protocollo, cioè una modifica a `bpf/zerotrust.c`, alla mappa e a
  `ipc.SourceStat`, da collaudare in VM.
- [x] ~~**Journal, rumore**: «binario Y non risolto» a ogni rescan~~ — ora escono una volta per binario all'avvio (18 righe in 15 minuti = 3 avvii, non una ogni 30 s). Gli avvisi sulle interfacce ora sono uno per ogni rete fisica o VPN non filtrata, più una riga riassuntiva per i container (0.0.7).
- [ ] **`configure_service.sh` da provare con un `.deb` vero in un'installazione pulita**: il pacchetto installato con `apt` funziona (servizio dalla unit
  del pacchetto, aggiornamenti 0.0.4 → 0.0.6), ma lo script con utente/profilo/dropin del canary e il fallimento se `bpf` manca non sono stati
  eseguiti su una macchina nuova, né dalla GUI con `pkexec`.
- [ ] **Installazione da sorgente e da pacchetto non si mescolano**: su una macchina con la unit del
  pacchetto, `install_service.sh` creerebbe una seconda copia in `/usr/local/sbin`. La GUI sceglie lo script
  giusto, ma a mano nulla lo impedisce: valutare un controllo nello script.
- [ ] **Falso positivo in audit**: il prompt `oh-my-posh` (in `~/.local/bin`, scrivibile dall'utente) legge i file di `cloud-creds` e compare come `[AUDIT]`
  a ogni prompt; il demone non può autorizzarlo così com'è. La GUI ora lo spiega e offre «Rendi affidabile» (copia in `/usr/local/bin`), ma sul PC di
  prova non è stato applicato. In alternativa: disattivare il segmento Kubernetes nel tema del prompt.
- [ ] **VPN: il demone non applica il kill-switch.** Resta una scelta (il demone è di sola
  misura): applicarlo in automatico può spegnere la rete della macchina, e non è mai stato
  provato su una rete vera. Se lo vuoi, serve un'azione sul canale di controllo con
  autenticazione polkit; non si fa prima del collaudo in VM.

## Decisioni aperte

- [ ] `block_subnets` scarta anche le risposte; con UFW `deny incoming` vale poco. Tenerlo? *Raccomandazione: tenerlo, spento di default (già così) e documentato.*
- [ ] Profilo di default `home` in `audit`: ok, o meglio `enforce`? *Raccomandazione: `audit` finché gli hook LSM non sono visti funzionare in VM.*
- [ ] DoT `yes` nel profilo `paranoid` rompe i captive portal: accettabile? *Raccomandazione: sì, per `paranoid`; `public-wifi` resta `opportunistic`.*
- [ ] Release: restare `prerelease` finché gli hook LSM non sono collaudati in enforce? *Raccomandazione: sì.*
- [ ] `nm_vpn.sh`: tenere `AUTO_DOWN` o toglierlo del tutto (il BSSID si clona)? *Raccomandazione: toglierlo; oggi è già spento di default.*

## Estensioni possibili

Vedi [`ROADMAP.md`](ROADMAP.md): fasi, valutazione di ogni proposta e ordine consigliato
(`selftest` e CI con kernel `lsm=…,bpf`, `doctor` con `io_uring_disabled`, IPv6/QinQ in XDP,
hook `ptrace`, egress, AV). Il controllo di postura CFI (CPU, kernel, binari) è parte di `doctor`.

## Fatto (sintesi)

- Kernel: XDP (poisoning sport+dport, VLAN singola, frammenti, subnet LPM, radar),
  LSM (`file_open` con `FMODE_READ`/`O_TRUNC`, `unlink`, `rename` sorgente e
  destinazione, `path_truncate`, `deny_write` per regola).
- Demone: fail-closed, rescan con riconciliazione, multi-interfaccia, watchdog
  systemd a metà intervallo, whitelist solo binari di root, filtro proprietario
  contro symlink verso file di sistema, audit con rate-limit, `-version`.
- Canary fanotify a due gruppi, chiusura senza race, kill solo in enforce.
- IPC: socket di proprietà dell'utente protetto (0600), testo sanificato in un punto solo,
  porte in ascolto TCP+UDP con tetto e totale dichiarato, stato VPN reale ogni 5 s.
- VPN: kill-switch atomico che tocca solo la propria tabella, `portal` a tempo del kernel,
  auto-VPN fail-closed, helper Proton, validazione del config.
- UI: TUI Bubble Tea (suggerimenti senza interpreti, blast-radius stabile), GUI Wails
  (ricerca eventi stabile, render raggruppati, guida per pacchetto e sorgente, versione dal
  binario), mock.
- Qualità: CI con test `-race`, test degli script (namespace e comandi finti), test GUI nel
  browser, `zt-probe` e test root su kernel del runner, govulncheck, gosec, Dependabot, Go 1.26.8.
- Distribuzione: pacchetto unico `zeroshield` con demone, TUI e GUI (`make package`; fino a v0.0.3 erano due), con script VPN e
  `zt-mockd`; workflow di pre-release sui tag `v*` (mai eseguito). La GUI dipende dal demone: i
  due file vanno installati insieme (da una release scaricata a mano, il solo pacchetto GUI non si
  installa).

## Limiti accettati

Aggiornato in 0.0.21 — ogni limite, se si può chiudere e come:

**Si possono chiudere con lavoro**

| Limite | Come | Costo e rischio |
|---|---|---|
| IPv6 oltre 6 extension header | alzare `MAX_V6_EXT` a 8–10 in XDP | basso; la CI fa verificare il programma al kernel. Un massimo ci sarà sempre |
| btrfs / overlayfs | leggere il dispositivo giusto per i file di quel filesystem | medio; serve un disco btrfs vero |
| fd già aperti, ereditati o passati con `SCM_RIGHTS` | hook `file_permission` che ricontrolla a ogni lettura | alto: costo su ogni lettura e rischio di falsi blocchi; prima in sola osservazione, in VM |
| hook mai provati su kernel reale | collaudo in VM (`docs/COLLAUDO_HARDENING.md`) | nessun codice, solo tempo |

**Si chiudono con una scelta dell'utente** (visibili dalla 0.0.21 in Stato → «Da fare»)

| Limite | Rimedio |
|---|---|
| io_uring fail-open | `kernel.io_uring_disabled=2`; può rompere pochi programmi |
| ptrace | `kernel.yama.ptrace_scope=1` (sul PC di prova è già a 1) |

**Non si chiudono, per natura**

| Limite | Perché |
|---|---|
| IPv6 con ESP | traffico cifrato: il filtro non può leggerne il contenuto |
| Root = game over | chi è root può scaricare qualunque hook; si mitiga con disco cifrato e backup |
| Whitelist per binario, non per catena | un programma autorizzato legge per chiunque lo lanci; si attenua con la chiave FIDO2 |
| Servizio fermo = nessuna protezione | scelta voluta (niente pinning, hook orfani peggio); l'icona diventa rossa |

- Root locale può scaricare gli hook eBPF.
- Tool interpretati (npm, pip, gcloud, az) non whitelistabili in modo sicuro.
- Il segreto forte è la chiave FIDO2, non la whitelist.
- Il BSSID di un access point si clona: non è autenticazione.
