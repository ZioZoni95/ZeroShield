# FIX_APPLICATI — ZeroShield

Registro cronologico delle correzioni: problema → fix → file → come riverificare.
Stato attuale e cose ancora aperte: [`PUNTI_APERTI.md`](PUNTI_APERTI.md).
Le sezioni 1–8 sono state scritte prima di qualsiasi test su kernel: la verifica
reale è nelle sezioni 11–12 e in [`TEST_SANDBOX.md`](TEST_SANDBOX.md).

## 1. Kernel `bpf/zerotrust.c` — APPLICATI

- **XDP guardava solo `dport`.** Risposta Responder (`sport=5355`, dport effimera)
  passava. Ora check `sport==porta || dport==porta` per 5355/5353/137/138.
  Riverifica: `nping --udp --source-port 5355 <victim> -p 50000` → DROP.
- **VLAN non parsata.** Tutto il traffico taggato 802.1Q passava. Ora unwrap
  singolo tag (`0x8100`/`0x88A8`), `nh` ricalcolato. QinQ doppio-tag resta PASS.
  Riverifica: test su rete taggata o veth con tag.
- **Frammenti IP.** Secondo frammento senza header UDP veniva letto come
  `dport` casuale (falso drop / mancato drop). Ora se `(frag & 0x3FFF)!=0`
  si salta il check L4, resta check subnet su `saddr`.
- **LSM bloccava anche `O_WRONLY`.** `ssh-keygen`, backup in scrittura negati
  anche a root. Ora check `FMODE_READ` in testa: write-only passa, solo la
  lettura è protetta. Costante `FMODE_READ 0x1` aggiunta.
- **Catena `BPF_CORE_READ(task,mm,exe_file,f_inode)` a rischio verifier.**
  Ora lettura a stadi con null-check (`task` → `mm` → `exe_file` → `f_inode`).
  `mm=NULL` (kernel thread / worker io_uring) → fail-open con `return 0`.
- **Nota io_uring aggiornata:** prima falso blocco, ora falso negativo mirato
  (worker senza `mm` passa). Trade-off noto, da chiudere con hook dedicati.

## 2. `internal/lsm/lsm.go` — APPLICATI

- **Walk seguiva `d.Type()`, non i symlink.** Segreto linkato in dir ricorsiva
  restava fuori mappa. Ora `os.Stat(p)` nel walk (segue symlink, coerente col kernel).
- **Troncamento `maxFilesPerPath` silenzioso.** Ora log esplicito con path quando
  si supera il tetto: resto NON protetto.
- **Glob malformato silenzioso.** Ora log `glob malformato %q`.
- **`reconcile` ignorava `it.Err()`.** Iterazione parziale = obsolete rimosse a
  metà. Ora log + `return` senza cancellare.
- **`resolveExe` solo `LookPath` (PATH systemd minimale).** `kubectl` snap,
  `aws` in `~/.local/bin` restavano fuori whitelist in silenzio. Ora fallback
  `/snap/bin`, `~/.local/bin`, `~/bin`; firma cambiata in
  `resolveExe(home, name)`; `Sync` logga ogni allow non risolto con nome regola.
- **Capienza mappe.** Oltre 16384 file / 1024 exe i `Put` falliscono `E2BIG` in
  silenzio. Ora warning preventivo con conteggi.
- **Nuovo `CheckFilesystem(home)`.** Avvisa se home su btrfs/overlayfs
  (`st_dev != s_dev` → chiave inerte). Prima solo test manuale lo rivelava.
  Da chiamare una volta a avvio da `main`.

## 3. `internal/config/config.go` — APPLICATI

- **`git` rimosso da regola `ssh`.** Git-over-SSH usa il binario `ssh`, non apre
  le chiavi direttamente. Tenerlo lì apriva `git hash-object ~/.kube/config`.
  Git resta in `dev-tokens` (serve `.git-credentials`). Effetto: `git` non legge
  più `~/.ssh/id_*` né `~/.kube/config`.
- **Deep copy preset.** Prima solo struct, slice condivise tra profili. Ora
  `Paths`/`Allow` copiati con `append([]string(nil), ...)`.
- **Strict YAML (secondo passaggio).** `KnownFields(true)`: refusi come
  `block_poisioning` ora errore invece di silenzio. Primo passaggio resta
  non-strict (struct solo `profile`).
- **`Validate` più severo:**
  - `allow` vuota rifiutata (deny-all anche per te, unica via stop demone);
  - nomi regola duplicati rifiutati (log ambigui);
  - `block_subnets` con `/%d < 8` rifiutato (`0.0.0.0/0` staccava tutto).

## 4. `internal/audit/audit.go` — APPLICATI

- **`decodeEvent` a offset espliciti** (`pid@0, comm@4(16), rule@20, ino@24(8),
  action@32, pad@36, 40B`). Prima `binary.Read` su struct Go funzionava solo
  perché il padding coincideva per fortuna.
- **Backoff errori:** `continue` immediato → busy loop 100% CPU su errore
  persistente. Ora `sleep 50ms`.
- **Rate-limit 50 ev/s** con riepilogo `audit flood: N soppressi` ogni 5s.
  Prima un loop di `open()` riempiva journal/disco.

## 5. `internal/xdp/xdp.go` — APPLICATI (libreria)

- **`Attach` accetta csv**, usa primo elemento, poi `logOtherUpInterfaces`:
  elenca interfacce UP non loopback scoperte e suggerisce
  `interface: "a,b"`. Prima copertura singola silenziosa.
- **Nuovo `AttachAll(prog, custom)`**: attacca a ogni iface della lista
  (o alla default se vuoto), un fallimento non blocca gli altri.
  Helper `splitList`/`firstOfList`/`splitCSV`+`trimSpace`.
- NOTA: `main.go` usa ancora `Attach` singolo: per attivare multi-iface
  serve la modifica main (sez. 7).

## 6. Comportamenti voluti confermati (non bug)

- `settings` default `ENFORCE=1` se voce assente: ok, main fa sempre `Put`.
- Chiave LPM in network order grezzo (`[4]byte`): corretto, era bug v1.
- `file_key`/`allow_key` 16B con `Extra`=rule: layout C/Go allineato.
- `reconcile` riscrive tutto ogni sync: costo accettato per immunità da disallineamenti.
- Timestamp eventi `time.Now()` userspace: skew con backlog ringbuf, noto.

## 7. Fix pianificati — APPLICATI (verificato 2026-10-02)

- [x] `scripts/harden_system.sh`: `ufw allow OpenSSH` prima di `enable`
  (lockout); fallback se manca sezione `[Resolve]`; `restart resolved` e
  `sysctl --system` tolleranti (`||` warning invece di abort con `set -e`).
- [x] `scripts/install_service.sh`: `StartLimitBurst/Interval` + `ExecStartPre`
  `grep bpf`; risolvi `bin/` da script-dir; valuta `ProtectSystem=strict` +
  `CapabilityBoundingSet` (test in VM prima).
- [x] `TESTING.md`: fix placeholder sed (`__USER__` vs `$USER`, `__UTENTE__`
  incoerenti) che rompono il copia-incolla.
- [~] Verifier reale: fatto per XDP (sandbox) e LSM (runner GitHub) con `zt-probe`;
  resta l'avvio completo del demone in VM. Testo originale: `sudo SHIELD_USER=$USER ./bin/zt-shield` + `bpftool prog show`,
  test btrfs/overlay, misura `run_cnt` con `bpf_stats_enabled=1`.
  (Nota: `NewTicker`, `AttachAll`, `CheckFilesystem`, conteggio subnet sono
  stati applicati durante il lavoro UI.)

## 8. Radar eBPF — collaudato su kernel reale (sez. 11)

- Kernel: mappa `xdp_stats` (LRU_HASH 1024, chiave saddr network order,
  valore poisoning/subnet/last_ns) + `count_drop()` su entrambi i drop XDP.
- Go: `xdp.ReadStats` (chiave `[4]byte` per non invertire gli IP),
  tracker wall-clock + top-12 in `main`, `ipc.TopSources` nel protocollo.
- Demo sicura senza kernel/root: `mockd` pubblica `TopSources` finte,
  TUI `--dump` e GUI le mostrano. Verifier del nuovo codice non ancora visto:
  primo load solo in VM con snapshot.

## 9. Revisione codice 2026-10-02 — APPLICATI

Compilato con clang + bpf2go (stub rigenerati), `go vet` e `go test -race`
puliti. **Verifier non visto**: i nuovi hook vanno caricati in VM prima dell'uso.

- **Watchdog systemd uccideva il demone.** Ping a ogni rescan (30s) con
  `WatchdogSec=30`: restart ogni ~30s, poi `StartLimitBurst=3` lo lasciava
  fermo. Ora `READY=1` all'avvio + ticker dedicato a `WATCHDOG_USEC/2`; il ping
  si ferma se il rescan e' fermo da > 2 intervalli + 30s (hung = restart).
  File: `internal/watchdog`, `cmd/zt-shield/main.go`, unit.
- **`rename` sopra un segreto non controllato.** `mv junk ~/.ssh/id_ed25519`
  sostituiva la chiave senza passare da `inode_unlink`. Ora `inode_rename`
  verifica anche `new_dentry`. Riverifica: `mv /tmp/x ~/.ssh/id_ed25519` → negato.
- **Wipe con `O_TRUNC`/`truncate(2)`.** `: > ~/.ssh/id_ed25519` passava come
  write-only. Ora `O_TRUNC` in `file_open` va in whitelist; nuovo hook
  `lsm/path_truncate` (`ZtPathTruncate`). Residuo: `ftruncate` su kernel ≥ 6.2
  (hook `file_truncate`, non usato per compatibilita').
- **Whitelist di binari scrivibili dall'utente.** `cat evil > ~/.local/bin/aws`
  manteneva l'inode autorizzato. Ora `trustedExe`: file e directory padri di
  root, non world-writable, group-writable solo con gid 0. Test in `lsm_test.go`.
- **Radar senza tetto.** `tracker` in `main` cresceva con IP spoofati; ora
  segue la LRU kernel (max 1024).
- **Data race in `main`.** `p`/`a`/`topSrc`/`publishStatus` letti e scritti da
  goroutine diverse, ticker avviato prima di `publishStatus`. Ora la goroutine
  di rescan parte dopo IPC e primo `publishStatus`, unica proprietaria dello stato.

## 10. Pipeline e caccia alle falle 2026-10-02 — APPLICATI

Strumenti eseguiti: staticcheck, shellcheck, gosec, `go test -race`, fuzz
`FuzzConfigLoad`, `npm audit`. govulncheck non raggiungibile dalla sandbox:
gira in CI.

- **Iniezione ANSI/OSC nel terminale.** `comm` (via `prctl`) e il path
  dell'exe sono scelti dal processo osservato e finivano grezzi in TUI e log
  testuale: `\x1b]52;...` scrive la clipboard di chi guarda, `\x1b[2J` cancella
  gli eventi veri. Ora `ipc.SafeText` (non stampabili → `\xNN`) in audit, canary
  e TUI; nella GUI anche escape HTML per le notifiche desktop (body-markup).
  TUI: `Time[11:19]` non va piu' in panic su timestamp corti (`clock`).
- **DoS di sistema da utente non privilegiato.** `~/.ssh/id_x -> libc.so.6`:
  il demone seguiva il symlink e proteggeva libc; in enforce nessuno (root
  incluso) la apriva piu'. Ora i pattern relativi alla home proteggono solo file
  del proprietario della home; i pattern assoluti dell'admin restano liberi.
  Test: `TestExpandSkipsForeignSymlink`.
- **CI riscritta** (`.github/workflows/ci.yml`): job lint (gofmt anche GUI,
  vet, staticcheck, shellcheck), test (race, coverage, fuzz smoke), eBPF
  (clang + bpf2go + `go vet ./...` completo + build demone, artefatto binari),
  GUI (Vite, `npm audit`, vet/build Wails con WebKitGTK, govulncheck),
  sicurezza (govulncheck bloccante, gosec SARIF in Code scanning), cron
  settimanale per nuove CVE. Dependabot per gomod (root+GUI), npm, actions.
  `Makefile`: `BPFTOOL` sovrascrivibile.

gosec, triage dei risultati restanti (non bloccanti, in SARIF):
G115 su layout kernel/fanotify e `Mask.Size()` (valori limitati, falsi
positivi); G302/G301 socket IPC 0666 (era una scelta documentata, **superata dalla sez. 13**:
il socket del demone ora e' 0600 dell'utente protetto; resta 0666 solo per mock e test); G304 config da
`-config` (input dell'admin); G704 `NOTIFY_SOCKET` (impostato da systemd).

## 11. Primo collaudo su kernel reale 2026-10-02 — APPLICATI

Dettagli, ambiente e comandi in `docs/TEST_SANDBOX.md`.

- **Canary mai partito.** `fanotify_mark` sulle cartelle → `EINVAL` (serve
  `FAN_REPORT_FID`). Ora gruppo classico per le esche + gruppo FID per le dir.
- **Race in `Watcher.Close()`.** fd chiusi con i loop vivi: il numero riusato dal
  watcher successivo faceva "rubare" eventi. Ora `poll()` su fd + pipe di stop,
  `WaitGroup`, chiusura dopo l'uscita dei loop. 10 ripetizioni con `-race` ok.
- **`settings` ARRAY**: commento corretto (le voci partono da 0, nessun default).
- **Nuovo `cmd/zt-probe`**: verifier per programma (rifiuto vero ≠ tipo non
  supportato) e test funzionale XDP su loopback. `make probe`, step CI.
- **Test root del canary** (`make test-root`, step CI con sudo).
- **README**: avviso di maturità con tabella "cosa è testato", badge CI sulla
  repo giusta, Go ≥ 1.26, `bpftool` da `linux-tools-generic` (autodetect nel
  `Makefile`), struttura aggiornata.

## 12. Documentazione e pacchetti 2026-10-02 — APPLICATI

- **Pacchetti `.deb`** con nfpm: `zeroshield` (demone, `zt-tui`, `zt-probe`,
  unit systemd, config come conffile, script in `/usr/share/zeroshield`, doc) e
  `zeroshield-gui` (GUI Wails compilata senza CLI Wails, `.desktop`, icona).
  `make package` / `make package-gui`; installazione, reinstallazione e rimozione
  provate. Il servizio NON parte da solo: senza `user:` e `bpf` negli LSM il
  demone si fermerebbe (fail-closed).
- **Script del pacchetto**: `prerm` disabilita il servizio solo su rimozione,
  non su aggiornamento; `systemctl` solo se systemd è l'init.
- **Release automatica** (`.github/workflows/release.yml`): tag `v*` → build,
  test, due `.deb` + `SHA256SUMS` in una GitHub Release (pre-release).
- **`zt-shield -version`**, versione iniettata dal Makefile (tag git o
  `0.0.0~dev+<commit>`).
- **Config di esempio**: `user: ""` (errore chiaro) invece di `mario`; commento
  `deny_write` corretto.
- **`.desktop` della GUI**: rimossi path assoluti di una macchina personale.
- **Documenti**: `PUNTI_APERTI` riscritto, `CANARY` come guida d'uso, `TESTING`
  (passo 0 `make probe`, niente scrittura in `/sys/kernel/security/lsm`, 5
  programmi attesi), `TESTING_LAB` (wipe, symlink, ANSI, canary), `UI_RESEARCH`
  e `FEATURE_PLAN` allineati.
- **Trovato**: canary sotto systemd bloccato da `ProtectHome=read-only`;
  documentato l'override `ReadWritePaths`, fix strutturale in `PUNTI_APERTI`.

## 13. Revisione di `main` del 2026-10-05 — APPLICATI

Revisione del lavoro VPN, `netstat` e UI. Per ogni difetto: provato prima (dove possibile con
un test che fallisce sulla versione vecchia), corretto, coperto da un test.

**Kill-switch `scripts/vpn_killswitch.sh` (riscritto)** — test: `scripts/test_killswitch.sh`
(54 controlli in un network namespace; verificato che fallisce sulla versione precedente).
- `off` faceva `nft flush ruleset` e ricaricava un backup: se il ricaricamento falliva restava
  la macchina **senza firewall**. Ora toglie solo la propria tabella.
- Il backup stava in `/tmp/zt-nft.backup`: un file piazzato da un altro utente prima del primo
  `on` veniva caricato come root da `off`. Nessun backup, nessun file di stato.
- `on` cancellava la vecchia tabella e poi applicava la nuova: un errore (es. endpoint IPv6)
  lasciava la macchina senza kill-switch. Ora un solo `nft -f` atomico, preceduto da `nft -c`.
- `portal` aspettava 5 minuti in primo piano e poi **non riattivava** il kill-switch (commento e
  codice si contraddicevano). Ora apre solo 80/443/DNS per N secondi con un timeout nel set
  nft: lo chiude il kernel, anche se lo script muore.
- Input validati (IPv4, `[IPv6]`, porta, interfaccia, CIDR v4/v6); endpoint con nome host
  rifiutato; IPv6 supportato.

**Auto-VPN `scripts/nm_vpn.sh` (riscritto)** — test: `scripts/test_nm_vpn.sh` (28 controlli).
- BSSID vuoto (cavo, hotel) → `grep -F ""` combaciava con ogni riga → rete "fidata" → **VPN
  spenta**. Ora BSSID vuoto, malformato o assente = non fidato = VPN su; confronto esatto.
- Agiva su ogni evento `up` (docker0, veth, il tunnel stesso): ora solo interfacce fisiche.
- Non spegne più la VPN su rete fidata (il BSSID si clona): solo con `AUTO_DOWN=1`.
- Non rilancia un tunnel già attivo (falso errore "resta scoperto").
- `PROTON=1` non trovava `proton_up.sh` installato in `dispatcher.d`: ora lo cerca anche in
  `/usr/share/zeroshield/scripts`.

**Helper Proton** — test: `scripts/test_proton.sh` (19 controlli).
- `proton_current.sh` prendeva la prima interfaccia WireGuard (poteva essere il tunnel di
  lavoro che dichiarava di ignorare): ora riconosce Proton dal nome e non sceglie mai da solo
  altro; `--iface` per decidere.
- `proton_setup.sh`: endpoint non-IP rifiutato (il kill-switch non può risolverlo); avviso (e
  `--remove-source`) per la chiave privata rimasta nel file scaricato.

**IPC e dati nuovi**
- `Listening.Exe` (scelto dal processo osservato) arrivava grezzo a TUI e GUI: **iniezione ANSI/OSC**
  (provata con `\x1b]52;…`). Ora `Status.sanitize()` in `ipc.UpdateStatus` sanifica ogni
  stringa in un punto solo (anche eventi e canary); la TUI sanifica di nuovo in difesa.
- Il socket era 0666: PID ed exe di tutti i processi (porte in ascolto comprese) arrivavano a
  qualunque utente locale. Ora proprietà dell'utente protetto, modo 0600 (`NewServerOwnedBy`);
  provato con utenti reali (protetto sì, altro utente `permission denied`, root sì).
- `netstat`: aggiunto UDP (mDNS/LLMNR sono la superficie che XDP difende), tetto di 256 voci con
  totale dichiarato (una riga di status oltre 1 MiB bloccava i client), ordine stabile, PID più
  basso invece del primo lessicografico, test su un finto `/proc`.
- Stato VPN reale (`internal/vpn`): tunnel UP, tabella nft attiva, età dell'handshake. Prima
  `enabled && interfaccia UP` = verde, anche senza kill-switch e senza handshake. Controllo ogni
  5 s (prima ogni 30). Il config valida `vpn.endpoint` (IP:porta) e `vpn.tunnel`.

**TUI** — test: `cmd/zt-tui/review_test.go`.
- I suggerimenti proponevano di autorizzare `python3.12`, `bash`, `/var/tmp/x`: ora solo percorsi
  di sistema e mai shell, interpreti o lettori/copiatori generici (`cat`, `curl`, `rsync`...).
- Il blast-radius contava `git` e `/usr/bin/git` come due binari e cambiava ordine a ogni
  render: ora per nome base, ordine deterministico.
- Tab Rete: UDP, IPv6 tra parentesi, troncamento dichiarato, quattro stati VPN.

**GUI** — test nel browser: `zt-gui/frontend/tests/gui.test.mjs` (19 controlli; sul frontend
precedente ne falliscono 13).
- La ricerca eventi perdeva focus e testo a ogni evento in arrivo: in un flood si riusciva a
  digitare **una sola lettera**. Ora la barra si costruisce una volta e si aggiorna solo la
  tabella; i render sono raggruppati con `requestAnimationFrame`.
- Guida e wizard indicavano `make build` e un `cp` che **sovrascriveva** la config: ora due
  percorsi (pacchetto `.deb` e sorgente, con `cp -n`); `zt-mockd` ora è nel pacchetto.
- Versione letta dal binario (`Version()` + `-ldflags`); la costante `APP_VERSION` non era
  nemmeno usata. Errore "permission denied" sul socket spiegato (utente non protetto).

**Documentazione e pacchetto** — `FEATURE_PLAN`, `FEATURE_STUDY`, `ROADMAP`,
`PUNTI_APERTI`, `VPN_SETUP`, `shield.example.yaml` e README allineati al codice (lo stack VPN
è dichiarato "non collaudato su rete reale"); `.deb` con script VPN, `zt-mockd` e `VPN_SETUP.md`.
