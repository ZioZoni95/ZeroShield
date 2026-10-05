# ROADMAP — ZeroShield, piano unificato

Sintesi di `FEATURE_PLAN.md` (cosa), `FEATURE_STUDY.md` (come) e
`PUNTI_APERTI.md` (debito noto) in fasi ordinate per valore/costo.
Regola: niente kernel nuovo prima di aver collaudato quello esistente.

## Fase 0 — Chiudere il collaudo (prerequisito di tutto)

Senza VM con `bpf` in LSM, ogni voce kernel sotto è teoria.

- [ ] VM Ubuntu 24.04 `lsm=...,bpf`: `make probe` + `TESTING_LAB.md` in enforce.
- [ ] Watchdog oltre 2 min, script in VM con snapshot, pentest LAN Test 5.
- Accettazione: tabella `TEST_SANDBOX.md` con riga enforce reale verde.

## Fase 1 — Rete sicura fuori casa (valore massimo, niente kernel)

- [ ] **VPN kill-switch** (giorni): `vpn:` in YAML, `vpn_killswitch.sh`
  idempotente + rollback, fail-chiuso se tunnel cade, eccezioni DHCP/captive.
  Accettazione: tunnel killato → `tcpdump` su gateway muto 60 s.
- [ ] **Auto-VPN su SSID** (ore): dispatcher NetworkManager su BSSID allowlist
  (mai solo nome: evil-twin). Accettazione: cambio rete → profilo+tunnel giusti.

## Fase 2 — Robustezza locale (ore/giorni, userspace e config)

- [ ] Canary sotto systemd: `ReadWritePaths` generati o esche fuori servizio.
- [ ] Canary `chown` utente, `exclude_exe` anche per trip (indicizzatori/backup).
- [ ] `ZT_SOCKET` ignorato se euid 0; preset token GitLab/`glab` in example.
- [ ] Finestra rescan: inotify sulle dir protette o rescan adattivo.
- [ ] Tetto per regola contro saturazione mappe (priorità ai pattern).
- [ ] `ftruncate` ≥6.2 (hook opzionale), commento QinQ allineato al codice.

## Fase 3 — Kernel avanzato (solo dopo Fase 0, una voce alla volta)

- [ ] IPv6 + QinQ in XDP (verifier nuovo, VM dedicata).
- [ ] Hook `ptrace` anti-memory-scrape.
- [ ] btrfs `st_dev`↔`s_dev`, SIGHUP reload, hardening unit completo.
- [ ] Check postura CFI in `check_prereqs.sh`/`zt-probe` (solo verifica).

## Fase 4 — Egress e AV (ultimi, costosi)

- [ ] Egress per processo via cgroup (dopo kill-switch; nftables prima del C).
- [ ] Hook AV esterno via fanotify `OPEN_PERM` (`av_socket:`, fail-open).

## Fase 5 — Feature originali (proposte, da valutare)

- [ ] **Honeytoken con lineage**: token finti marchiati + catena genitori
  (`npm → node → cat`) via `/proc` al momento del tocco. Attribuzione
  supply-chain, solo userspace.
- [ ] **Incident bundle one-click**: a ogni kill/blocco grave, `.tar.gz` con
  exe, cmdline, parenti, file aperti, ultime 50 righe log.
- [ ] **Shadow-verify periodico**: il demone tenta da solo una lettura vietata
  ogni N minuti; se passa invece di `EACCES`, hook caduto = allarme.
  Anti morto-silenzioso integrato.
- [ ] **Self-hash binario** (da GhostCatcher/OmniShield): SHA256 del proprio
  eseguibile a ogni rescan vs valore a avvio; drift = alert critico. Solo Go.
- [ ] **Atomic self-tests schedulati** (mini-Coalmine): batteria di micro-check
  (open/unlink/rename negati, mappe non vuote, IPC vivo) ogni N minuti con
  report pass/fail in UI. Estende shadow-verify, tutto userspace.
- [ ] **Install-session mode**: `zt-shield run -- npm install x` attiva profilo
  paranoico temporaneo + report dedicato (negati, canary). Riusa sensori
  esistenti, zero kernel nuovo. Solo wrapper userspace.
- [ ] **USB allowlist integrata**: default-deny BadUSB via `authorized_default`
  + allow chiavette note, stato in UI. USBGuard esterno esiste ma pesante;
  integrata nel profilo è originale nel nostro insieme.
- [ ] **LKM gate** (da SPiCa): nega `insmod` post-init via `kernel_read_file`.
  Caveat: root scarica prima i nostri hook; vale solo con Secure Boot.
  Fase 3, mai prima della VM.

## Non-obiettivi (strutturali, non si pianificano)

Root game over, whitelist=canale, FIDO2 software, backup (altrui ma obbligatorio
per l'utente), motori AV propri, cifratura traffico (è WireGuard, non nostro).
