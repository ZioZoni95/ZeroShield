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

## Non-obiettivi (strutturali, non si pianificano)

Root game over, whitelist=canale, FIDO2 software, backup (altrui ma obbligatorio
per l'utente), motori AV propri, cifratura traffico (è WireGuard, non nostro).
