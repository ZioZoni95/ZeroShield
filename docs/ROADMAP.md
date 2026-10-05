# ROADMAP — ZeroShield, piano unificato

Sintesi di `FEATURE_PLAN.md` (cosa), `FEATURE_STUDY.md` (come) e
`PUNTI_APERTI.md` (debito noto) in fasi ordinate per valore/costo.
Regola: niente kernel nuovo prima di aver collaudato quello esistente.

Legenda: `[x]` fatto e verificato · `[~]` implementato, **non** collaudato nell'ambiente
reale · `[ ]` da fare. Aggiornato dopo la revisione del 2026-10-05.

## Fase 0 — Chiudere il collaudo (prerequisito di tutto)

Senza VM con `bpf` in LSM, ogni voce kernel sotto è teoria. Fatto: XDP e canary su kernel
reale; i 4 programmi LSM passano il verifier (kernel dei runner GitHub).

- [ ] VM Ubuntu 24.04 `lsm=...,bpf`: `make probe` + `TESTING_LAB.md` in enforce.
- [ ] Watchdog oltre 2 min, script di sistema in VM con snapshot, pentest LAN Test 5.
- [ ] **`zt-shield selftest`** (proposta): comando one-shot che prova da solo open/unlink/rename/
  truncate su un file esca dedicato (mai un segreto vero) e verifica `EACCES` in enforce o
  l'evento nel ring buffer in audit. Trasforma la riga "enforce verde" in un comando
  ripetibile, utilizzabile in VM e in CI. Base dei due punti seguenti.
- [ ] **CI con un kernel `lsm=…,bpf`** (proposta): avviare in CI lo stesso kernel del runner in
  una VM leggera con `bpf` tra gli LSM (es. `virtme-ng`) ed eseguire `selftest` in enforce.
  **Da verificare:** che i runner espongano `/dev/kvm`. Se sì, chiude la Fase 0 per ogni PR.
- Accettazione: tabella `TEST_SANDBOX.md` con riga enforce reale verde.

## Fase 1 — Rete sicura fuori casa (valore massimo, niente kernel)

- [~] **VPN kill-switch** — `scripts/vpn_killswitch.sh` (on/off/status/portal), stanza `vpn:`
  validata, stato reale nelle UI (tunnel, tabella nft, handshake). Provato in un network
  namespace (54 controlli, anche in CI), **mai su rete reale né con un tunnel vero**.
  Accettazione: tunnel killato → `tcpdump` su gateway muto 60 s, in VM.
- [~] **Auto-VPN su rete non fidata** — `scripts/nm_vpn.sh`, fail-closed, non spegne mai la VPN
  da solo. Provato con comandi finti (28 controlli); **mai con NetworkManager vero**.
  Accettazione: cambio rete → tunnel giusto, in VM con NM.
- [~] Helper ProtonVPN (`proton_setup/current/up.sh`): provati con comandi finti (19 controlli).

## Fase 2 — Robustezza locale (ore/giorni, userspace e config)

- [ ] Canary sotto systemd: `ReadWritePaths` generati o esche fuori servizio.
- [ ] Canary `chown` utente, `exclude_exe` anche per trip (indicizzatori/backup).
- [ ] `ZT_SOCKET` ignorato se euid 0; preset token GitLab/`glab` in example.
- [ ] Finestra rescan: inotify sulle dir protette o rescan adattivo.
- [ ] Tetto per regola contro saturazione mappe (priorità ai pattern).
- [ ] `ftruncate` ≥6.2 (hook opzionale), commento QinQ allineato al codice.
- [x] Socket IPC di proprietà dell'utente protetto (0600) e testo dei processi sanificato in un
  punto solo (`ipc.SafeText`).

## Fase 3 — Kernel avanzato e postura (solo dopo Fase 0, una voce alla volta)

- [ ] **`zt-shield doctor`** (proposta, costo basso): controlli di postura che non richiedono
  codice kernel: `kernel.yama.ptrace_scope`, modalità lockdown, lista LSM,
  `kernel.unprivileged_bpf_disabled`, CFI della CPU/kernel (`ibt`, `user_shstk`,
  `CONFIG_CFI_CLANG`), e **`kernel.io_uring_disabled=2`** (kernel ≥ 6.6, da verificare sul
  tuo): chiude con una riga di sysctl il bypass `io_uring` documentato nei limiti.
- [ ] IPv6 + QinQ in XDP. Il verifier si controlla già in CI con `zt-probe`.
- [ ] Hook `ptrace` anti-memory-scrape. **Valore medio** con `yama.ptrace_scope≥1` (default
  Ubuntu): prima il controllo in `doctor`, l'hook dopo.
- [ ] btrfs `st_dev`↔`s_dev`, SIGHUP reload, hardening unit completo.

## Fase 4 — Egress e AV (ultimi, costosi)

- [ ] Egress per processo via cgroup (dopo kill-switch; nftables prima del C).
- [ ] Hook AV esterno via fanotify `OPEN_PERM` (`av_socket:`, fail-open). Nell'hook va escluso il
  PID del demone, altrimenti va in deadlock.

## Fase 5 — Feature originali (proposte) — valutazione della revisione 2026-10-05

| Proposta | Valore | Note e correzioni al piano |
|---|---|---|
| **Shadow-verify periodico** | alto, costo basso | Va su un file esca dedicato, mai su un segreto. In `audit` la lettura passa: la prova è l'evento nel ring buffer. Escludere il PID del demone dagli eventi. Si fonde con `selftest` (Fase 0). Protegge da bug e da stacchi rumorosi, non da un root silenzioso. |
| **Incident bundle** | medio-alto | Per il canary: `SIGSTOP` → raccolta → `SIGKILL`, altrimenti il processo sparisce prima. Mai `environ`; file `0600`; tetto sul numero di bundle (flood = disco pieno). |
| **Honeytoken con lineage** | medio | "Solo userspace" è ottimistico: il genitore cambia (reparenting a init) e un figlio veloce muore prima che Go legga `/proc`. Per un `postinstall` serve leggere la catena dei genitori nel kernel: Fase 3. |
| **Install-session mode** | medio | Meglio un **wrapper di sandbox** generato dalle regole (`systemd-run --user --scope` con `InaccessiblePaths`, o bubblewrap): niente cambio di profilo nel demone. Cambiarlo richiederebbe un canale di controllo con autenticazione che oggi non esiste. |
| **Self-hash del binario** | basso | Falsi positivi a ogni `apt upgrade`; contro root non protegge. |
| **Atomic self-tests schedulati** | alto | È `selftest` (Fase 0) eseguito ogni N minuti, con report pass/fail in UI. Prima il one-shot. |
| **USB allowlist** | basso, rischio alto | `authorized_default=0` toglie anche la tastiera USB al primo re-plug. Fuori dal threat model attuale: rimandare a USBGuard. |
| **LKM gate** | basso | `init_module` con buffer aggira `kernel_read_file` (serve anche `kernel_load_data`); rompe firmware e DKMS; lockdown `integrity` + moduli firmati copre già l'obiettivo. |

## Non-obiettivi (strutturali, non si pianificano)

Root game over, whitelist=canale, FIDO2 software, backup (altrui ma obbligatorio
per l'utente), motori AV propri, cifratura traffico (è WireGuard, non nostro).
