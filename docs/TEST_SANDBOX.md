# Test su kernel reale — 2026-10-02

Primo contatto del codice con un kernel vero. Fino a qui ZeroShield era verificato
solo da compilatore, test unitari e analisi statica.

## Ambiente

| Voce | Valore |
|---|---|
| Macchina | VM cloud isolata e usa e getta (Firecracker), root, nessun dato reale |
| Kernel | `6.18.44`, `CONFIG_BPF_LSM=y`, BTF presente, JIT attivo |
| LSM attivi | `lockdown,capability,landlock,selinux,bpf` (dopo `mount -t securityfs`) |
| Lockdown | `integrity` |
| Filesystem | ext4 (chiave dev+inode valida) |
| Go / clang | go1.26.8, clang + libbpf-dev, bpftool da `linux-tools-generic` |

## Risultati

| # | Test | Esito | Note |
|---|---|---|---|
| 1 | Compilazione eBPF (`make generate`) | ✅ | 5 programmi: 1 XDP, 4 LSM |
| 2 | Verifier `xdp_shield` | ✅ | accettato |
| 3 | XDP su `lo`: UDP 5355 / 5353 | ✅ droppati | |
| 4 | XDP su `lo`: UDP 9999 | ✅ ricevuto | il traffico normale passa |
| 5 | Radar `xdp_stats` | ✅ | `127.0.0.1 poisoning=2` |
| 6 | Verifier programmi LSM (`zt_file_open`, `zt_file_unlink`, `zt_file_rename`, `zt_path_truncate`) | ⚠️ non verificabile | `load program: operation not permitted`; `bpftool feature probe`: `program_type lsm/tracing NOT available` su questo kernel |
| 7 | Demone `zt-shield` con LSM non caricabile | ✅ fail-closed | esce con errore invece di dichiararsi attivo |
| 8 | Canary: avvio fanotify | ❌ → ✅ | **bug trovato**: `EINVAL` sul mark delle cartelle (manca `FAN_REPORT_FID`). Corretto |
| 9 | Canary: tocco esca (audit) | ✅ | alert con path e exe |
| 10 | Canary: 60 create+delete in 10 s | ✅ | alert di massa |
| 11 | Canary: tocco esca (enforce) | ✅ | figlio ucciso con `SIGKILL` |
| 12 | Canary: 10 ripetizioni con `-race` | ❌ → ✅ | **bug trovato**: `Close()` chiudeva gli fd con i loop vivi, fd riusati rubavano eventi. Corretto |
| 13 | TUI contro mock (`zt-tui --dump`) | ✅ | tutte le tab |

### Bug emersi solo grazie al kernel reale

1. **Canary mai partito** (`internal/canary`). `FAN_DELETE`/`FAN_MOVED_*` sono accettati
   solo da gruppi `FAN_REPORT_FID`, che però non consegnano fd (niente path dell'esca).
   Ora due gruppi: uno classico per le esche, uno FID per le cartelle.
2. **Race in `Watcher.Close()`**: chiusura fd con goroutine ancora in `read()`. Ora `poll()`
   su fd + pipe di stop, attesa dei loop, poi chiusura.
3. **Commento ingannevole in `zerotrust.c`**: la mappa `settings` è un ARRAY, le voci
   esistono sempre a 0, quindi il default di `setting()` non scatta mai. Il demone scrive
   sempre le impostazioni, quindi in produzione non cambia nulla; `zt-probe` ora le imposta.

## Runner GitHub (CI, stesso giorno)

Lo step `Kernel reale (zt-probe)` del job `ebpf` (PR #12) sul kernel `ubuntu-24.04`:

| Programma | Esito |
|---|---|
| `xdp_shield` | ✅ accettato + test funzionale su `lo` superato |
| `zt_file_open`, `zt_file_unlink`, `zt_file_rename`, `zt_path_truncate` | ✅ **accettati dal verifier** |
| Canary fanotify (test root) | ✅ |

Prima verifica del verifier sugli hook LSM: il codice C dei segreti è accettato dal
kernel. `zt-probe` carica i programmi ma non li aggancia (di proposito: un hook
attivo sul runner bloccherebbe file a caso), quindi il blocco effettivo resta da vedere.

## Cosa resta da provare (serve una VM con BPF LSM attivo)

Ubuntu 24.04 in VM con `lsm=...,bpf` sulla riga di comando del kernel, poi:

- `make probe` → i 4 programmi LSM ✅ (già visto sul runner GitHub);
- collaudo completo di [`TESTING_LAB.md`](TESTING_LAB.md): `cat ~/.kube/config` negato in
  enforce, whitelist per identità, `mv`/`: >`/`truncate` su una chiave negati, symlink verso
  file di sistema ignorato, watchdog systemd stabile oltre 2 minuti.

## Revisione e correzioni del 2026-10-05

Test aggiunti con le correzioni della revisione (dettagli in `FIX_APPLICATI.md` sez. 13). Tutti
girano anche in CI. Per ognuno è stato verificato che **fallisce** sulla versione precedente.

| Test | Dove | Esito |
|---|---|---|
| Kill-switch: on/off/status/portal, atomicità, IPv6, input ostili, backup in `/tmp` ignorato | `scripts/test_killswitch.sh`, network namespace (`unshare -n`) | ✅ 54/54 · sulla versione vecchia fallisce (riapplicazione non atomica, firewall perso, porta 0 accettata, nessun IPv6) e `portal` non termina |
| Auto-VPN: BSSID vuoto, evil-twin, interfacce virtuali, tunnel già su, Proton | `scripts/test_nm_vpn.sh`, comandi finti | ✅ 28/28 |
| Helper Proton: tunnel di lavoro mai scelto, endpoint non-IP, chiave privata | `scripts/test_proton.sh`, comandi finti | ✅ 19/19 |
| Socket IPC con utenti reali | client minimale come `zttest`, `nobody` e root | ✅ protetto legge · altro utente `permission denied` · root legge |
| GUI nel browser: ricerca sotto flood, stati VPN, UDP/IPv6, HTML ostile, guida | `zt-gui/frontend/tests/gui.test.mjs`, Chromium headless, demone simulato | ✅ 19/19 · sul frontend vecchio 13 falliscono (digitabile **una** lettera durante il flood) |
| `netstat` su un finto `/proc` (v4, v6, UDP, tetto, PID più basso) | `go test ./internal/netstat` | ✅ |
| Stato VPN (4 combinazioni, tool mancanti mai verdi) | `go test ./internal/vpn` | ✅ |

Non provato: kill-switch con traffico e tunnel veri, `nm_vpn.sh` con NetworkManager, helper
Proton con un account, GUI e TUI vere da due utenti diversi.

## Come rifare questi test

```bash
# Dipendenze (Ubuntu 24.04)
sudo apt install -y clang llvm libbpf-dev linux-tools-generic

# Se /sys/kernel/security è vuoto (container/VM minimali)
sudo mount -t securityfs securityfs /sys/kernel/security
cat /sys/kernel/security/lsm            # deve contenere "bpf"

# 1-6: verifier per programma + XDP su loopback (non tocca le interfacce reali)
make probe                              # = make build-probe && sudo ./bin/zt-probe -xdp-lo
ZT_PROBE_VERBOSE=1 sudo ./bin/zt-probe  # log completo del verifier in caso di rifiuto

# 7: fail-closed del demone (config di prova, utente finto)
sudo useradd -m zttest
sudo ./bin/zt-shield -config configs/shield.example.yaml   # con user: zttest, mode: audit

# 8-12: canary fanotify reale (root)
make test-root

# VPN: script (nm_vpn e proton con comandi finti; kill-switch in un network namespace)
make test-scripts

# GUI nel browser (Chrome di sistema o CHROME_PATH=...)
(cd zt-gui/frontend && npm ci && npm run build && npm i --no-save playwright-core && node tests/gui.test.mjs dist)

# 13: TUI senza root
make build-tui build-mock
ZT_SOCKET=/tmp/z.sock ./bin/zt-mockd &
ZT_SOCKET=/tmp/z.sock ./bin/zt-tui --dump
```

In CI: il job `ebpf` esegue `zt-probe -xdp-lo` e il job `test` esegue `make test-root`
sui runner GitHub (VM con sudo).
