# Punti aperti — ZeroShield

Aggiornato: 2026-10-02. Storico delle correzioni in [`FIX_APPLICATI.md`](FIX_APPLICATI.md),
esiti dei test reali in [`TEST_SANDBOX.md`](TEST_SANDBOX.md),
piano feature unificato in [`ROADMAP.md`](ROADMAP.md).

## Stato in una riga

Compila, CI verde (lint, test `-race`, eBPF, GUI, sicurezza, pacchetti `.deb`).
**XDP e canary collaudati su kernel reale; i 4 hook LSM passano il verifier ma non
sono mai stati agganciati**: il blocco effettivo dei segreti resta da vedere in VM.

| Componente | Stato |
|---|---|
| XDP anti-poisoning + radar | ✅ kernel reale (drop verificato su loopback) |
| Canary fanotify | ✅ kernel reale (esca, massa, kill in enforce) |
| Hook LSM (`file_open`, `unlink`, `rename`, `truncate`) | 🟡 verifier ok sul runner GitHub, mai agganciati |
| TUI / GUI / mock / IPC | ✅ |
| Pacchetti `.deb` | ✅ installazione e rimozione provate |
| Script di sistema (`harden_system.sh`, `setup_fido2.sh`) | ⚠️ mai eseguiti (solo shellcheck) |

## Origine e scopo

Progetto personale nato dopo uno zero-day con ransomware, attacco ad Active
Directory e GitLab, furto di token, ingresso da VM Windows Server 2013.
La bonifica enterprise è compito di altri: qui si protegge solo la postazione
personale. Lezione tradotta: i token piatti rubati fanno il disastro, quindi
priorità a segreti locali, token brevi, firma FIDO2.

**È:** anti-furto-segreti locali (LSM dev+inode), anti-poisoning (XDP +
resolved/UFW), esche anti-ransomware (fanotify), hardening, FIDO2.
**Non è:** antivirus, firewall completo (niente egress), EDR, backup.
Root locale, keylogger e disco non cifrato restano fuori scopo.

## Da fare — collaudo

- [ ] **VM Ubuntu 24.04 con `lsm=...,bpf`**: `make probe`, poi collaudo completo di
  [`TESTING_LAB.md`](TESTING_LAB.md) in `enforce` (è l'unico pezzo mai visto funzionare).
- [ ] **Watchdog systemd** stabile oltre 2 minuti (`systemctl status zt-shield`).
- [ ] **Percorsi dei browser** in `audit` (deb/snap/flatpak) prima di `public-wifi` in enforce.
- [ ] **Script** `harden_system.sh` e `setup_fido2.sh` in VM con snapshot.
- [ ] **Test furto-token** in VM isolata: infostealer simulato, reverse shell host-only.
- [ ] **Pentest LAN** da macchina esterna ([`TESTING.md`](TESTING.md), Test 5).

## Da fare — codice

- [ ] **Canary sotto systemd**: la unit ha `ProtectHome=read-only`, le esche non si
  possono creare. Oggi va aggiunto `ReadWritePaths=` a mano (`systemctl edit`);
  meglio generarlo dal config o creare le esche fuori dal servizio.
- [ ] **Canary creato da root**: `MkdirAll` crea `~/Documents` di root se manca,
  esche di root. Fare `chown` all'utente protetto.
- [ ] **Canary e indicizzatori**: tracker/baloo/deja-dup/rsync aprono le esche →
  `SIGKILL` in enforce. `exclude_exe` vale solo per la massa.
- [ ] **`ZT_SOCKET` rispettato anche dal demone root**: ignorarlo se euid 0.
- [ ] **QinQ**: il commento in `zerotrust.c` promette lo unwrap del doppio tag,
  il codice ne gestisce uno. Allineare.
- [ ] **`ftruncate` su kernel ≥ 6.2** non coperto (hook `lsm/file_truncate`,
  da caricare opzionale per non rompere i kernel vecchi).
- [ ] **Saturazione mappe da utente**: molti file in una dir protetta esauriscono
  `maxFilesPerPath`/16384 voci, le chiavi vere possono restare fuori. Serve un
  tetto per regola e priorità ai pattern di file.
- [ ] **Finestra di rescan**: un segreto riscritto via rename (nuovo inode) è
  scoperto fino al rescan successivo (30 s). Valutare inotify sulle dir protette.
- [ ] **Preset token dev** (GitLab `~/.config/gitlab/*`, `glab`) in `shield.example.yaml`.

## Decisioni aperte

- [ ] `block_subnets` scarta anche le risposte; con UFW `deny incoming` vale poco. Tenerlo?
- [ ] Profilo di default `home` in `audit`: ok, o meglio `enforce`?
- [ ] DoT `yes` nel profilo `paranoid` rompe i captive portal: accettabile?
- [ ] Release: restare `prerelease` finché gli hook LSM non sono collaudati in enforce?

## Estensioni possibili

- [ ] IPv6 e QinQ in XDP (LLMNR/mDNS su `ff02::`).
- [ ] Hook `ptrace`.
- [ ] **Controllo postura CFI** in `check_prereqs.sh`/`zt-probe`: IBT e shadow stack
  della CPU (`/proc/cpuinfo`: `ibt`, `user_shstk`), kCFI/IBT del kernel
  (`CONFIG_CFI_CLANG`, `CONFIG_X86_KERNEL_IBT`), binari whitelistati compilati con
  `-fcf-protection`. ZeroShield non implementa CFI (Go è memory-safe, il verifier
  vincola l'eBPF): lo verifica e lo segnala.
- [ ] Hardening unit: `ProtectSystem=strict`, `CapabilityBoundingSet`.
- [ ] Supporto btrfs (mappatura `st_dev` ↔ `s_dev`).
- [ ] Gruppo di regole per wallet e password manager.
- [ ] Ricaricamento config a caldo (SIGHUP).
- [ ] VPN kill-switch, auto-VPN, egress per processo: [`FEATURE_PLAN.md`](FEATURE_PLAN.md).

## Fatto (sintesi)

- Kernel: XDP (poisoning sport+dport, VLAN singola, frammenti, subnet LPM, radar),
  LSM (`file_open` con `FMODE_READ`/`O_TRUNC`, `unlink`, `rename` sorgente e
  destinazione, `path_truncate`, `deny_write` per regola).
- Demone: fail-closed, rescan con riconciliazione, multi-interfaccia, watchdog
  systemd a metà intervallo, whitelist solo binari di root, filtro proprietario
  contro symlink verso file di sistema, audit con rate-limit, `-version`.
- Canary fanotify a due gruppi, chiusura senza race, kill solo in enforce.
- UI: TUI Bubble Tea, GUI Wails, mock, IPC con testo sanificato (anti-ANSI).
- Qualità: CI a 5 job + `zt-probe` e test root su kernel del runner,
  govulncheck, gosec, Dependabot, toolchain Go 1.26.8.
- Distribuzione: pacchetti `zeroshield` e `zeroshield-gui` (`make package`),
  release automatica sui tag `v*`. La GUI dipende dal demone: chi installa
  la GUI ha sempre tutto (`apt install zeroshield-gui` tira dentro `zeroshield`).

## Limiti accettati

- Root locale può scaricare gli hook eBPF.
- Tool interpretati (npm, pip, gcloud, az) non whitelistabili in modo sicuro.
- Il segreto forte è la chiave FIDO2, non la whitelist.
