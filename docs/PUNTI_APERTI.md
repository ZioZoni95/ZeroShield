# Punti aperti — ZeroShield

Aggiornato: 2026-10-05. Storico delle correzioni in [`FIX_APPLICATI.md`](FIX_APPLICATI.md),
esiti dei test reali in [`TEST_SANDBOX.md`](TEST_SANDBOX.md),
piano feature unificato in [`ROADMAP.md`](ROADMAP.md).

## Stato in una riga

Compila, CI verde (lint, test `-race`, test degli script, eBPF, GUI nel browser, sicurezza,
pacchetti `.deb`). **XDP e canary collaudati su kernel reale; i 4 hook LSM passano il verifier ma
non sono mai stati agganciati**: il blocco effettivo dei segreti resta da vedere in VM. Lo stack
VPN è provato solo in un network namespace e con comandi finti.

| Componente | Stato |
|---|---|
| XDP anti-poisoning + radar | ✅ kernel reale (drop verificato su loopback) |
| Canary fanotify | ✅ kernel reale (esca, massa, kill in enforce) |
| Hook LSM (`file_open`, `unlink`, `rename`, `truncate`) | 🟡 verifier ok sul runner GitHub, mai agganciati |
| TUI / GUI / mock / IPC | ✅ (GUI provata in un browser vero con demone simulato; socket provato con utenti reali) |
| Pacchetti `.deb` | ✅ installazione e rimozione provate |
| Kill-switch VPN | 🟡 provato in un network namespace (54 controlli); mai su rete reale |
| Auto-VPN + helper Proton | 🟡 provati con comandi finti; mai con NetworkManager o Proton veri |
| Script di sistema (`harden_system.sh`, `setup_fido2.sh`) | ⚠️ mai eseguiti (solo shellcheck) |

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
  [`TESTING_LAB.md`](TESTING_LAB.md) in `enforce` (è l'unico pezzo mai visto funzionare).
- [ ] **VPN in VM con snapshot**, con un tunnel vero: kill-switch (tunnel killato → `tcpdump`
  muto 60 s), `portal`, auto-VPN con NetworkManager, helper Proton. Procedura in
  [`VPN_SETUP.md`](VPN_SETUP.md).
- [ ] **Socket IPC con GUI e TUI vere** da due utenti diversi (il controllo è già provato con
  un client minimale; manca la prova end-to-end con le interfacce).
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
- [ ] **VPN: il demone non applica il kill-switch.** È una scelta (il demone resta di sola
  misura), ma se la vuoi automatica serve un comando con autenticazione, che oggi il socket
  di sola lettura non ha.

## Decisioni aperte

- [ ] `block_subnets` scarta anche le risposte; con UFW `deny incoming` vale poco. Tenerlo?
- [ ] Profilo di default `home` in `audit`: ok, o meglio `enforce`?
- [ ] DoT `yes` nel profilo `paranoid` rompe i captive portal: accettabile?
- [ ] Release: restare `prerelease` finché gli hook LSM non sono collaudati in enforce?
- [ ] `nm_vpn.sh`: tenere `AUTO_DOWN` o toglierlo del tutto (il BSSID si clona)?

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
- Distribuzione: pacchetti `zeroshield` e `zeroshield-gui` (`make package`), con script VPN e
  `zt-mockd`; release automatica sui tag `v*`. La GUI dipende dal demone: chi installa la GUI
  ha sempre tutto.

## Limiti accettati

- Root locale può scaricare gli hook eBPF.
- Tool interpretati (npm, pip, gcloud, az) non whitelistabili in modo sicuro.
- Il segreto forte è la chiave FIDO2, non la whitelist.
- Il BSSID di un access point si clona: non è autenticazione.
