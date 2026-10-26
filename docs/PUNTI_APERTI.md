# Punti aperti — ZeroShield

Aggiornato: 2026-10-26. Storico delle correzioni in [`FIX_APPLICATI.md`](FIX_APPLICATI.md),
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
| TUI / GUI / mock / IPC | ✅ GUI vera avviata sotto Xvfb contro il mock + frontend in un browser (21 controlli); socket provato con utenti reali |
| Demone `zt-shield` end-to-end | ⚠️ mai avviato (non parte senza BPF LSM): il collegamento IPC/VPN/netstat è compilato e analizzato, non eseguito |
| Pacchetti `.deb` | ✅ costruiti, installati e rimossi · release v0.0.1–v0.0.3 pubblicate (pre-release) · il pacchetto GUI da solo non si installa |
| Kill-switch VPN | 🟡 provato in un network namespace (54 controlli); mai su rete reale |
| Auto-VPN + helper Proton | 🟡 provati con comandi finti; mai con NetworkManager o Proton veri |
| `harden_system.sh` | 🟡 `--dry-run` + 21 controlli con comandi finti; mai su un sistema vero |
| `setup_fido2.sh` | ⚠️ mai eseguito (solo shellcheck) |
| Hook `lsm/file_truncate` (≥ 6.2), inotify sulle dir protette | 🟡 compilati e testati dove possibile (inotify sì); l'hook mai caricato su un kernel con BPF LSM |

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
- [ ] **Avviare il demone end-to-end** in una VM con `bpf` attivo: è l'unico modo di eseguire
  insieme IPC (socket 0600 dell'utente protetto), stato VPN ogni 5 s e porte in ascolto.
- [ ] **VPN in VM con snapshot**, con un tunnel vero: kill-switch (tunnel killato → `tcpdump`
  muto 60 s), `portal`, auto-VPN con NetworkManager, helper Proton. Procedura in
  [`VPN_SETUP.md`](VPN_SETUP.md).
- [ ] **Socket IPC con GUI e TUI vere** da due utenti diversi (il controllo è già provato con
  un client minimale; manca la prova end-to-end con le interfacce).
- [ ] **Watchdog systemd** stabile oltre 2 minuti (`systemctl status zt-shield`).
- [ ] **Percorsi dei browser** in `audit` (deb/snap; Flatpak non è coperto) prima di `public-wifi` in enforce.
- [ ] **`zt-probe` su un kernel con BPF LSM**: deve accettare anche `zt_file_truncate` (nuovo, mai caricato).
- [ ] **Unit systemd**: provare `ProtectSystem=strict` e `CapabilityBoundingSet` in VM (le direttive a basso rischio aggiunte sono validate solo con `systemd-analyze`).
- [ ] **Script** `harden_system.sh` (prima con `--dry-run`) e `setup_fido2.sh` in VM con snapshot.
- [ ] **Test furto-token** in VM isolata: infostealer simulato, reverse shell host-only.
- [ ] **Pentest LAN** da macchina esterna ([`TESTING.md`](TESTING.md), Test 5).

## Da fare — codice

Chiusi il 2026-10-26 (dettagli in [`FIX_APPLICATI.md`](FIX_APPLICATI.md)): canary sotto systemd
(`zt-shield dropin`), canary `chown` e `allow_exe`, `ZT_SOCKET` ignorato dal demone root, QinQ a
doppio tag, IPv6 in XDP, `ftruncate` ≥ 6.2, tetto per regola sulle mappe, inotify contro la
finestra di rescan, preset `glab`.

- [ ] **IPv6 nel radar**: XDP droppa il poisoning v6 ma il radar delle UI è IPv4 (chiave a 4
  byte); per v6 c'è solo un totale nel log. Richiede una seconda mappa e un campo nuovo in IPC.
- [ ] **IPv6 con extension header**: il poisoning dietro extension header passa (si guarda solo
  il next-header diretto).
- [ ] **Flatpak** nel preset `browsers`: serve il percorso del binario visto dal kernel, da
  verificare in audit su una macchina con Flatpak.
- [ ] **Browser snap/apt aggiornati**: dopo un aggiornamento l'inode del binario cambia e il
  browser resta fuori whitelist fino al rescan (inotify osserva i segreti, non i binari).
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
- Distribuzione: pacchetti `zeroshield` e `zeroshield-gui` (`make package`), con script VPN e
  `zt-mockd`; workflow di pre-release sui tag `v*` (mai eseguito). La GUI dipende dal demone: i
  due file vanno installati insieme (da una release scaricata a mano, il solo pacchetto GUI non si
  installa).

## Limiti accettati

- Root locale può scaricare gli hook eBPF.
- Tool interpretati (npm, pip, gcloud, az) non whitelistabili in modo sicuro.
- Il segreto forte è la chiave FIDO2, non la whitelist.
- Il BSSID di un access point si clona: non è autenticazione.
