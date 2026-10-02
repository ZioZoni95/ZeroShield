# Punti aperti — Local Zero-Trust Shield

Stato: repo strutturata e implementata. `go vet` pulito, `go test ./internal/...` ok, `make build` produce `bin/zt-shield`.
**Mai caricato nel kernel**: verifier non ancora visto.
Fix statici applicati e trascritti in `FIX_APPLICATI.md`; scenario lab aggiornato in `TESTING_LAB.md`.

## Origine e scopo (nota 2026-10-02)

Progetto personale nato dopo uno zero-day con ransomware, attacco ad Active
Directory e GitLab, furto di token, ingresso da VM Windows Server 2013.
La bonifica enterprise (2013, AD, GitLab server) è compito di altri: qui si
lavora solo sulla postazione personale, per sfruttare la lezione in locale.

Lezione tradotta in personale: i token piatti rubati fanno il disastro.
Quindi priorità a `extra_rules` per token dev (GitLab, `gh`, docker, kube,
aws), token a breve scadenza dove possibile, firma FIDO2, test lab di
furto-token (infostealer simulato, reverse shell) in VM isolata.

## Cosa questo tool è / non è (chiarimento dopo discussione)

- È: anti-furto-segreti locali (LSM dev+inode) + anti-poisoning rete (XDP +
  resolved/UFW) + hardening + FIDO2. Vedi `README.md` e `TESTING_LAB.md`.
- Non è: antivirus (zero firme/euristiche), firewall completo (solo ingresso,
  niente egress), anti-ransomware (niente hook su write/unlink/rename: la
  cifratura di `~/docs` passa), IDS, EDR, backup. Ransomware, keylogger,
  root locale, disco non cifrato restano fuori scopo (vedi Limiti accettati).

## Da fare

- [ ] **Abilitare `bpf` nei LSM.** Su questa macchina `/sys/kernel/security/lsm` = `lockdown,capability,landlock,yama,apparmor,ima,evm`: manca `bpf`. Procedura GRUB nel README, poi riavvio.
- [ ] **Test con root.** `sudo SHIELD_USER=$USER ./bin/zt-shield` e verifica che il verifier accetti i programmi.
  - Punto a rischio: `BPF_CORE_READ(task, mm, exe_file, f_inode)` in `lsm/file_open`.
  - Punto a rischio: aritmetica sul puntatore UDP con `ihl` variabile in `xdp_shield`.
- [ ] **Collaudo LSM** in `enforce`: `cat ~/.kube/config` negato, `kubectl` ok, test anti-bypass `cp /usr/bin/cat /tmp/ssh`.
- [ ] **Collaudo XDP:** UDP verso 5355 da un'altra macchina, `bpftool prog show name xdp_shield` con `kernel.bpf_stats_enabled=1`.
- [ ] **Penetration Test esterno (LAN/Wi-Fi):** Scansione stealth nmap, drop subnet XDP e test esfiltrazione segreti da reverse shell (documentato in `TESTING.md` - Test 5).
- [ ] **Verificare i percorsi dei browser** in `audit` sulla tua macchina (deb/snap/flatpak) prima di usare `public-wifi` in `enforce`.
- [ ] **Test di `harden_system.sh` e `install_service.sh`** (mai eseguiti, solo `bash -n`).
- [ ] **Preset `extra_rules` token dev** (lezione zero-day): GitLab
  (`~/.config/gitlab/*`, `.git-credentials`, `glab` hosts), `gh/hosts.yml`,
  docker, kube, aws già coperti — verificare in `audit` e fissare in
  `configs/shield.example.yaml`. Token brevi dove possibile, resto in LSM.
- [ ] **Test lab furto-token** in VM isolata (vedi `TESTING_LAB.md` Fase 2/5):
  infostealer simulato, reverse shell host-only, flood log con rate-limit.
- [ ] **Applicare fix pendenti** elencati in `FIX_APPLICATI.md` sez. 7
  (`main.go` multi-iface/Ticker/cleanup, UFW `allow OpenSSH`, unit
  `StartLimit`+`ExecStartPre`, sed `TESTING.md`).
- [ ] **Commit** delle modifiche (working tree con file modificati e non tracciati).

## Decisioni aperte

- [ ] `block_subnets`: scarta anche le risposte; con UFW `deny incoming` il valore è basso. Tenerlo?
- [ ] Profilo di default `home` in `audit`: ok, o meglio `enforce`?
- [ ] DoT `yes` nel profilo `paranoid` rompe i captive portal: accettabile?
- [ ] Token FIDO2: serve hardware; senza resta la chiave software.

## Estensioni possibili

- [ ] IPv6 e VLAN in XDP (LLMNR/mDNS su `ff02::`).
- [ ] Più interfacce XDP (VPN + Wi-Fi).
- [ ] Hook aggiuntivi: `unlink`/`rename` sui segreti, `ptrace`.
- [ ] Hardening unit systemd: `ProtectSystem=strict`, `CapabilityBoundingSet` (CAP_BPF, CAP_NET_ADMIN, CAP_PERFMON).
- [ ] Notifiche desktop sugli eventi bloccati.
- [ ] Supporto btrfs (mappatura `st_dev` ↔ `s_dev`).
- [ ] Regole per wallet crypto e password manager pronte in un gruppo dedicato.
- [ ] Ricaricamento config a caldo (SIGHUP).

## Fatto

- [x] Fix statici senza esecuzione test (dettagli in `FIX_APPLICATI.md`):
  XDP `sport`+`dport`/VLAN/frammenti, LSM `mm` a stadi + `FMODE_READ`,
  `resolveExe` con fallback + log, `Validate` severa (`/<8`, allow vuota,
  duplicati, strict YAML), `decodeEvent` esplicito + backoff + rate-limit,
  `AttachAll` + warning iface scoperte, `git` fuori da `ssh-keys`,
  `CheckFilesystem` btrfs/overlay.
- [x] Scenario lab reale aggiornato in `TESTING_LAB.md` (VM isolata,
  simulatori benigni, checklist post-fix).
- [x] Scaffold popolato: `bpf/`, `cmd/`, `internal/{config,lsm,xdp,audit}`, `scripts/`, `configs/`, `Makefile`.
- [x] Profili `home` / `corporate` / `public-wifi` / `paranoid`, regole per gruppo, `extra_rules`.
- [x] Modalità `audit` / `enforce`.
- [x] Whitelist per identità del binario (dev+inode di `exe_file`).
- [x] Rimozione voci obsolete dalle mappe (rescan).
- [x] Drop XDP di LLMNR/mDNS/NBT-NS.
- [x] Log JSON con `exe` del processo.
- [x] Test unitari su config e profili.

## Limiti accettati

- Root locale può scaricare gli hook eBPF.
- Tool interpretati (npm, pip, gcloud, az) non whitelistabili in modo sicuro.
- Il segreto forte è la chiave FIDO2, non la whitelist.
