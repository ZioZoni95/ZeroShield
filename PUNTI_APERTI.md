# Punti aperti — Local Zero-Trust Shield

Stato: repo strutturata e implementata. `go vet` pulito, `go test ./internal/...` ok, `make build` produce `bin/zt-shield`.
**Mai caricato nel kernel**: verifier non ancora visto.

## Da fare

- [ ] **Abilitare `bpf` nei LSM.** Su questa macchina `/sys/kernel/security/lsm` = `lockdown,capability,landlock,yama,apparmor,ima,evm`: manca `bpf`. Procedura GRUB nel README, poi riavvio.
- [ ] **Test con root.** `sudo SHIELD_USER=$USER ./bin/zt-shield` e verifica che il verifier accetti i programmi.
  - Punto a rischio: `BPF_CORE_READ(task, mm, exe_file, f_inode)` in `lsm/file_open`.
  - Punto a rischio: aritmetica sul puntatore UDP con `ihl` variabile in `xdp_shield`.
- [ ] **Collaudo LSM** in `enforce`: `cat ~/.kube/config` negato, `kubectl` ok, test anti-bypass `cp /usr/bin/cat /tmp/ssh`.
- [ ] **Collaudo XDP:** UDP verso 5355 da un'altra macchina, `bpftool prog show name xdp_shield` con `kernel.bpf_stats_enabled=1`.
- [ ] **Verificare i percorsi dei browser** in `audit` sulla tua macchina (deb/snap/flatpak) prima di usare `public-wifi` in `enforce`.
- [ ] **Test di `harden_system.sh` e `install_service.sh`** (mai eseguiti, solo `bash -n`).
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
