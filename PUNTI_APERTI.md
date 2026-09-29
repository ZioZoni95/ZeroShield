# Punti aperti — Local Zero-Trust Shield v2

Stato: codice C + Go compila (`clang`, `bpf2go`, `go build`). **Mai caricato nel kernel**, verifier non ancora visto.

## Da fare

- [ ] **Test con root.** Eseguire `sudo SHIELD_USER=$USER ./zt-shield` e verificare che il verifier accetti i programmi.
  - Punto a rischio: `BPF_CORE_READ(task, mm, exe_file, f_inode)` nel hook `lsm/file_open`.
  - Punto a rischio: aritmetica sul puntatore UDP con `ihl` variabile in `xdp_shield`.
- [ ] **Abilitare `bpf` nei LSM.** Su questa macchina `/sys/kernel/security/lsm` = `lockdown,capability,landlock,yama,apparmor,ima,evm`: manca `bpf`. Serve la procedura GRUB + riavvio.
- [ ] **Collaudo LSM.** `cat ~/.kube/config` deve dare Permission denied, `kubectl get pods` deve funzionare.
- [ ] **Test anti-bypass.** `cp /usr/bin/cat /tmp/ssh && /tmp/ssh ~/.kube/config` deve restare bloccato.
- [ ] **Collaudo XDP.** UDP verso porta 5355 da un'altra macchina LAN, controllo con `bpftool prog show name xdp_shield` (con `kernel.bpf_stats_enabled=1`).
- [ ] **Installare `llvm-strip`** oppure tenere `-no-strip` nel `go:generate` (già impostato nel doc).

## Decisioni aperte

- [ ] **`SHIELD_BLOCK`.** Bloccare subnet in XDP scarta anche le risposte. Con UFW `deny incoming` già attivo il valore è basso. Decidere se tenerlo o togliere la feature.
- [ ] **DNS-over-TLS / DNSSEC.** Lasciato commentato nello script: rompe i nomi interni aziendali. Attivare solo se non servono.
- [ ] **Chiave FIDO2.** Serve un token hardware. Senza, resta la chiave software con passphrase (protezione più debole).
- [ ] **Whitelist tool.** Valutare se `git` e `aws` vanno tenuti: un `git` lanciato da uno script malevolo legge `.git-credentials`.

## Estensioni possibili

- [ ] Parser IPv6 in XDP (LLMNR/mDNS su `ff02::`), oggi coperti solo da `systemd-resolved`.
- [ ] Gestione VLAN tag in XDP.
- [ ] Hook aggiuntivi: `unlink`/`rename` sui segreti, `ptrace`.
- [ ] Hardening unit systemd: `ProtectSystem=strict`, ecc.
- [ ] Supporto btrfs: `st_dev` userspace ≠ `s_dev` kernel, la chiave dev+inode non matcha sui subvolume.
- [ ] Rimozione dalle mappe dei file/binari non più presenti (oggi il rescan solo aggiunge).

## Limiti accettati

- Root locale può scaricare gli hook eBPF: lo scudo non difende da privilege escalation riuscita.
- Il segreto forte è la chiave FIDO2, non la whitelist.

## File

- `gemini-code-1790668303538.md` — proposta v2 con script di setup completo.
- `PUNTI_APERTI.md` — questo file.
