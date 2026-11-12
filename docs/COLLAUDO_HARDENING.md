# Collaudo dell'hardening (0.0.17) — procedura per VM

Cosa **non** è ancora provato su un kernel reale e come provarlo. Da eseguire in una **VM con snapshot**, kernel con `bpf` in
`lsm=`, solo file finti (vedi [`TESTING_LAB.md`](TESTING_LAB.md)). Nessun comando qui tocca segreti veri.

Prima di ogni prova scrivi l'esito in [`PUNTI_APERTI.md`](PUNTI_APERTI.md): ✅ come atteso, ❌ diverso (con l'output).

## 0. Preparazione

```bash
mkdir -p ~/zs-collaudo && cd ~/zs-collaudo
for f in a1 a2 b1 n1; do echo "segreto-$f" > $f; done      # a* = regola A, b1 = regola B, n1 = non protetto
```

Nella GUI → Regole → *Proteggi un mio file* (o `extra_rules` nel config), due protezioni, **in `enforce`**:

| Nome | Percorsi | Programmi autorizzati | `deny_write` |
|---|---|---|---|
| `zs-a` | `zs-collaudo/a1`, `zs-collaudo/a2` | `/usr/bin/mv` | no |
| `zs-b` | `zs-collaudo/b1` | `/usr/bin/cat` | no |

(Con il percorso reale di `mv`/`cat` della VM: `readlink -f $(which mv)`. Su Ubuntu recente `mv` è `/usr/bin/gnumv`.)
Dopo *Applica*, `journalctl -u zt-shield -f` in un secondo terminale: ogni negato compare come `[BLOCCATO]`.

## 1. `inode_rename` (ZS-005) — il punto aperto più importante

| # | Comando | Atteso | Perché |
|---|---|---|---|
| 1 | `mv a2 n2` | ✅ passa | `mv` è autorizzato per A, la destinazione non è protetta |
| 2 | `mv n2 a2` | ✅ passa | sorgente non protetto, `a2` torna protetto dal rescan: se la destinazione è A, `mv` è autorizzato |
| 3 | **`mv a2 b1`** | ❌ **Permission denied** | sorgente di A (autorizzato), destinazione di B (`mv` non autorizzato per B): prima della 0.0.16 passava |
| 4 | `mv n1 b1` | ❌ Permission denied | sorgente non protetto, destinazione protetta da B |
| 5 | `cat b1` | ✅ passa | `cat` autorizzato per B |
| 6 | `cat a1` | ❌ Permission denied | `cat` non autorizzato per A |
| 7 | `python3 -c "import os; os.rename('a1','n3')"` | ❌ Permission denied | `python3` non è in lista per A |

Se il 3 passa, ZS-005 non è chiuso: fermati e allega il log.

## 2. Operazioni di modifica e `deny_write`

Con `zs-a` **senza** `deny_write` (programma non autorizzato = `bash`, `rm`, `ln`, `truncate`):

| # | Comando | Atteso |
|---|---|---|
| 1 | `echo x >> a1` | ✅ passa (scrittura in append, senza `deny_write`) |
| 2 | `echo x > a1` | ❌ negato (`O_TRUNC` conta come distruzione) |
| 3 | `rm a1` | ❌ negato |
| 4 | `ln a1 a1.hard` | ❌ negato (`inode_link`) |
| 5 | `truncate -s0 a1` | ❌ negato (`path_truncate`) |
| 6 | `python3 -c "f=open('a1','r+'); f.truncate(0)"` | ❌ negato (`file_truncate`, kernel ≥ 6.2; **mai verificato**: se passa, annotalo) |

Poi attiva `deny_write` su `zs-a`, *Applica*, e ripeti:

| # | Comando | Atteso |
|---|---|---|
| 7 | `echo x >> a1` | ❌ negato (ora anche la scrittura semplice) |
| 8 | `/usr/bin/mv a1 a1.bak && /usr/bin/mv a1.bak a1` | ✅ passa: `mv` è in lista, `deny_write` nega ai programmi **non** autorizzati |
| 9 | `python3 -c "open('a1','w')"` | ❌ negato |

## 3. Errori sulle mappe (0.0.16)

Difficile da provocare a mano. Con un config che protegge più file del tetto per regola (4096) guarda nel journal che compaia
`⚠️ mappe eBPF incomplete … la protezione è parziale` invece del solo `File protetti: N`.

## 4. XDP con traffico vero

IPv4 frammentato (primo frammento con MF) e IPv6 con extension header: da un'altra macchina della stessa rete (o un namespace):

```bash
# da un host sulla stessa LAN, contro l'IP della VM (installare scapy)
python3 - <<'PY'
from scapy.all import *
dst = "IP_DELLA_VM"
pkt = IP(dst=dst)/UDP(sport=5355, dport=49152)/Raw(b"x"*3000)
send(fragment(pkt, fragsize=1200), verbose=0)                       # IPv4 frammentato, risposta LLMNR finta
pkt6 = IPv6(dst="FE80::VM%IFACE")/IPv6ExtHdrHopByHop()/UDP(sport=5353, dport=5353)/Raw(b"x")
send(pkt6, verbose=0)                                                # IPv6 con hop-by-hop, mDNS
PY
```

Atteso sulla VM: il contatore del radar (`zt-tui` / GUI) sale per l'IP sorgente, e `sudo bpftool map dump name xdp_stats` mostra i drop.
Senza la correzione 0.0.12 il primo caso non veniva contato.

## 5. Descrittori di file ereditati (limite noto, non una correzione)

```bash
python3 - <<'PY'
import os, subprocess
fd = os.open('b1', os.O_RDONLY)           # lo fa un processo autorizzato (qui: eseguire con un programma in lista)
print(subprocess.run(['/usr/bin/cat', f'/proc/self/fd/{fd}'], pass_fds=[fd], capture_output=True))
PY
```

Atteso: l'accesso tramite l'fd **passa** (l'hook controlla l'`open`, non l'uso). Serve come prova del limite dichiarato in README.

## 7. Audit delle connessioni in uscita (0.0.20)

Con il demone in `audit` e la protezione `zs-b` della sezione 0 (`/usr/bin/cat` autorizzato per B):

| # | Comando | Atteso nel journal |
|---|---|---|
| 1 | `journalctl -u zt-shield -b \| grep "connessioni in uscita"` | `📤 Audit delle connessioni in uscita attivo (solo registro).` (altrimenti la riga con il motivo) |
| 2 | `python3 -c "import socket; f=open('b1'); s=socket.create_connection(('example.org',443),5)"` con `python3` autorizzato per B | `📤 [USCITA] regola=zs-b … → <IP>:443 (internet, nuova destinazione)` |
| 3 | lo stesso comando una seconda volta | **nessuna** nuova riga (stessa coppia) |
| 4 | `python3 -c "import socket; s=socket.create_connection(('127.0.0.1',22),2)"` subito dopo aver letto `b1` | nessuna riga (loopback) |
| 5 | connessione a una destinazione **senza** aver letto prima un segreto | nessuna riga |
| 6 | stessa connessione 70 secondi dopo la lettura | nessuna riga (finestra scaduta) |

La GUI → Eventi → «uscita» deve mostrare la riga del punto 2 con l'ambito `internet`.

## 6. Pulizia

Togli le due protezioni (GUI → Regole → Elimina → Applica), poi `rm -r ~/zs-collaudo`: finché esistono, i file sono protetti.
