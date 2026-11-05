# Collaudo degli hook LSM su un kernel reale — 2026-11-05

Prima volta in cui il blocco dei segreti è stato visto funzionare. **Non è una VM**: è il PC di sviluppo, con un file
**finto** (`~/zs-test/segreto.txt`) protetto da una regola creata dalla GUI. Nessun segreto vero è stato esposto.

## Ambiente

| | |
|---|---|
| Kernel | `7.0.0-42-generic` (Ubuntu), `bpf` tra gli LSM attivi (`lockdown,capability,landlock,yama,apparmor,bpf,ima,evm`) |
| Filesystem della home | ext4 (famiglia ext2/ext3/ext4 di `statfs`): quello supportato |
| Versione | `0.0.6~dev+7c22899` (demone e GUI), installata dal `.deb` costruito dai sorgenti |
| Modalità | **generale `audit`**; solo la regola `prova` in **`enforce`** (modalità per regola, `mode: enforce`) |
| Regola | `prova`: `paths: [zs-test/segreto.txt]`, `allow: [/usr/bin/nano]`, creata con *Regole → Proteggi un mio file* e applicata con *Applica* (pkexec → `config-apply`) |

## Esiti

| Prova | Esito | Hook coinvolto |
|---|---|---|
| `cat ~/zs-test/segreto.txt` | ✅ **negato** (`Permission denied`) | `file_open` |
| copia di `cat` in `/tmp/t/cat` e lettura | ✅ **negato**: conta l'identità del file (inode), non il nome | `file_open` |
| `mv segreto.txt segreto.txt.x` | ✅ **negato** | `inode_rename` |
| `rm segreto.txt` | ✅ **negato** | `inode_unlink` |
| `truncate -s 0 segreto.txt` | ✅ **negato** | apertura in scrittura / troncamento |
| `: > segreto.txt` (O_TRUNC da shell) | ✅ **negato** | `file_open` (O_TRUNC) |
| `echo prova >> segreto.txt` | ✅ **passa** (scrittura semplice non negata senza `deny_write`: comportamento documentato) | — |
| `ln segreto.txt segreto.txt.hard` | ⚠️ **passa**: creare un secondo nome non è bloccato (non c'è un hook sui link) | — |
| `cat`, `rm`, `mv` sul secondo nome | ✅ **negati**: la protezione è sull'inode, quindi vale anche per l'alias | `file_open`, `inode_unlink`, `inode_rename` |
| Altre regole (`cloud-creds`, ...) | ✅ restano in **audit**: `oh-my-posh` risulta solo osservato, non bloccato | modalità per regola |
| Applica dalla GUI | ✅ password via `pkexec`, config scritto nel blocco gestito, copia di sicurezza, riavvio | `config-apply` |
| `nano segreto.txt` (programma autorizzato) | ✅ si apre (riferito da chi ha fatto la prova) | whitelist |
| Demone attivo per 9 minuti con `WatchdogSec=30` | ✅ nessun riavvio (`NRestarts=0`) | watchdog |

Il demone ha registrato ogni tentativo: `🚨 [BLOCCATO] regola=prova PID=… comm='…'`, compreso l'indicizzatore di GNOME
(`localsearch-extractor-3`) che ha provato a leggere il file da solo.

## Cosa NON è stato provato

- l'hook `file_truncate` (`ftruncate` su un descrittore già aperto, kernel ≥ 6.2) e `path_truncate` isolatamente: nel journal compare solo «Hook LSM 'file_open' attivo», quindi non è nemmeno confermato che gli altri siano segnalati a log (il loro effetto è visibile: rinomina e cancellazione negate);
- `deny_write: true` (blocco anche delle scritture semplici);
- le protezioni **predefinite** (ssh, kubeconfig, token, gpg) in `enforce` con i programmi veri (`ssh`, `kubectl`, `git`...);
- il comportamento dopo un aggiornamento del binario autorizzato (inode che cambia);
- una VM isolata con snapshot e il resto di [`TESTING_LAB.md`](TESTING_LAB.md) (pentest, VPN, hardening, FIDO2).

## Difetti emersi

- Nella riga `[BLOCCATO]` il campo `exe=` è a volte vuoto (visto con `cat`, non con `rm`, `mv`, `truncate`, `bash`): il processo negato
  esce prima che il demone legga `/proc/<pid>/exe`. Non incide sulla protezione, ma l'evento non dice sempre *quale* programma è stato bloccato.
- Un indicizzatore di sistema (`localsearch`) viene negato come qualunque altro programma non autorizzato: proteggere una cartella di
  documenti in `enforce` ne blocca l'indicizzazione. Per segreti veri è voluto; per documenti comuni va messo tra i programmi autorizzati
  (se ha un percorso di root) o la regola lasciata in `audit`.
- Prima di questo collaudo la GUI aperta dall'icona non poteva usare `pkexec` (`NoNewPrivileges` nell'unit dell'icona, ereditato dalla GUI):
  corretto nella 0.0.6.

## Radar con un volume alto (stessa giornata)

Con `lo` aggiunto alle interfacce filtrate (`interface: enx…,wlp1s0,lo`, applicato con `pkexec zt-shield config-apply`) sono stati inviati 250 pacchetti UDP a
`127.0.0.1:5355`. Lo stato del demone ha riportato `127.0.0.1` con 90 drop al primo rescan e **250** al successivo: il conteggio del kernel è corretto e il radar
si aggiorna ogni 30 secondi (non in tempo reale). Oltre i 100 drop totali la sorgente è classificata «da verificare». Dopo la prova `lo` è stata tolta.

## Come ripeterlo

```bash
mkdir -p ~/zs-test && echo "segreto finto" > ~/zs-test/segreto.txt
# GUI: Regole -> + Proteggi un mio file -> ~/zs-test/segreto.txt, programma nano, modalità Blocca -> Applica
cat ~/zs-test/segreto.txt                                  # Permission denied
mkdir -p /tmp/t && cp /usr/bin/cat /tmp/t/cat && /tmp/t/cat ~/zs-test/segreto.txt   # Permission denied (stesso nome, altro inode)
mv ~/zs-test/segreto.txt ~/zs-test/x                       # Permission denied
rm ~/zs-test/segreto.txt                                   # Permission denied
journalctl -u zt-shield -n 20                              # righe [BLOCCATO]
```

Per pulire: *Regole → Elimina* la protezione → *Applica*, poi `rm -r ~/zs-test` (finché la regola c'è, nemmeno tu puoi cancellare il file).
