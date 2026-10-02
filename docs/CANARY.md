# Canary anti-ransomware — guida d'uso e design

Il canary è il terzo livello di ZeroShield accanto a LSM (segreti) e XDP (rete):
file-esca piazzati dove un ransomware guarda per primo, sorvegliati con
**fanotify**. Chi tocca un'esca viene segnalato (audit) o ucciso (enforce).
Collaudato su kernel reale il 2026-10-02 ([`TEST_SANDBOX.md`](TEST_SANDBOX.md)).

## 1. Cosa fa, in concreto

Due allarmi, indipendenti:

| Trigger | Cosa lo scatena | `audit` | `enforce` |
|---|---|---|---|
| **Tocco esca** | qualsiasi processo apre, modifica o chiude in scrittura un file esca | log + evento UI + notifica | **`SIGKILL` al processo** + log + evento + notifica |
| **Massa** | un singolo PID fa ≥ `burst_count` scritture/cancellazioni/rinomine in `burst_secs` secondi nelle cartelle sorvegliate | log + evento UI | log + evento UI (**mai kill**: troppi falsi positivi) |

- La modalità è quella globale (`mode:` nel config): niente impostazione separata.
- Il kill non colpisce mai PID 1 né il demone stesso.
- Un'esca è un file di 4 KB di byte casuali: non contiene nulla, si può cancellare.

Perché funziona: il ransomware commodity cifra in massa e in ordine alfabetico
o di directory. Un'esca chiamata `.canary-accounts.xlsx` in `~/Documents` viene
toccata nei primi secondi, molto prima dei tuoi file veri.

## 2. Quando usarlo (e quando no)

- **Sì** su una workstation dove ransomware o wiper sono un rischio reale e hai
  già un backup offline (il canary riduce il danno, non lo annulla).
- **Prima in `audit` per almeno una settimana**: devi scoprire chi tocca le esche
  in modo legittimo (backup, indicizzatori, sincronizzazioni cloud).
- **No** come unica difesa: non sostituisce backup né aggiornamenti.

## 3. Attivazione passo passo

### 3.1 Config

In `/etc/zt-shield/shield.yaml`:

```yaml
mode: audit                 # prima settimana: solo log
canary:
  enabled: true
  dirs: ["Documents"]       # relative alla home o assolute
  names: [".canary-accounts.xlsx", ".canary-wallet.dat", ".canary-backup.zip"]
  burst_count: 50           # soglia allarme di massa...
  burst_secs: 10            # ...in questa finestra
  exclude_exe: ["restic", "rsync", "cc1"]   # esclusi SOLO dall'allarme di massa
```

Se `dirs`/`names`/soglie mancano, valgono i default mostrati sopra.
Nomi con il punto iniziale: i file manager li nascondono, quindi tu non li apri per sbaglio.

### 3.2 Servizio systemd (obbligatorio)

La unit monta la home in sola lettura (`ProtectHome=read-only`), ma le esche vanno
create proprio lì. Senza questo override il canary non parte (log
`⚠️ canary non attivo: canary write ...: read-only file system`):

```bash
sudo systemctl edit zt-shield
# nell'editor:
[Service]
ReadWritePaths=/home/<utente>/Documents
```

Una riga `ReadWritePaths=` per ogni cartella in `dirs`.

### 3.3 Avvio e verifica

```bash
sudo systemctl restart zt-shield
journalctl -u zt-shield -n 30
```

Righe attese:

```text
🐤 esca creata: /home/mario/Documents/.canary-accounts.xlsx (non aprirla mai: ogni tocco e' allarme)
🐤 Watcher canary attivo.
```

`fanotify` richiede root (`CAP_SYS_ADMIN`): se il demone non lo è, il canary non
parte ma LSM e XDP restano attivi.

## 4. Cosa vedi quando scatta

Log (journal o terminale):

```text
🐤 [CANARY-ALERT] pid=4242 exe=/usr/bin/python3.12 kind=open path=/home/mario/Documents/.canary-wallet.dat motivo=tocco esca canary (audit: solo log)
🐤 [CANARY-KILL] pid=4242 exe=/usr/bin/python3.12 kind=open path=/home/mario/Documents/.canary-wallet.dat motivo=tocco esca canary
🐤 [CANARY-ALERT] pid=5151 exe=/usr/bin/gpg kind=delete path= motivo=massa rename/delete oltre soglia
```

- **TUI** (`zt-tui`): tab Eventi, righe `🐤 CANARY` / `🐤 KILL` in testa.
- **GUI** (`zt-gui`): tabella eventi + notifica desktop per ogni tocco (anche in audit).
- `[CANARY-KILL-FALLITO]`: il processo era già uscito o non uccidibile, guarda il PID.

Cosa fare dopo un `CANARY-KILL`: isola la macchina dalla rete, guarda `exe=` e il
processo padre nel journal, controlla i file modificati di recente, ripristina dal backup.

## 5. Taratura in `audit`

1. Lascia `mode: audit` per una settimana di lavoro normale.
2. `journalctl -u zt-shield | grep CANARY` ogni giorno.
3. Per ogni `exe` legittimo:
   - **tocca un'esca** (backup, sync cloud, antivirus, indicizzatore): escludi la
     cartella delle esche dal suo percorso. Esempi: `restic backup --exclude '.canary-*'`,
     `rsync --exclude='.canary-*'`, Déjà Dup → "Cartelle da ignorare".
     `exclude_exe` **non** basta: protegge solo dall'allarme di massa, il tocco
     esca resta un kill in enforce.
   - **supera la soglia di massa** (compilazioni, `git checkout`, estrazione archivi):
     aggiungi una sottostringa del suo path a `exclude_exe`, oppure togli quella
     cartella da `dirs`.
4. Quando per qualche giorno compaiono solo allarmi che non sai spiegare, passa a `mode: enforce`.

## 6. Provarlo senza rischi

In **audit** (nessun kill), dalla tua sessione:

```bash
cat ~/Documents/.canary-wallet.dat > /dev/null      # -> CANARY-ALERT kind=open
mkdir -p ~/Documents/zt-mass && cd ~/Documents/zt-mass
for i in $(seq 1 60); do echo x > f$i; rm f$i; done  # -> allarme di massa
cd .. && rmdir zt-mass
```

In **enforce**, solo in VM: `sh -c 'exec 3<~/Documents/.canary-wallet.dat; sleep 30'`
deve morire subito (`Killed`). Gli stessi controlli sono automatici in
`make test-root` (`internal/canary/start_root_test.go`).

## 7. Disattivare e pulire

```bash
sudoedit /etc/zt-shield/shield.yaml      # canary.enabled: false
sudo systemctl restart zt-shield
rm ~/Documents/.canary-*                 # il demone non le cancella mai da solo
```

Le esche esistenti non vengono mai sovrascritte (potrebbero essere file tuoi con lo
stesso nome): se le cancelli, vengono ricreate al prossimo avvio con `enabled: true`.

## 8. Design interno

```
~/Documents/.canary-* ─open/modify/close_write─▶ gruppo fanotify "esche" (con fd)
                                                    └─ path via /proc/self/fd ─▶ Detector
~/Documents/          ─delete/move/close_write─▶ gruppo fanotify "dir" (FAN_REPORT_FID)
                                                    └─ solo PID ─────────────▶ Detector
Detector ─ esca? ─▶ kill (enforce) / alert (audit)
         ─ ≥ soglia per PID in finestra? ─▶ alert (+ cooldown = 1 allarme per finestra)
         └─▶ callback demone ─▶ log + IPC (TUI/GUI) con testo sanificato
```

Perché due gruppi: il kernel accetta `FAN_DELETE`/`FAN_MOVED_*` solo su gruppi
`FAN_REPORT_FID`, che però non consegnano fd (quindi niente path). Le esche hanno
bisogno del path, la massa solo del PID. Con un gruppo solo il canary non partiva
(`EINVAL`, bug trovato sul kernel reale). La chiusura ferma i loop con `poll()` su
un pipe di stop prima di chiudere gli fd, per evitare che un fd riusato rubi eventi.

## 9. Confronto con le alternative

| Strumento | Vede | Blocca | Note |
|---|---|---|---|
| `inotify` | eventi senza PID | no | inutile per attribuire |
| **`fanotify`** (usato) | eventi + PID (+ path con fd) | kill a posteriori | userspace, nessun codice kernel |
| `fanotify` `FAN_OPEN_PERM` | come sopra | **nega prima** dell'apertura | estensione possibile, costa latenza su ogni open |
| eBPF LSM di ZeroShield | open/unlink/rename/truncate dei segreti | nega prima | per i segreti, non per i documenti |

## 10. Limiti

- Non ferma un ransomware che cifra **in-place** senza rinomine e salta le esche.
- Il kill arriva **dopo** il tocco: qualche file può essere già cifrato.
- Non recupera nulla: l'unico antidoto è il backup offline.
- Root locale lo spegne come il resto dello scudo.
- Cartelle enormi in `dirs` (build, `.cache`) costano CPU e danno falsi allarmi di massa.
- Aperti (vedi [`PUNTI_APERTI.md`](PUNTI_APERTI.md)): esche create con proprietario
  root, override systemd manuale.

## 11. Fonti e codice di riferimento

Documentazione ufficiale:

- `fanotify(7)` man page — API completa, classi, eventi, permessi:
  https://man7.org/linux/man-pages/man7/fanotify.7.html
- `fanotify_init(2)` / `fanotify_mark(2)` — syscall e flag:
  https://man7.org/linux/man-pages/man2/fanotify_init.2.html
- Kernel admin-guide, filesystem monitoring (anche `FAN_FS_ERROR`):
  https://docs.kernel.org/6.10/admin-guide/filesystem-monitoring.html
- Guida operativa con esempi C completi (permessi, DFID_NAME, allowlist exec):
  https://www.systemshardening.com/articles/linux/linux-fanotify-security-monitoring/

Codice sorgente da studiare (non copiare alla cieca: ognuno ha trade-off):

- **CanaryWatch** (Python, `ctypes` su libc): canary + `FAN_OPEN_PERM` + kill
  PID + `FAN_DENY`. Il più vicino al nostro Trigger 1, leggibile in un'ora:
  https://github.com/Tr1sH-G/CanaryWatch
  (file chiave: `canarywatch.py` — vedi costanti, struct metadata, risposta DENY)
- **RansomShield** (Rust, systemd): honeypot + entropia + burst + quarantena
  via rename + `SIGSTOP` prima di `SIGKILL` + trusted-exe per sha256. Il modello
  per i nostri Trigger 1+2 e per `monitor` vs `enforce`:
  https://github.com/Spellskite-coding/RansomShield
- `dmacvicar/fanotify_example`: `FAN_DELETE` e `FAN_REPORT_FID` (kernel 5.1+):
  https://github.com/dmacvicar/fanotify_example
- LTP `fanotify03.c`: matrice permessi per tipo di mark (test di riferimento):
  https://github.com/linux-test-project/ltp/blob/master/testcases/kernel/syscalls/fanotify/fanotify03.c
- Sample kernel `fs-monitor.c` (parser eventi `FAN_FS_ERROR`):
  https://gbmc.googlesource.com/linux/+/12a75f2d9f73172161d096fc61cacc4989250604/samples/fanotify/fs-monitor.c

Librerie Go (nessuna dominante — valutare `opcoder0/fanotify` o syscall dirette
via `golang.org/x/sys/unix`, che già usiamo):

- https://github.com/opcoder0/fanotify (MIT, con validazione flag per kernel)
- https://github.com/zemul/go-fanotify (wrapper alte prestazioni)
- https://gitlab.com/zygoon/go-fanotify (API tipizzata + permessi allow/deny)
- Nota: `fsnotify` usa inotify, **non** fanotify (niente PID, niente DENY):
  https://github.com/fsnotify/fsnotify
