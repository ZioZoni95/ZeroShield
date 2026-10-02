# Canary + fanotify — guida e design per ZeroShield

## 1. File canary: l'esca

Un **canary** (canarino in miniera) è un file finto e appetibile piazzato dove
il ransomware guarda per primo: `~/Documents/000_passwords.xlsx`,
`~/.canary_wallet.dat`. Tu non lo tocchi mai; qualunque accesso è sospetto.
Il ransomware commodity cifra in massa e in ordine: becca l'esca entro secondi
dal via, molto prima di finire i tuoi file veri.

- Costo: zero. Un file, qualche byte.
- Limite onesto: ransomware mirato che evita esche passa oltre. Per quello
  serve anche il punto 3 (euristica di massa).

## 2. fanotify: le orecchie sul filesystem

**fanotify** è una API Linux (userspace, niente kernel da scrivere) che dice
al demone *ogni* open/write/rename/unlink in una directory, con PID e path
del colpevole. Differenze pratiche:

| Strumento | Vede | Blocca prima | Costo |
|---|---|---|---|
| `inotify` | eventi, ma senza PID affidabile né blocco | no | basso, ma cieco |
| `fanotify` | eventi + PID + path, può negare l'operazione | sì (`FAN_DENY`) | medio, una syscall per evento |
| eBPF LSM (già tuo) | solo `open`, con identità binario | sì | basso, ma cieco su rename/unlink |

Per ransomware serve proprio ciò che LSM non ha: **rename/unlink in massa**
(la cifratura tipica è scrivi `.locked` + cancella originale) e **PID da killare**.

## 3. Design in ZeroShield

```
~/Documents/.canary-01 ──tocco──▶ fanotify ──▶ demone (root)
                                          ├─▶ kill PID offensore
                                          ├─▶ evento IPC → TUI/GUI + notifica
                                          └─▶ log con PID, exe, path
```

- **Trigger 1 — tocco canary:** qualsiasi write/unlink/rename di un canary =
  kill immediato del PID + notifica. Falsi positivi solo se lo tocchi tu:
  i tuoi editor vanno in allowlist, e i canary hanno nomi che non apri mai.
- **Trigger 2 — euristica massa:** più di N (es. 50) rename/unlink in 10s fuori
  dalle dir escluse (cache browser, build) = allarme + opzione freeze
  (default: avvisa; kill solo canary). Taratura in `audit` prima.
- **Modalità:** riusa `audit`/`enforce` esistenti. In audit logga e basta.

## 4. Cosa NON fa (limiti accettati)

- Non ferma ransomware che cifra **in-place** senza rename e schiva i canary.
- Non recupera file già cifrati: serve backup offline (unico antidoto reale).
- `fanotify` vede tutto il filesystem: su dir enormi (build, `.cache`) va
  escluso o il demone macina CPU. Allowlist di path rumorosi obbligatoria.
- Root locale lo stacca come gli hook eBPF (stesso limite del resto).

## 5. Piano di test in lab (VM, dati finti)

1. Simulatori benigni: script che tocca canary → kill + notifica attesa.
2. Simulatore massa: rinomina 200 file fake → allarme euristica, nessun kill
   in audit.
3. Falsi positivi: compila progetto, naviga cache → zero allarmi dopo allowlist.
4. Misura CPU del demone durante copia massiccia (target <5%).

## 6. Fonti online e codice di riferimento

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
