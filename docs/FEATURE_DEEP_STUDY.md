# FEATURE_DEEP_STUDY — studio con fonti di tutte le feature (2026-10)

Metodo: per ogni feature, stato dell'arte dal web → cosa copiamo → cosa è
nostro → effort. Niente implementato qui.

## 1. Install-session mode

Fonti: `chain-eye` (11 probe eBPF, sessioni npm/pip, 28 regole YAML),
`kojuto` (sandbox + honeypot credenziali + libfaketime, 100% TPR su dataset
Datadog), `trace-npm` (strace + HOME finta con canary), Datadog (execution
contexts che raggruppano eventi per albero `npm install`).
Originalità: i tool esistenti portano eBPF propri o sandbox pesanti. Nostro:
riuso sensori già attivi (LSM deny + canary + radar) con profilo temporaneo
paranoico + report. Zero kernel nuovo. Effort: giorni (wrapper + report).

## 2. Exec-allowlist fanotify

Fonti: `fapolicyd` (RHEL, trust da RPM db, `FAN_OPEN_EXEC_PERM`),
systemshardening.com (guida fanotify: permessi bloccanti, PIDFD anti-TOCTOU,
gap mmap anonimo coperto solo da LSM `mmap_file`).
Originalità: media. Il meccanismo è standard; originale è l'integrazione nel
profilo personale con learning-mode + allowlist esistenti. Effort: medio.
Nota: `mmap(PROT_EXEC)` anonimo resta buco noto anche lì.

## 3. Honeytoken con lineage

Fonti: Koney/Dynatrace (deception-as-code k8s, honeytoken + Tetragon),
Datadog execution contexts, kntrl ancestry `npm>node>curl`, TraceTree (grafi
NetworkX con firme temporali).
Originalità: packaging workstation-singola coi nostri sensori; lineage via
`/proc` racy ma economica. Effort: basso.

## 4. Incident bundle

Fonti: prassi comune (GhostCatcher quarantine vault, EDR forensics).
Originalità: nessuna — comodità. Effort: basso. Avviso: bundle con dati
sensibili → 0600 o cifratura.

## 5. Shadow-verify suite + 6. Self-hash

Fonti: Red Canary Coalmine/Vuvuzela (emulazione avversari schedulata),
GhostCatcher `selfguard` (sha256 + systemd watchdog), OmniShield (self-hash
60s), CIRISVerify (self-check con manifest firmato), gomcp antitamper (Go).
Originalità: alta per shadow-verify LSM sintetico (quasi nessuno fa self-test
continuo dell'enforcement in locale); commodity per self-hash. Effort:
ore (hash) / giorni (suite).

## 7. AI adattiva (solo baseline statistiche)

Fonti: Aura-Process-Guardian (z-score per-processo, offline, spiegabile),
KOBRA (paper: baseline per-app, 95% accuracy), memgar EWM (freeze baseline
per non farla derive sotto attacco), fullmon (baseline + rebase per server
statici), Novikova (tipicità vs malignità, senza ML).
Disegno nostro: EWM per exe (open/h, orari), freeze sotto attacco, z-score,
mai auto-enforce. Niente LLM (non deterministico), niente cloud (dati a casa).
Effort: medio. Opt-in, mai default.

## 8. USB allowlist

Fonti: USBGuard (maturo, rule language, GNOME integrato), kernel
`authorized_default`, Red Hat docs.
Verdetto: NON reimplementare. Integrazione documentata + check prerequisiti.

## Sintesi ordine

6 (ore) → 5/1 (giorni, valore) → 2/3 (medio) → 7 (opt-in) → 4 (comodità).
8 = docs. LKM gate resta Fase 3 con Secure Boot.

## Diagrammi delle pseudosoluzioni (architettura + flusso dati)

Legenda: i dati attraversano kernel → demone → UI. Ogni freccia dice cosa
viaggia davvero (syscall, mappa, socket, file).

### Install-session mode

```mermaid
flowchart TB
    subgraph U1["USER-SPACE: wrapper"]
        CLI["zt-shield run -- npm install x"] --> SNAP["salva profilo attivo"]
        SNAP --> STRICT["scrivi profilo paranoico temporaneo"]
        STRICT --> SPAWN["fork/exec comando + cattura PID root"]
        SPAWN --> WAIT["wait exit code"]
    end
    subgraph K1["KERNEL: sensori esistenti (nessun codice nuovo)"]
        LSM1["LSM deny → ringbuf audit_logs"]
        CAN1["fanotify canary → kill/log"]
        XDP1["XDP stats → mappa xdp_stats"]
    end
    subgraph D1["DEMONE: collector di sessione"]
        WAIT --> COLLECT["raccogli per PID-tree: negati, canary, top exe"]
        LSM1 -.->|"ringbuf"| COLLECT
        CAN1 -.->|"callback"| COLLECT
        XDP1 -.->|"poll mappe"| COLLECT
        COLLECT --> REP["report sessione (stdout + file)"]
        REP --> RESTORE["ripristina profilo salvato"]
    end
    RESTORE --> DEC{"negati o canary?"}
    DEC -- "si" --> BUNDLE["incident bundle tar.gz"]
    DEC -- "no" --> OK["ok"]
```
### Exec-allowlist fanotify (learning → enforce)

```mermaid
flowchart TB
    subgraph K2["KERNEL: fanotify"]
        EXE["execve()"] --> PERM["FAN_OPEN_EXEC_PERM: processo sospeso"]
        PERM --> QEV["evento pid+fd → demone"]
    end
    subgraph D2["DEMONE: watcher esteso"]
        QEV --> HASH["sha256 exe (o dev+ino)"]
        HASH --> DB{"in allowlist?"}
        DB -- "learning: registra candidata" --> CAND[("candidati su disco")]
        DB -- "enforce: si" --> ALLOW["FAN_ALLOW → parte"]
        DB -- "enforce: no" --> DENY["FAN_DENY + log + IPC"]
        CAND --> REV["review umana → allowlist"]
    end
    DENY -.->|"timeout risposta? fail-open + warn"| EXE
```

### Shadow-verify + self-hash (loop)

```mermaid
flowchart TB
    subgraph D3["DEMONE: ogni N minuti"]
        TICK["timer"] --> SH["open() sintetica su file finto protetto"]
        SH --> RES{"errno?"}
        RES -- "EACCES" --> OKH["hook vivo"]
        RES -- "passa" --> A1["allarme hook caduto → IPC + log"]
        OKH --> H["sha256 /proc/self/exe vs valore avvio"]
        H --> EQ{"uguale?"}
        EQ -- "si" --> OK2["integro"]
        EQ -- "no" --> A2["allarme binario sostituito"]
    end
    subgraph K3["KERNEL: come lo vede"]
        SH -.->|"LSM file_open nega"| RES
    end
```

### Baseline adattiva EWM (mai auto-enforce)

```mermaid
flowchart TB
    subgraph D4["DEMONE: collector + motore"]
        EV["eventi LSM/canary esistenti"] --> AGG["aggregatore: open/h per exe, finestra 5m"]
        AGG --> ST["stato EWM su disco (mean, var, frozen)"]
        ST --> FR{"frozen?"}
        FR -- "no" --> LEARN["aggiorna EWM → stabilita? congela"]
        FR -- "si" --> ZSCORE["z = (x-mean)/std"]
        ZSCORE --> THR{"z >= 3 per 3 finestre?"}
        THR -- "si" --> SUG["suggerimento in TUI (mai enforce)"]
        THR -- "no" --> QUIETE["silenzio"]
    end
    subgraph U4["UTENTE: decide"]
        SUG --> DEC2{"accetti?"}
        DEC2 -- "si" --> RULE["aggiungi allow / ignora exe"]
        DEC2 -- "no" --> IGN["scarta, resta frozen"]
    end
```
