# 🛡️ Local Zero-Trust Shield (`zt-shield`)

> **Kernel-Enforced Local Security Agent for Developer Workstations**  
> *Difesa in profondità locale a livello kernel contro movimenti laterali, reti ostili e furto di credenziali.*

---

## 📋 Panoramica Architetturale

`zt-shield` è un agente di sicurezza locale progettato per postazioni di sviluppo Linux che operano in reti non fidate o ambienti potenzialmente compromessi (LAN pubbliche, shared networks, host compromessi).

Il sistema implementa il paradigma **Zero-Trust ("Never Trust, Always Verify")** direttamente a livello kernel tramite **eBPF (XDP + LSM)**, combinato con hardening del sistema operativo e credenziali hardware non estraibili (**FIDO2**).

```
                      +------------------------------------------+
                      |         Developer Workstation            |
                      |                                          |
                      |   [Git Commit / SSH]                     |
                      |           │                              |
                      |           ▼                              |
                      |   [FIDO2 Token (ed25519-sk)]             |
                      |   (Richiede tocco fisico)                |
                      +──────────────────────────────────────────+
                                      │
 ┌────────────────────────────────────┼────────────────────────────────────┐
 │  KERNEL-SPACE (eBPF)               │                                    │
 │                                    │                                    │
 │   [ Ingress Traffic ]              ▼                                    │
 │            │              [ Syscall: file_open ]                        │
 │            ▼                       │                                    │
 │    ┌───────────────┐               ▼                                    │
 │    │   eBPF XDP    │       ┌───────────────┐                            │
 │    │ (Drop Subnet) │       │   eBPF LSM    │                            │
 │    └───────────────┘       │ (Inodes Map)  │                            │
 │            │               └───────────────┘                            │
 │            ▼                       │                                    │
 │       [ PASS/DROP ]           [ Whitelist ]──(No)──► [ -EACCES Deny ]   │
 │                                    │                       │            │
 │                                  (Yes)                     ▼            │
 │                                    │               [ Ring Buffer Logs ] │
 │                                    ▼                       │            │
 │                             [ Access Allow ]               │            │
 └────────────────────────────────────┼───────────────────────┼────────────┘
                                      │                       │
                                      ▼                       ▼
                      +──────────────────────────────────────────+
                      |          USER-SPACE DAEMON (Go)          |
                      |                                          |
                      |  • Loader mappe e programmi eBPF         |
                      |  • Auto-discovery interfaccia di default |
                      |  • Inode sync per file segreti           |
                      |  • Audit event consumer in tempo reale   |
                      +------------------------------------------+
```

---

## 🗂️ Struttura della Repository

```text
personal_zeroT/
├── .gitignore                  # Esclusioni per binari, artefatti C e vmlinux.h
├── README.md                   # Documentazione architetturale e guida operativa
├── PUNTI_APERTI.md             # Registro attività, decisioni aperte e checklist
├── gemini-code-1790668303538.md # Specifiche tecniche e storico evolutivo
├── go.mod                      # Definizione modulo Go
├── bpf/
│   └── zerotrust.c             # Codice kernel C: hook XDP (rete) e LSM (file_open)
├── cmd/
│   └── zt-shield/
│       └── main.go             # Entrypoint demone Go (loader eBPF, event loop)
├── internal/
│   ├── config/
│   │   └── config.go           # Parsing configurazioni (whitelist processi, file protetti)
│   ├── lsm/
│   │   └── lsm.go              # Gestione attach LSM, mappe inode e whitelist comm
│   ├── xdp/
│   │   └── xdp.go              # Gestione attach XDP (Generic/Native) e trie LPM subnet
│   └── audit/
│       └── audit.go            # Consumer eventi ring buffer e formattazione alert
├── configs/
│   └── shield.example.yaml     # File di configurazione di esempio
└── scripts/
    ├── check_prereqs.sh        # Verifica moduli LSM kernel, BTF, toolchain e dipendenze
    ├── harden_system.sh        # Hardening UFW, disabilitazione LLMNR/mDNS in systemd-resolved
    └── setup_fido2.sh          # Generazione chiavi SSH FIDO2 residenti e configurazione Git
```

---

## 🎯 I Quattro Livelli di Protezione

### 1. Network Layer (eBPF XDP)
* **Ingress Filtering a livello kernel/driver:** Scarta ad alte prestazioni i pacchetti provenienti da subnet o indirizzi IP ostili prima ancora che raggiungano lo stack TCP/IP del kernel.
* **Supporto Universale:** Utilizza il fallback `XDP_GENERIC` per operare senza incompatibilità su qualsiasi interfaccia (Wi-Fi, Ethernet, tunnel VPN).

### 2. Secret & Data Layer (eBPF LSM)
* **Protezione Inode:** Registra gli inode di file critici (`~/.kube/config`, `~/.ssh/id_rsa`, `~/.aws/credentials`).
* **Enforcement a livello kernel:** Intercetta l'hook `file_open` e restituisce `-EACCES` (Permission Denied) a qualsiasi processo non esplicitamente registrato nella whitelist (`allowed_readers`).
* **Audit Ring Buffer:** Invia in tempo reale eventi asincroni a user-space ogni volta che un processo non autorizzato tenta l'accesso a un file protetto.

### 3. Identity & Non-Repudiation Layer (FIDO2 Hardware Keys)
* **Chiavi residenti non estraibili:** Generazione di chiavi `ed25519-sk` su token hardware (YubiKey, token FIDO2/U2F) con tocco fisico obbligatorio (`verify-required`).
* **Anti-Impersonation Git:** Tutti i commit sui repository devono essere obbligatoriamente firmati crittograficamente con la chiave hardware.
* **Anti SSH-Agent Hijacking:** Protezione dell'agente SSH locale tramite flag `-c` (richiesta di conferma esplicita a schermo per ogni utilizzo della chiave).

### 4. Protocol & OS Hardening
* **Anti-Poisoning Broadcast:** Disattivazione di protocolli insicuri di broadcast discovery (LLMNR e mDNS) in `systemd-resolved` per neutralizzare attacchi di sniffing e spoofing locale.
* **Firewall Strict Ingress:** Policy predefinita `default deny incoming` tramite UFW.
* **DNS Security:** Protezione contro attacchi di DNS poisoning locale tramite configurazione crittografica sicura (DoH / DoT).

---

## ⚙️ Prerequisiti di Sistema

* **Sistema Operativo:** Ubuntu 22.04 LTS, 24.04 LTS o qualsiasi distribuzione Linux con kernel >= 5.15 e BTF abilitato (`/sys/kernel/btf/vmlinux`).
* **BPF LSM attivo nel kernel:**
  Verifica con:
  ```bash
  cat /sys/kernel/security/lsm
  ```
  Se la lista non include `bpf`, aggiungilo nei parametri di avvio in `/etc/default/grub`:
  ```bash
  sudo sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf /' /etc/default/grub
  sudo update-grub
  sudo reboot
  ```
* **Toolchain di sviluppo:**
  ```bash
  sudo apt update
  sudo apt install -y clang llvm libbpf-dev bpftool golang libfido2-dev fido2-tools ufw
  ```

---

## 🚀 Guida Rapida di Compilazione e Avvio

### 1. Esegui la verifica dei prerequisiti
```bash
bash scripts/check_prereqs.sh
```

### 2. Genera l'header BTF del kernel
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

### 3. Genera gli stub Go per eBPF e compila il binario
```bash
go generate ./...
go build -o bin/zt-shield ./cmd/zt-shield
```

### 4. Avvia lo Shield con permessi di root
```bash
sudo ./bin/zt-shield
```

---

## 📖 Riferimenti
* Per le specifiche tecniche dettagliate del motore eBPF e lo storico evolutivo, consulta [gemini-code-1790668303538.md](file:///home/acucchiara/Scrivania/personal_zeroT/gemini-code-1790668303538.md).
