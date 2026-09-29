# 🛡️ Local Zero-Trust Shield (`zt-shield`)

> **Kernel-Enforced Local Security Agent for Developer Workstations**  
> *Defesa in profondità locale contro movimenti laterali, compromissioni Active Directory e furto di credenziali.*

---

## 📋 Panoramica Architetturale

`zt-shield` è un agente di sicurezza locale progettato per postazioni di sviluppo Linux (Ubuntu) che operano in reti aziendali non fidate o potenzialmente compromesse (es. caduta di Active Directory / domain-joined environments).

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
* **Ingress Filtering hardware/driver level:** Scarta a monte i pacchetti provenienti da subnet LAN compromesse o non autorizzate prima ancora che raggiungano lo stack TCP/IP del kernel.
* **Supporto Universale:** Utilizza il fallback `XDP_GENERIC` per operare senza incompatibilità su schede di rete Wi-Fi e dongle Ethernet tipici dei laptop di sviluppo.

### 2. Secret & Data Layer (eBPF LSM)
* **Protezione Inode:** Registra gli inode di file critici (`~/.kube/config`, `~/.ssh/id_rsa`, `~/.aws/credentials`).
* **Enforcement a livello kernel:** Intercetta l'hook `file_open` e restituisce `-EACCES` (Permission Denied) a qualsiasi binario non esplicitamente registrato nella whitelist (`allowed_readers`).
* **Audit Ring Buffer:** Invia in tempo reale eventi asincroni a user-space ogni volta che un processo non autorizzato tenta l'accesso a un file protetto.

### 3. Identity & Non-Repudiation Layer (FIDO2 Hardware Keys)
* **Chiavi residenti non estraibili:** Generazione di chiavi `ed25519-sk` su token hardware (YubiKey, token FIDO2/U2F) con tocco fisico obbligatorio (`verify-required`).
* **Anti-Impersonation Git:** Tutti i commit sui repository locali e remoti devono essere obbligatoriamente firmati crittograficamente con la chiave hardware.
* **Anti SSH-Agent Hijacking:** Protezione dell'agente SSH locale tramite flag `-c` (richiesta di conferma esplicita a schermo per ogni utilizzo della chiave).

### 4. Protocol & OS Hardening
* **Anti-Responder / Anti-Inveigh:** Disattivazione di LLMNR (*Link-Local Multicast Name Resolution*) e mDNS in `systemd-resolved` per neutralizzare il furto broadcast di hash NTLM.
* **Firewall Strict Ingress:** Policy predefinita `default deny incoming` tramite UFW.
* **DNS Protection:** Isolamento dai server DNS interni gestiti dai Domain Controller aziendali tramite configurazione DNS-over-HTTPS (DoH).

---

## ⚙️ Prerequisiti di Sistema

* **Sistema Operativo:** Ubuntu 22.04 LTS o 24.04 LTS (o kernel Linux compatibile >= 5.15 con BTF attivo in `/sys/kernel/btf/vmlinux`).
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
* Per l'analisi dettagliata dei bug del prototipo iniziale e il threat model completo, consulta [gemini-code-1790668303538.md](file:///home/acucchiara/Scrivania/personal_zeroT/gemini-code-1790668303538.md).
