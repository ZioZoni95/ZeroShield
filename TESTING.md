# 🧪 Scenari di Collaudo e Test Reale (`zt-shield`)

Questo documento descrive le procedure per validare e testare sul campo tutti i livelli di protezione del **Local Zero-Trust Shield** in un ambiente controllato, **senza la necessità di macchine esterne** (sfruttando i Network Namespaces di Linux).

---

## 📋 Matrice di Collaudo

| Test | Livello | Minaccia Simulata | Esito Atteso |
| :--- | :--- | :--- | :--- |
| **Test 1** | **eBPF LSM (`file_open`)** | Dipendenza malevola / script utente tenta di leggere segreti locali (`kubeconfig`, SSH). | `Permission denied` a livello kernel + alert istantaneo nel Ring Buffer. |
| **Test 2** | **eBPF XDP** | Host compromesso sulla LAN che effettua scansioni e tentativi di connessione. | Pacchetti scartati all'ingresso (`XDP_DROP`) prima dello stack TCP/IP. |
| **Test 3** | **Hardening Protocolli** | Attaccante che sfrutta attacchi broadcast (*Responder*, *Inveigh*) per rubare hash. | Traffico broadcast LLMNR/mDNS azzerato su porte 5355 e 5353. |
| **Test 4** | **Hardware Token FIDO2** | Malware con accesso shell che tenta di eseguire commit malevoli a nome dell'utente. | Operazione bloccata in timeout senza il tocco fisico sul dispositivo FIDO2. |

---

## 🛡️ Test 1: Isolamento Segreti & Blocco Kernel (eBPF LSM)

Simula uno script malevolo o una dipendenza (npm, pip, cargo) eseguita con i normali privilegi dell'utente che tenta di accedere a `~/.kube/config`, `~/.ssh/id_rsa` o `~/.aws/credentials`.

### 1. Prerequisiti
Verifica che `bpf` sia attivo nei moduli LSM del kernel:
```bash
cat /sys/kernel/security/lsm
# Deve includere "bpf" (es. lockdown,capability,landlock,yama,apparmor,bpf)
```

### 2. Avvio dello Shield
In un terminale dedicato (Terminale 1):
```bash
cd ~/zt-shield
sudo ./bin/zt-shield
```

### 3. Tentativo di Accesso Non Autorizzato
In un secondo terminale (Terminale 2, come utente normale):
```bash
# Tentativo tramite cat
cat ~/.kube/config

# Tentativo tramite script Python
python3 -c "print(open('$HOME/.kube/config').read())"
```

* **Esito Terminale 2:** Errore immediato `cat: ~/.kube/config: Permesso negato` (`-EACCES`), anche se il file appartiene all'utente ed ha permessi corretti (`0600`).
* **Esito Terminale 1 (Shield Log):** Notifica in tempo reale dal Ring Buffer:
  ```text
  🚨 [TENTATIVO BLOCCATO] PID: 48921 | Processo: 'cat' | Inode: 1426091
  ```

### 4. Verifica Flusso Legittimo (Whitelist)
Nello stesso Terminale 2, esegui un comando autorizzato (presente in `allowedProcesses`):
```bash
kubectl config view
```
* **Esito:** Il comando legge il file e mostra la configurazione senza generare errori né blocchi.

### 5. Test di Evasione (Anti-Spoofing del Processo)
Un attaccante consapevole della whitelist tenta di rinominare un binario non autorizzato:
```bash
cp /usr/bin/cat /tmp/ssh
/tmp/ssh ~/.kube/config
```
* **Verifica:** Se il controllo è solo sul nome (`comm`), il comando passerebbe; se implementato il controllo avanzato sull'eseguibile reale (`exe_file->f_inode`), il kernel blocca anche questo tentativo.

---

## 🌐 Test 2: Ingress Drop Hardware-Level (eBPF XDP)

Simula un host ostile presente nella stessa sottorete che tenta di contattare la postazione di sviluppo.

Per testare questo scenario in locale senza una seconda macchina, utilizziamo un **Linux Network Namespace** con una coppia di interfacce virtuali (`veth`).

### 1. Creazione dell'Ambiente di Rete Simulato
```bash
# Crea un namespace isolato per l'attaccante
sudo ip netns add attacker-ns

# Crea una coppia di interfacce virtuali
sudo ip link add veth-host type veth peer name veth-att

# Sposta un'estremità nel namespace dell'attaccante
sudo ip link set veth-att netns attacker-ns

# Configura l'IP dell'host (la tua macchina)
sudo ip addr add 192.168.100.1/24 dev veth-host
sudo ip link set veth-host up

# Configura l'IP dell'attaccante (nella subnet da bloccare)
sudo ip netns exec attacker-ns ip addr add 192.168.100.2/24 dev veth-att
sudo ip netns exec attacker-ns ip link set veth-att up
```

### 2. Test Pre-Attivazione dello Scudo
Dal namespace dell'attaccante, esegui un ping verso l'host:
```bash
sudo ip netns exec attacker-ns ping -c 3 192.168.100.1
```
* **Esito:** Il ping risponde normalmente (0% packet loss).

### 3. Attivazione XDP sull'Interfaccia Virtuale
Avvia `zt-shield` specificando l'interfaccia virtuale creata:
```bash
sudo SHIELD_IFACE=veth-host ./bin/zt-shield
```
*(Assicurati che la mappa `infected_subnets` includa `192.168.100.0/24`)*.

### 4. Test Post-Attivazione dello Scudo
Rilancia il ping dal namespace attaccante:
```bash
sudo ip netns exec attacker-ns ping -c 3 -W 1 192.168.100.1
```
* **Esito:** `100% packet loss` immediato.

### 5. Verifica dei Contatori Kernel
Verifica che i pacchetti siano stati scartati direttamente da XDP:
```bash
sudo bpftool prog show name xdp_drop_lateral_movement
```

### 6. Pulizia dell'Ambiente Virtuale
Al termine del test, elimina il namespace e le interfacce virtuali:
```bash
sudo ip link delete veth-host 2>/dev/null || true
sudo ip netns delete attacker-ns 2>/dev/null || true
```

---

## 📡 Test 3: Mitigazione Avvelenamento Broadcast (Anti-Responder)

Simula la presenza sulla LAN di strumenti di avvelenamento (*Responder*, *Inveigh*) in attesa di richieste broadcast per catturare hash di credenziali.

### 1. Monitoraggio del Traffico Broadcast in Uscita
In un terminale apri `tcpdump` per osservare le porte UDP 5355 (LLMNR) e 5353 (mDNS):
```bash
sudo tcpdump -i any -n -v "port 5355 or port 5353"
```

### 2. Generazione di una Risoluzione Fallita
In un altro terminale, tenta di raggiungere un host inesistente:
```bash
ping -c 1 host-inesistente-test.local
```

### 3. Valutazione dei Risultati
* **Macchina NON protetta:** `tcpdump` mostra pacchetti UDP broadcast inviati verso `224.0.0.252:5355` (LLMNR) o `224.0.0.251:5353` (mDNS), esponendo il nome utente e la richiesta alla LAN.
* **Macchina Protetta (`LLMNR=no`, `MulticastDNS=no` in `resolved.conf`):** `tcpdump` resta **completamente muto**. La richiesta viene gestita esclusivamente tramite DNS unicast verso il resolver configurato, azzerando la superficie d'attacco broadcast.

---

## 🔑 Test 4: Anti-Impersonation e Tocco Fisico (FIDO2 & SSH Agent)

Simula un attaccante o un processo locale che ha ottenuto una shell e tenta di committare codice o usare credenziali SSH all'insaputa dell'utente.

### 1. Test Firma Commit Git (FIDO2)
Con Git configurato per firmare tramite chiave `ed25519-sk`:
```bash
git commit -m "security test"
```

* **Comportamento atteso:** Il token hardware (es. YubiKey) inizia a lampeggiare.
* **Se l'utente tocca fisicamente il token:** Il commit viene firmato e registrato con successo.
* **Se l'operazione è remota o automatica (nessun tocco):** Dopo pochi secondi il comando fallisce con:
  ```text
  error: gpg.ssh.allowedSignersFile ... sign_and_send_pubkey: signing failed: agent refused operation
  fatal: failed to write commit object
  ```

### 2. Verifica Crittografica della Firma
Controlla la firma del commit generato:
```bash
git log -1 --show-signature
```
* **Output atteso:**
  ```text
  Good "git" signature for user with ED25519-SK key ...
  ```

### 3. Test Conferma Agente SSH (`ssh-add -c`)
Se utilizzi l'agente SSH locale con conferma manuale:
```bash
ssh-add -c ~/.ssh/id_ed25519
```
Ad ogni tentativo di autenticazione SSH verso un server remoto, il sistema apre un prompt a video (`ssh-askpass`) che richiede autorizzazione esplicita. Qualsiasi tentativo silente da parte di un malware di usare il socket `SSH_AUTH_SOCK` viene immediatamente intercettato e richiede conferma dell'utente.
