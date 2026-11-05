<p align="center">
  <img src="zt-gui/build/appicon.png" width="128" alt="ZeroShield"/>
</p>
<h1 align="center">ZeroShield</h1>
<p align="center"><b>Uno scudo zero-trust locale nel kernel Linux.</b><br/>
Difende segreti e rete di una postazione da Wi-Fi ostili, dipendenze avvelenate e ladri di token: senza server, senza cloud, senza account.</p>
<p align="center">
  <a href="#-come-si-usa-in-breve">Come si usa</a> ·
  <a href="#-stato-reale-del-progetto">Stato</a> ·
  <a href="#-demo-in-60-secondi-dati-finti">Demo</a> ·
  <a href="#-installazione">Installazione</a> ·
  <a href="#-configurazione">Configurazione</a> ·
  <a href="#-interfacce">Interfacce</a> ·
  <a href="#-documentazione">Documentazione</a>
</p>
<p align="center"><i>⚠️ ALPHA permanente finché gli hook LSM non sono collaudati in enforce — solo lab · MIT © 2026 ZioZoni95</i></p>
<p align="center">
  <a href="https://github.com/ZioZoni95/ZeroShield/actions/workflows/ci.yml"><img src="https://github.com/ZioZoni95/ZeroShield/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white" alt="Go"/>
  <img src="https://img.shields.io/badge/eBPF-cilium%2Febpf-8A2BE2" alt="eBPF"/>
  <img src="https://img.shields.io/badge/TUI-Bubble_Tea-FF75B7" alt="TUI"/>
  <img src="https://img.shields.io/badge/GUI-Wails-EB1C24" alt="GUI"/>
  <img src="https://img.shields.io/badge/license-MIT-yellow" alt="MIT"/>
</p>

> [!WARNING]
> **Alpha sperimentale.** Il blocco dei segreti è stato visto funzionare **una sola volta, su un solo PC**
> (kernel 7.0 Ubuntu, file finto: `file_open`, rinomina, cancellazione e troncamento negati, vedi
> [`docs/COLLAUDO_LSM_2026-11-05.md`](docs/COLLAUDO_LSM_2026-11-05.md)). Non è stato collaudato in una VM isolata, né con i
> programmi veri sulle protezioni predefinite, né su altri kernel. Usalo in `audit` e metti in **Blocca** una
> protezione alla volta, dopo aver controllato i programmi autorizzati; fai prima la prova con un file finto.

---

## 🧭 Cos'è

`zt-shield` è un agente di sicurezza locale per postazioni Linux (sviluppo e uso quotidiano) che lavorano
su reti non fidate o su cui può girare codice non fidato. Applica il paradigma **Zero-Trust** a livello
kernel con **eBPF (XDP + LSM)**, affiancato da hardening del sistema, esche anti-ransomware, monitor e
kill-switch VPN e firma dei commit con credenziali hardware.

* **Difende da:** poisoning di rete su Wi-Fi o LAN (LLMNR/mDNS/NBT-NS), codice di terze parti che legge
  `~/.ssh`, `~/.aws` e token (supply-chain, infostealer), ransomware, furto di chiavi SSH.
* **Non è:** un antivirus, un firewall completo (niente egress per processo), un EDR, un backup né uno
  strumento di cifratura. Root locale, keylogger e disco non cifrato restano fuori scopo.

---

## 🚀 Come si usa (in breve)

ZeroShield lavora in due tempi, pensati per chi non vuole scrivere file di configurazione:

1. **Installa e avvia in `audit`.** Con il pacchetto: `sudo apt install ./zeroshield_*_amd64.deb`, poi
   `sudo /usr/share/zeroshield/scripts/configure_service.sh $USER home` (o il pulsante *Installa e attiva*
   della GUI). In `audit` ZeroShield **osserva e non blocca niente**.
2. **Guarda l'icona nella barra.** 🟢 verde = protetto (enforce), 🟡 gialla = solo osservazione (audit),
   🔴 rossa = demone spento. Chiudere la finestra non ferma la protezione: è un servizio di sistema.
3. **Lavora come al solito per qualche giorno**, poi apri la GUI → scheda **Regole**. Un percorso in tre passi
   (*Osserva → Autorizza → Blocca*) ti mostra i programmi che hanno letto i tuoi segreti e quali puoi
   autorizzare con un clic (kubectl, helm, k3d, k9s…). Premi **Applica**: ZeroShield si riavvia da solo e,
   se qualcosa non va, torna alla configurazione precedente.
4. **Quando l'indicatore dice che è tutto autorizzato**, passa a **Blocca**: per tutte le protezioni insieme dalla
   scheda *Configurazione*, oppure **una alla volta** dalla scheda *Regole* (ogni protezione ha la sua modalità).
   Da quel momento solo i programmi in lista leggono quei segreti.
5. **Hai file tuoi da proteggere?** (un portafoglio crypto, un database di password) *Regole → Proteggi un mio file*:
   scegli il file o la cartella, vedi quanti file protegge e decidi chi può usarli.

Non serve scrivere YAML: la GUI lo fa per te. Restano però i limiti dello [stato reale](#-stato-reale-del-progetto):
**non usare `enforce` su una macchina vera prima del collaudo in VM**.

---

## 🔬 Stato reale del progetto

Ultima release pubblicata: **v0.0.4** (pre-release, alpha). Il numero che vedi in fondo alla barra laterale della
GUI è quello del binario in uso; le build locali sono `<VERSION>~dev+<commit>`. Cosa cambia in ogni versione:
[`CHANGELOG.md`](CHANGELOG.md).

| Componente | Stato | Come è stato verificato |
|---|---|---|
| XDP anti-poisoning (IPv4 + IPv6, fino a 2 tag VLAN) e radar | ✅ **kernel reale** | `zt-probe -xdp-lo` + pacchetti sintetici contro il vero programma (`BPF_PROG_TEST_RUN`) |
| Canary anti-ransomware (fanotify) | ✅ **kernel reale** | tocco esca, allarme di massa, kill in `enforce` (`make test-root`) |
| **Hook LSM dei segreti** (5 programmi) | 🟢 **visti negare su un kernel reale** (un PC) | `file_open`, rinomina, cancellazione, troncamento: file finto, kernel 7.0.0-42 Ubuntu, 2026-11-05; **non** provati `file_truncate`, `deny_write`, le protezioni predefinite con i programmi veri, una VM isolata |
| **Demone end-to-end** | 🟢 **gira su un PC con BPF LSM** | avviato dal `.deb`, XDP + hook + canary + IPC + `config-apply`; mai in una VM con snapshot né per giorni di fila |
| Config, IPC, audit, whitelist, inotify, `netstat` | ✅ test unitari | `go test -race`, fuzz sul config, CI |
| TUI, GUI, mock | ✅ testati | test unitari e `--dump` (TUI); test della GUI nel browser contro un demone simulato |
| **Scheda Regole**, modalità per regola e `zt-shield config-apply` | 🟢 provati su un PC | protezione personale creata dalla GUI, applicata con `pkexec`, in `enforce` solo per quella regola; il ripristino automatico dopo un riavvio fallito resta provato solo con test |
| Icona nella barra (`zt-tray`, servizio utente) | 🟡 provata su un PC | registrata in GNOME, stato e notifiche; percorso `.deb` (postinstall) non provato |
| Pacchetto `.deb` | ✅ costruito, installato e rimosso | CI e prove locali |
| Kill-switch VPN, auto-VPN, helper Proton, `harden_system.sh`, `configure_service.sh` | 🟡 solo in namespace o con comandi finti | mai su una rete, un sistema o un `.deb` installato veri |
| `setup_fido2.sh`, unit systemd | ⚠️ solo sintassi | `shellcheck`, `systemd-analyze verify` |

**In pratica:** puoi guardare le interfacce con dati finti e provare XDP e canary su un kernel vero.
**Non** puoi ancora fidarti che i tuoi segreti siano protetti.

---

## ⚡ Demo in 60 secondi (dati finti)

Non prova la protezione (nessun kernel coinvolto): mostra le interfacce con **dati inventati**, senza root e
senza toccare il demone vero. Il finto demone `zt-mockd` genera anche eventi e **canary finti** a intervalli
regolari: non sono allarmi veri.

```bash
# con il pacchetto installato
ZT_SOCKET=/tmp/z.sock zt-mockd &
ZT_SOCKET=/tmp/z.sock zt-gui        # oppure zt-tui: una finestra collegata al finto demone
pkill zt-mockd                      # fine

# dai sorgenti
make build-tui build-mock
ZT_SOCKET=/tmp/z.sock ./bin/zt-mockd &
ZT_SOCKET=/tmp/z.sock ./bin/zt-tui
```

`./bin/zt-tui --dump` stampa un'anteprima senza terminale interattivo. La stessa demo, con i comandi da copiare,
è nella GUI (primo avvio, demone spento e scheda *Guida*).

---

## 🏗️ Come funziona

Il demone `zt-shield` gira come root, carica i programmi eBPF e pubblica stato ed eventi su un socket Unix
che TUI e GUI leggono come utente normale.

**Rete (XDP):** ogni pacchetto in ingresso, prima dello stack di rete.

```mermaid
flowchart TD
    PKT(["pacchetto in ingresso"]) --> VLAN["scarta fino a 2 tag VLAN (802.1Q / QinQ)"]
    VLAN --> L3{"IPv4 o IPv6?"}
    L3 -- "altro (ARP, PPPoE)" --> PASS["✅ PASS"]
    L3 -- "IPv6" --> P6{"UDP diretto su 5355 / 5353 / 137 / 138?"}
    P6 -- "sì" --> D6["⛔ DROP + contatore v6"]
    P6 -- "no" --> PASS
    L3 -- "IPv4" --> P4{"UDP su 5355 / 5353 / 137 / 138?<br/>(sport o dport)"}
    P4 -- "sì" --> D4["⛔ DROP + radar per IP"]
    P4 -- "no" --> SUB{"sorgente in block_subnets?"}
    SUB -- "sì" --> D4S["⛔ DROP + radar per IP"]
    SUB -- "no" --> PASS
    classDef deny fill:#fde7ea,stroke:#d70015,color:#4a0a12;
    classDef ok fill:#e2f3e5,stroke:#1d8127,color:#0c2b12;
    class D6,D4,D4S deny;
    class PASS ok;
```

**Segreti (LSM):** ogni `open`, `unlink`, `rename`, `truncate` del sistema passa da una lookup.

```mermaid
flowchart TD
    OP["open / unlink / rename / truncate / ftruncate"] --> PROT{"il file è protetto?<br/>(chiave dev + inode)"}
    PROT -- "no" --> OK["✅ accesso normale"]
    PROT -- "sì" --> WL{"l'exe è in whitelist<br/>per quella regola?<br/>(dev + inode del binario)"}
    WL -- "sì" --> ALLOW["✅ allow"]
    WL -- "no" --> MODE{"modalità"}
    MODE -- "enforce" --> DENY["⛔ -EACCES"]
    MODE -- "audit" --> LOG["⚠️ passa, ma logga"]
    ALLOW & DENY & LOG --> RING[("ring buffer di audit")]
    RING --> DAEMON["demone Go: Sync + rescan + inotify + canary<br/>fail-closed + watchdog"]
    DAEMON --> SOCK[("socket di lettura<br/>/run/zt-shield/api.sock")]
    DAEMON --> CTRL[("socket di controllo<br/>/run/zt-shield/control.sock<br/>root o polkit")]
    SOCK --> UI["💻 zt-tui · 🖥️ zt-gui · 🔔 zt-tray (leggono)"]
    CTRL --> ACT["⚙️ azioni: rescan, avvio/stop, install, audit↔enforce, applica regole"]
    classDef deny fill:#fde7ea,stroke:#d70015,color:#4a0a12;
    classDef ok fill:#e2f3e5,stroke:#1d8127,color:#0c2b12;
    class DENY deny;
    class OK,ALLOW ok;
```

Il confine tra userspace e kernel è fatto di **numeri**, non di stringhe: per ogni file protetto si mette in
mappa `(device, inode)` e il kernel confronta i propri numeri con l'oggetto che sta per essere aperto. Per
questo la whitelist non si aggira con symlink, rename o copie del binario: conta l'identità del file, non il
nome con cui lo chiami.

---

## 🎯 Cosa protegge

* **Rete (XDP + firewall).** Scarta in ingresso LLMNR (5355), mDNS (5353), NBT-NS (137) e NetBIOS-DGM (138),
  guardando sia la porta sorgente sia quella di destinazione (la risposta avvelenata di Responder ha
  `sport=5355`). Il contatore non distingue le *richieste* degli altri host dalle *risposte avvelenate*. Vale
  per IPv4 e IPv6, anche dietro uno o due tag VLAN; il radar delle UI è solo IPv4. `block_subnets` scarta
  intere reti IPv4 (anche le risposte: mai gateway o DNS). XDP generico: funziona su Wi-Fi, Ethernet e VPN,
  con `interface` come lista (`wlan0,eth0`).
* **Segreti (LSM).** Hook su `open`, `unlink`, `rename`, `path_truncate` e, sui kernel ≥ 6.2, `file_truncate`
  (opzionale). Ogni regola associa file ai soli binari autorizzati; entrano in whitelist solo **binari di
  root** non scrivibili da altri. Una scrittura semplice passa, `O_TRUNC` e `truncate` passano dalla
  whitelist, `deny_write` per regola blocca anche quelle. I file nominati dalle regole hanno precedenza
  sulle mappe (tetto di 4096 per regola, 16384 in tutto) e un watcher **inotify** riallinea le mappe entro
  ~0,5 s da un rename; il rescan periodico (`rescan_seconds`) resta come rete di sicurezza.
  **Fail-closed**: se un hook non si aggancia il demone si ferma invece di fingersi attivo.
* **Anti-ransomware (canary + fanotify).** File esca nascosti nelle cartelle scelte: chi li tocca viene
  ucciso in `enforce` (mai PID ≤ 1 né il demone). Una raffica di scritture, cancellazioni o rinomine genera
  solo un allarme. `exclude_exe` e `allow_exe` esentano indicizzatori e backup. Spento di default: si tara una
  settimana in `audit` ([`docs/CANARY.md`](docs/CANARY.md)).
* **VPN.** Il demone **monitora, non applica**: mostra tunnel, kill-switch nftables e handshake WireGuard.
  `scripts/vpn_killswitch.sh` applica il kill-switch con una sola tabella nft (`inet zt-killswitch`);
  `nm_vpn.sh` e `proton_*.sh` sono opzionali. Tutto provato solo in un namespace o con comandi finti
  ([`docs/VPN_SETUP.md`](docs/VPN_SETUP.md)).
* **Identità (FIDO2).** `setup_fido2.sh` crea una chiave `ed25519-sk` residente (PIN + tocco) e configura
  commit firmati via SSH.
* **Hardening (`scripts/harden_system.sh`).** LLMNR e mDNS spenti in `systemd-resolved`, DNS-over-TLS nei
  profili per reti ostili, sysctl anti-redirect, `avahi` disabilitato, UFW `default deny incoming`. Usa
  **sempre `--dry-run` prima**: mostra diff e comandi senza modificare nulla.

---

## 🧩 Profili e regole

| Profilo | Modalità | Gruppi di regole | Hardening (`harden_system.sh`) |
|---|---|---|---|
| `home` *(default)* | `audit` | ssh, cloud, tokens, gpg | UFW, no LLMNR/mDNS, sysctl base |
| `corporate` | `enforce` | ssh, cloud, tokens, gpg | come `home`; DNS interni mantenuti |
| `public-wifi` | `enforce` | + browsers | + DoT opportunistic, ARP, avahi off |
| `paranoid` | `enforce` | come `public-wifi` | DoT `yes` (rompe i captive portal) |

| Gruppo | Protegge | Autorizzati |
|---|---|---|
| `ssh` | `~/.ssh/id_*` | ssh, ssh-add, ssh-agent, ssh-keygen, scp, sftp |
| `cloud` | `.kube/config`, `.aws/credentials`, credenziali Terraform | kubectl, helm, k9s, aws, terraform, tofu |
| `tokens` | `.git-credentials`, `.docker/config.json`, `gh/hosts.yml`, `.cargo/credentials.toml`, `glab-cli/config.yml` | git, gh, glab, docker, cargo |
| `gpg` | `~/.gnupg/private-keys-v1.d/` | gpg, gpg-agent, gpgsm |
| `browsers` | cookie e password di Chrome, Chromium, Firefox (anche snap), Brave | i binari dei browser (percorsi assoluti) |

**Dalla GUI (consigliato).** La scheda *Regole* mostra questi gruppi con un interruttore e **una modalità propria**
(*come le altre*, *solo osserva*, *blocca*) ciascuno, permette di togliere o rimettere i programmi di base e di creare
**protezioni tue** (*Proteggi un mio file*: selettore, schemi con `*`, anteprima dei file coperti e avvisi). Mostra anche un
**catalogo di programmi noti** (k3d, helm, k9s, oh-my-posh, kubectx, stern, flux, argocd, kind, minikube,
skaffold, lazydocker, gh, glab) e l'elenco dei programmi visti in `audit`, con il motivo quando uno non si può
autorizzare. Le scelte restano una bozza finché non premi *Applica*.

**A mano.** Aggiungi i tuoi segreti con `extra_rules`, sostituisci le regole del profilo con `rules`, oppure
ritocca quelle del profilo senza riscriverle con `allow_extra` (binari in più per una regola), `disable_rules`
(togli una regola) ed `enable_groups` (aggiungi un gruppo predefinito). La GUI scrive queste tre chiavi in un
blocco delimitato in fondo al file e non tocca il resto; se le scrivi tu a mano, la GUI le mostra solo in lettura.

**Perché alcuni programmi non si possono autorizzare.** Il demone accetta in whitelist solo binari (e cartelle)
di **root**: un programma che puoi modificare tu, come `~/.local/bin/oh-my-posh` o quello di Homebrew, potrebbe
essere sostituito da un malware con i tuoi permessi. La GUI lo dice e offre *Rendi affidabile*: una copia
protetta in `/usr/local/bin` (chiede la password). Vale solo se poi lanci quella copia, e va ripetuta dopo un
aggiornamento del programma.

> [!IMPORTANT]
> Tool con shebang (`npm`, `pip`, `gcloud`, `az`) **non sono in whitelist** di proposito: il processo che apre
> il file è l'interprete (`node`, `python`), e autorizzarlo autorizzerebbe qualunque script, compresi gli
> `postinstall` malevoli. Per quei token usa credenziali a breve durata o un keyring. I browser **Flatpak**
> non sono coperti: verifica in `audit` il percorso del binario visto dal kernel.

---

## ⚙️ Configurazione

File: `/etc/zt-shield/shield.yaml` (`-config FILE` per un altro). Senza file vale il profilo `home`. Le chiavi
sconosciute sono **rifiutate** (un refuso non passa in silenzio). Il pacchetto installa l'esempio commentato
([`configs/shield.example.yaml`](configs/shield.example.yaml)) e non lo sovrascrive agli aggiornamenti.

| Chiave | Default | Significato |
|---|---|---|
| `profile` | `home` | `home` · `corporate` · `public-wifi` · `paranoid` |
| `user` | — | **Obbligatoria come servizio**: utente la cui home si protegge (sotto systemd non esiste `SUDO_USER`) |
| `mode` | dal profilo | `audit` (logga) · `enforce` (nega) |
| `interface` | rotta di default | interfaccia XDP; lista separata da virgole. **Le altre interfacce attive non sono filtrate** |
| `block_poisoning` | `true` | drop LLMNR/mDNS/NBT-NS in ingresso |
| `block_subnets` | — | CIDR IPv4 da scartare in XDP |
| `rules` / `extra_rules` | dal profilo | `name`, `paths` (relativi alla home o assoluti, glob, directory ricorsive), `allow` (nomi o percorsi assoluti, mai vuota), `deny_write`, `mode` (`audit`/`enforce`, vuoto = modalità globale). Massimo 255 regole |
| `allow_extra` / `remove_allow` / `disable_rules` / `enable_groups` / `rule_modes` | — | ritocchi alle regole del profilo senza riscriverle: binari in più (**solo percorsi assoluti**) o tolti, regole da togliere, gruppi da aggiungere (`ssh`·`cloud`·`tokens`·`gpg`·`browsers`), modalità `audit`/`enforce` per singola regola. Li gestisce la GUI (anche `extra_rules` per le protezioni personali) |
| `canary.*` | spento | `enabled`, `dirs`, `names`, `burst_count`, `burst_secs`, `exclude_exe`, `allow_exe` |
| `vpn.*` | spento | `enabled`, `endpoint` (IP:porta, mai un nome host), `tunnel`, `block_dhcp`, `allow_lan` |
| `log_format` | `text` | `text` · `json` (una riga per evento) |
| `rescan_seconds` | `30` | riallineamento periodico delle mappe (minimo 5) |

Variabili d'ambiente: `SHIELD_USER` (utente da proteggere in primo piano), `ZT_SOCKET` e `ZT_CONTROL` (solo
per mock e test: il demone root le **ignora**). Percorsi: socket di lettura `/run/zt-shield/api.sock`
(proprietà dell'utente protetto, `0600`), socket di controllo `/run/zt-shield/control.sock` (root, polkit
`org.zeroshield.manage`), script in `/usr/share/zeroshield/scripts/`, documentazione in
`/usr/share/doc/zeroshield/`.

---

## 📦 Installazione

> [!CAUTION]
> Installare il pacchetto **non attiva la protezione**: il servizio non parte da solo, serve `user:` nel
> config e serve `bpf` tra gli LSM del kernel (senza il demone si ferma di proposito). Il blocco è stato visto
> su un solo PC: prova prima con un file finto, meglio in una VM.

### Da pacchetto

Ogni tag `v*` pubblica una **pre-release** con **un solo `.deb`** (`zeroshield_<versione>_amd64.deb`:
demone, TUI, GUI, servizio, polkit e script) e `SHA256SUMS`. Ogni release è un'istantanea del codice al suo
tag, non cumulativa. Le versioni restano `0.0.x`; la `1.0.0` arriverà solo a prodotto testato e completo.

```bash
sha256sum -c SHA256SUMS --ignore-missing
sudo apt install ./zeroshield_*_amd64.deb      # server senza schermo: aggiungi --no-install-recommends

sudo zt-probe -xdp-lo                          # il kernel accetta i programmi?
sudo /usr/share/zeroshield/scripts/configure_service.sh $USER home   # scrive user:/profile:, parte in audit
zt-tui                                         # oppure zt-gui
```

`configure_service.sh` imposta `user:` e `profile:` nel config (con una copia di sicurezza, senza perdere i
commenti), parte **sempre in audit** e avvia il servizio del pacchetto: non copia binari né scrive un'altra
unit. Lo stesso fa il pulsante *Installa e attiva* della GUI. A mano: `sudoedit /etc/zt-shield/shield.yaml`
(`user:` è obbligatorio) e `sudo systemctl enable --now zt-shield`.

Il pacchetto installa anche l'**icona di stato** come servizio utente (`zeroshield-tray.service`): parte con la
sessione grafica, riparte da sola e viene riavviata dall'aggiornamento. Su GNOME serve l'estensione AppIndicator
(`gnome-shell-extension-appindicator`, già presente su Ubuntu).

Le librerie grafiche (GTK e WebKit) sono *consigliate*: sul desktop apt le installa; senza di esse demone e
TUI funzionano, la GUI no. Fino a v0.0.3 la GUI era un pacchetto a parte (`zeroshield-gui`): il pacchetto
unico lo sostituisce e `apt` lo gestisce (`Replaces`/`Conflicts`).

### Prerequisito: BPF LSM attivo

Serve Linux con kernel ≥ 5.15 e BTF (`file_truncate` richiede ≥ 6.2, sui precedenti viene saltato). Controlla
`cat /sys/kernel/security/lsm`: se manca `bpf`, **appendilo alla lista esistente** (non sostituirla) e riavvia:

```bash
CURRENT_LSM="$(cat /sys/kernel/security/lsm)"
sudo cp /etc/default/grub /etc/default/grub.bak
sudo sed -i "s|^GRUB_CMDLINE_LINUX=\"|GRUB_CMDLINE_LINUX=\"lsm=${CURRENT_LSM},bpf |" /etc/default/grub
sudo update-grub && sudo reboot
```

`bash scripts/check_prereqs.sh` verifica kernel, BTF, LSM e toolchain.

### Da sorgente

Serve la toolchain: `clang llvm libbpf-dev linux-tools-generic make ufw` (`bpftool` arriva da
`linux-tools-generic`; il `Makefile` lo trova da solo, altrimenti `BPFTOOL=/percorso`), **Go ≥ 1.26** e, per
la GUI, Node 22 e `libgtk-3-dev libwebkit2gtk-4.1-dev` (la CLI `wails` solo per `make gui`).

```bash
make build                                 # genera vmlinux.h e stub eBPF, compila demone e TUI
make probe                                 # il kernel accetta i programmi? (sudo)
sudo SHIELD_USER=$USER ./bin/zt-shield     # prova in primo piano (profilo home = solo audit)

bash scripts/harden_system.sh home --dry-run    # PRIMA: mostra diff e comandi
sudo bash scripts/harden_system.sh home         # poi, in VM: corporate | public-wifi | paranoid
sudo bash scripts/install_service.sh $USER home # servizio systemd (solo da sorgente; dal .deb c'è configure_service.sh)
make package                                    # dist/zeroshield_<versione>_<arch>.deb (demone + TUI + GUI + icona)
```

Installando i binari a mano (senza `.deb`) mancano l'avvio automatico dell'icona e il file del menu:

```bash
sudo install -m 0755 bin/zt-shield /usr/local/sbin/zt-shield && sudo systemctl restart zt-shield
sudo install -m 0755 bin/zt-gui bin/zt-tui bin/zt-tray /usr/local/bin/
install -Dm644 packaging/zeroshield-tray.service ~/.config/systemd/user/zeroshield-tray.service
systemctl --user enable --now zeroshield-tray     # icona nella barra, parte a ogni login
```

La versione dei binari è `<file VERSION>~dev+<commit>` per le build locali e `X.Y.Z` per i tag; `zt-shield -version`,
`zt-tray -version` e `zt-gui -version` la stampano.

### Primo avvio sicuro

1. **VM con snapshot**, kernel con `bpf` in `lsm=`, solo segreti finti ([`docs/TESTING_LAB.md`](docs/TESTING_LAB.md)).
2. `make probe`: tutti i programmi devono risultare ✅.
3. Parti in **`audit`** e lascia lavorare qualche giorno: il log dice, per ogni accesso, regola, PID ed `exe`.
4. Passa a **`enforce`** (in `shield.yaml` o dalla scheda Configurazione) solo quando il log non mostra più
   accessi legittimi.
5. Collaudo: `cat ~/.kube/config` deve dare *Permission denied*; `cp /usr/bin/cat /tmp/ssh && /tmp/ssh ~/.kube/config`
   deve restare negato (conta l'identità, non il nome); `kubectl get pods` deve passare.
6. Hardening, VPN e canary uno alla volta, ognuno prima con snapshot.

---

## 🖥️ Interfacce

Il demone pubblica stato ed eventi sul socket di lettura, di proprietà dell'utente in `user:` con modo `0600`:
lo leggono solo lui e root (contiene PID, exe e percorsi), quindi un secondo utente locale non vede GUI e TUI
(*permission denied*: è voluto). Leggere è libero; **agire** (rescan, avvio/stop, install, audit↔enforce)
passa dal canale di controllo (controllo delle credenziali del peer + polkit `auth_admin`) o da `pkexec`:
mai click silenziosi, mai password maneggiate dalle UI. Ogni testo che arriva dai processi osservati è
sanificato nel demone (`ipc.SafeText`) prima di raggiungere TUI e GUI.

| Strumento | Cosa è |
|---|---|
| `zt-shield` | Il demone (`sudo zt-shield` o servizio). Sottocomandi: `ctl ping\|rescan`, `dropin` (drop-in systemd per il canary), `config-apply FILE` (root: valida un config, copia di sicurezza, sostituzione atomica, riavvio e ripristino se non riparte; lo usa la GUI) |
| `zt-tui` | Terminale con sei schede (Stato, Eventi, Regole, Rete, Radar, Config), filtro eventi, azioni (`i` installa, `s` avvia, `X` ferma, `m` mode, `R` rescan) e `--dump` |
| `zt-gui` | Finestra desktop (Wails): verdetto di protezione, eventi raggruppabili, radar che separa rumore di rete da sorgenti da verificare, **regole guidate** (catalogo, «Rendi affidabile», bozza e *Applica*), rete e VPN, configurazione con cambio audit/enforce, guida a schede, primo avvio con controlli preliminari e popup **Novità** a ogni nuova versione. Scorciatoie `1`-`7`; la versione è in fondo alla barra laterale |
| `zt-tray` | Icona nella barra di sistema: 🟢 enforce con hook, 🟡 audit o senza hook LSM, 🔴 demone spento. Notifica demone caduto/tornato e blocchi/canary **anche a finestra chiusa** (con la GUI aperta se ne occupa lei). Servizio utente systemd; clic = apre la GUI. Chiuderla non ferma la protezione |
| `zt-mockd` | Finto demone con dati inventati, per vedere le UI senza root né eBPF |
| `zt-probe` | Collaudo del kernel: verifier per programma e, con `-xdp-lo`, XDP su loopback |

Fuori da un ambiente snap le GUI GTK vanno lanciate con `GTK_PATH` e `GIO_MODULE_DIR` ripuliti. Ricerca e
decisioni di design in [`docs/UI_RESEARCH.md`](docs/UI_RESEARCH.md).

---

## ✅ Test e CI

```bash
make test           # Go: unitari, nessun privilegio
make test-scripts   # script con comandi finti (VPN, Proton, configure_service, hardening) + kill-switch in un namespace (sudo)
make test-root      # canary con fanotify reale + parser XDP e loader con BPF_PROG_TEST_RUN (sudo)
make probe          # il kernel accetta i programmi eBPF? (sudo)
make check          # prerequisiti + lint + test + build

# GUI nel browser (Chrome di sistema, demone simulato; non salva nulla in package.json)
cd zt-gui/frontend && npm ci && npm run build && npm i --no-save playwright-core && node tests/gui.test.mjs dist
```

I test degli script usano **comandi finti** nel `PATH` e file temporanei: non toccano mai UFW o DNS veri.

La CI (`.github/workflows/ci.yml`, su push a `main`, pull request e ogni lunedì) esegue cinque job: **Lint**
(`gofmt`, `go vet`, `staticcheck`, `shellcheck`), **Test** (`go test -race`, fuzz del config, script, canary da
root), **eBPF** (`clang` + `bpf2go`, build, `zt-probe` sul kernel del runner), **GUI** (Vite + `npm audit`,
test nel browser, build Wails, `.deb` unico verificato) e **Sicurezza** (`govulncheck`, `gosec`). Dependabot
aggiorna Go, npm e le GitHub Actions; `release.yml` pubblica il `.deb` ai tag `v*`.

---

## 🗂️ Struttura

```text
bpf/        kernel C (1 XDP + 5 LSM), loader a runtime e test; gli stub generati non sono versionati
cmd/        zt-shield (demone) · zt-tui · zt-tray (icona) · zt-mockd · zt-probe
internal/   config · lsm · xdp · audit · canary · netstat · vpn · priv (canale privilegiato) · watchdog
pkg/        ipc (socket di lettura, SafeText) · svc (azioni di servizio dalle UI) · rules (catalogo, verifica «affidabile», blocco gestito)
zt-gui/     GUI Wails (frontend Vite + Go) con i suoi test nel browser
configs/    shield.example.yaml
VERSION     prossima versione da rilasciare (le build locali diventano <VERSION>~dev+<commit>)
scripts/    hardening, FIDO2, servizio, VPN (kill-switch, NetworkManager, Proton) e relativi test
packaging/  nfpm (.deb), unit systemd (demone e icona), policy polkit, .desktop
docs/       documentazione (vedi sotto)
```

---

## 🚧 Limiti noti

**Strutturali: si mitigano, non si risolvono.**

* **Root = game over.** Chi ha root scarica gli hook e legge tutto. Contano solo LUKS e backup offline.
* **Whitelist per binario, non per catena.** Ogni binario in lista legge i suoi file per chiunque lo invochi.
  Il segreto forte resta la chiave FIDO2.
* **`io_uring` = fail-open** (scelta per evitare falsi blocchi) e **niente hook `ptrace`**: un processo con lo
  stesso UID legge la memoria di `ssh` (mitigato da `kernel.yama.ptrace_scope=1`).
* **btrfs e overlayfs: protezione inerte** (avviso all'avvio): solo ext4 e xfs.
* **Servizio fermo = zero protezione**: nessun pinning degli hook, di proposito.

**Da sapere prima di `enforce`.**

* Il blocco è stato visto su un solo PC e con un file finto (vedi lo stato sopra): `file_truncate`, `deny_write` e le protezioni predefinite con i programmi veri non sono stati provati.
* Il radar è solo IPv4 e il poisoning IPv6 dietro extension header passa.
* Dopo un aggiornamento (apt, snap) l'inode di un browser cambia e resta fuori whitelist fino al rescan.
* Il canary uccide dopo il tocco e non ferma scritture in-place che saltano le esche.
* Il demone non applica il kill-switch VPN: applicarlo in automatico può spegnere la rete.
* Programmi installati in cartelle che puoi modificare (Homebrew, `~/.local/bin`) non entrano in whitelist
  così come sono: serve la copia protetta («Rendi affidabile») e poi lanciare quella.
* Scheda Regole e `config-apply` mai provati con `pkexec` e servizio veri; l'icona nella barra mostra solo
  ciò che il demone dichiara, non verifica il blocco reale dei file.

L'elenco completo e aggiornato è in [`docs/PUNTI_APERTI.md`](docs/PUNTI_APERTI.md).

---

## 📖 Documentazione

| Documento | Cosa contiene |
|---|---|
| [`CHANGELOG.md`](CHANGELOG.md) | Cosa cambia in ogni versione, comprese le modifiche non ancora rilasciate |
| [`docs/PUNTI_APERTI.md`](docs/PUNTI_APERTI.md) | Stato, collaudi mancanti, decisioni aperte |
| [`docs/COLLAUDO_LSM_2026-11-05.md`](docs/COLLAUDO_LSM_2026-11-05.md) | Primo blocco reale degli hook LSM: ambiente, esiti, cosa non è provato, come ripeterlo |
| [`docs/TEST_SANDBOX.md`](docs/TEST_SANDBOX.md) · [`TESTING_LAB.md`](docs/TESTING_LAB.md) · [`TESTING.md`](docs/TESTING.md) | Cosa è stato provato su kernel reale; collaudo in VM isolata; collaudo pratico di LSM, XDP, FIDO2 e pentest esterno |
| [`docs/CANARY.md`](docs/CANARY.md) · [`VPN_SETUP.md`](docs/VPN_SETUP.md) | Anti-ransomware: uso e taratura; kill-switch, auto-VPN, ProtonVPN |
| [`docs/UI_RESEARCH.md`](docs/UI_RESEARCH.md) | Ricerca TUI/GUI e architettura IPC |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) · [`FEATURE_*.md`](docs/) | Piano a fasi e studi sulle estensioni |
| [`docs/FIX_APPLICATI.md`](docs/FIX_APPLICATI.md) · [`gemini-code-*.md`](docs/) | Registro dei fix e specifiche iniziali |
| [`docs/README.md`](docs/README.md) | Indice di `docs/` con l'ordine di lettura consigliato |

---

<p align="center"><sub>ZeroShield è un progetto personale e sperimentale, rilasciato con licenza MIT. Nessuna garanzia: leggi lo <a href="#-stato-reale-del-progetto">stato reale</a> prima di fidarti di qualunque cosa.</sub></p>
