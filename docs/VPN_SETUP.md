# VPN con ProtonVPN + kill-switch ZeroShield

> **Stato: provato solo in un network namespace e con comandi finti** (vedi
> [`TEST_SANDBOX.md`](TEST_SANDBOX.md)). Mai su una rete reale, mai con un tunnel vero,
> mai con NetworkManager vero. Gli script cambiano le regole di rete di una macchina
> **come root**: la prima volta, solo in una VM con snapshot.

Percorsi: negli esempi gli script sono `scripts/…` (da sorgente). Con il pacchetto `.deb` stanno
in `/usr/share/zeroshield/scripts/`.

## Cosa fa e cosa no

| Pezzo | Chi lo fa | Note |
|---|---|---|
| Cifrare il traffico | **WireGuard** (`wg-quick` o l'app Proton) | ZeroShield non cifra niente |
| Bloccare tutto tranne il tunnel | `scripts/vpn_killswitch.sh` | nftables, UNA tabella `inet zt-killswitch` |
| Alzare il tunnel su reti non fidate | `scripts/nm_vpn.sh` | dispatcher NetworkManager, opt-in |
| **Misurare** lo stato e avvisare | il demone `zt-shield` | tunnel su, kill-switch attivo, handshake |

**Il demone non applica il kill-switch.** `vpn.enabled: true` nel config significa "monitora
questo tunnel", non "attivalo": il kill-switch lo applichi tu con lo script. Il demone legge
lo stato reale (la tabella nft esiste adesso? l'interfaccia è UP? quando è stato l'ultimo
handshake?) e lo mostra in TUI e GUI. Per questo ci sono quattro stati, non due:

| Tunnel | Kill-switch | Le UI mostrano |
|---|---|---|
| su | attivo | 🔒 **protetta** (l'unico verde) |
| su | **non** attivo | ⚠️ protetta solo finché il tunnel regge: se cade esci in chiaro |
| giù | attivo | ⛔ offline ma **non in chiaro** |
| giù | non attivo | ⚠️ **in chiaro** |

Il controllo avviene ogni 5 secondi (non ogni `rescan_seconds`) e il demone logga ogni cambio.
`up` indica che l'interfaccia esiste ed è UP, non che il traffico passi: per questo si mostra
anche l'età dell'ultimo handshake.

## Regola d'oro: accensioni solo in VM

Il tunnel di lavoro che hai già attivo su una macchina va **lasciato stare**: un kill-switch
applicato male stacca lavoro e proxy. Prove di accensione e spegnimento solo in VM con
snapshot. `proton_current.sh` non sceglie mai da solo un tunnel che non si chiami Proton.

## Setup del tunnel (una volta)

1. account.protonvpn.com → Downloads → WireGuard configuration → scegli un server → scarica il `.conf`.
2. Installalo come profilo `proton`:
   ```bash
   sudo scripts/proton_setup.sh --remove-source ~/Downloads/proton-ch.conf
   ```
   Lo script:
   - verifica `[Interface]`, `PrivateKey` ed `Endpoint`;
   - **rifiuta un Endpoint che non sia un IP** (il kill-switch non può risolvere un nome senza tunnel);
   - installa in `/etc/wireguard/proton.conf` con modo `0600`;
   - con `--remove-source` cancella il file scaricato. Senza, ti avvisa: **contiene la tua
     chiave privata** ed è rimasto in `~/Downloads`. Su SSD e filesystem copy-on-write
     nessuna cancellazione è garantita: se il file è finito in un cloud o in un backup,
     genera una nuova configurazione dall'account.
   - stampa la stanza `vpn:` da incollare nel config.
3. Metti nel config (`/etc/zt-shield/shield.yaml`) i valori stampati:
   ```yaml
   vpn:
     enabled: true
     endpoint: "185.107.80.5:51820"   # IPv4:porta oppure "[2001:db8::1]:51820", mai un nome host
     tunnel: "proton"                 # max 15 caratteri: lettere, cifre, _ . -
     allow_lan: ["192.168.1.0/24"]    # facoltativo (stampante...), IPv4 o IPv6
   ```
   Il config viene validato all'avvio: un endpoint o un nome interfaccia malformato fa
   fermare il demone con un messaggio chiaro, invece di arrivare allo script.
4. In VM: `sudo wg-quick up proton`, poi `curl ifconfig.me` deve mostrare l'IP del server, non il tuo.

Se usi l'app grafica di Proton (non `wg-quick`), `sudo bash scripts/proton_current.sh` legge il
tunnel attivo e stampa endpoint e interfaccia. Riconosce Proton dal nome ("proton" o "pvpn");
se trova solo altri tunnel li elenca e **non ne sceglie nessuno** (`--iface NOME` per decidere tu).

## Kill-switch

```bash
sudo scripts/vpn_killswitch.sh on <endpoint> <interfaccia-tunnel> [lan-cidr...]
sudo scripts/vpn_killswitch.sh status      # rc 0 = attivo, rc 3 = non attivo
sudo scripts/vpn_killswitch.sh off
sudo scripts/vpn_killswitch.sh portal [interfaccia] [secondi]
```

Con `on` esce **solo**: il tunnel, l'endpoint VPN (UDP e TCP), il DHCP (a meno di
`BLOCK_DHCP=1`: senza DHCP il tunnel non si riallaccia dopo un cambio di rete), il loopback
e le LAN extra. Tutto il resto viene scartato e loggato (`zt-ks-drop`, al massimo 5/minuto).
Se il tunnel cade, niente esce: meglio offline che in chiaro.

Come è fatto, e perché (ogni punto era un difetto della prima versione):

- **Tocca una sola tabella.** Niente backup del ruleset, niente `flush ruleset`. `off` fa
  `nft delete table inet zt-killswitch` e il resto del firewall (UFW, Docker...) è
  esattamente com'era. Prima `off` cancellava tutto e ricaricava un backup da `/tmp`: se il
  ricaricamento falliva restavi senza firewall, e se il file l'aveva scritto un altro utente
  lo caricavi come root.
- **Applicazione atomica.** Un solo `nft -f` con `add table` + `delete table` + `table`:
  la vecchia tabella viene sostituita in un colpo, e se nft rifiuta il ruleset non cambia
  niente. Prima un errore lasciava la macchina senza kill-switch. Prima di applicare, `nft -c`
  controlla il ruleset senza toccare niente.
- **Input validati prima di costruire le regole:** endpoint IPv4 o `[IPv6]`, porta 1-65535,
  nome interfaccia, CIDR v4/v6. Un valore con `;` o spazi viene rifiutato.
- **`portal` si chiude da solo.** Per il login di un captive portal apre per N secondi
  (default 300, da 5 a 900) **solo** web (80/443) e DNS sull'interfaccia fisica. La scadenza è
  un timeout dell'elemento nel set nft: la gestisce il kernel, senza processi di appoggio.
  Se chiudi il terminale, o lo script muore, si chiude lo stesso. Prima restava aperto per
  sempre.
- Nessun file di stato, nessun backup: non c'è niente in `/tmp` da piazzare o da leggere.

Limiti noti: l'IPv6 sull'interfaccia fisica è bloccato (è voluto: fail-closed); nome host
come endpoint non è supportato; non è un firewall completo.

## Auto-VPN su reti non fidate (facoltativo)

```bash
sudo install -m 0755 scripts/nm_vpn.sh /etc/NetworkManager/dispatcher.d/90-zt-vpn
```

Reti fidate in `/etc/zt-shield/vpn-nets` (**senza questo file lo script non fa nulla**):

```text
# SSID (libero)  BSSID
Casa     AA:BB:CC:DD:EE:FF
Ufficio  11:22:33:44:55:66
wired                            # facoltativo: il cavo è fidato
```

Regole, tutte per fallire dal lato sicuro:

- Agisce solo su interfacce **fisiche**: docker0, veth, bridge e il tunnel stesso sono ignorati.
- Decide per l'interfaccia che ha generato l'evento.
- Una rete è fidata solo se **identificata**: BSSID in elenco (confronto esatto, non su
  sottostringa; righe commentate escluse), oppure `wired` esplicito per il cavo. BSSID vuoto,
  malformato o assente = **non fidata** = VPN su. (Prima un BSSID vuoto, per esempio sul cavo
  di un hotel, risultava "fidato" e spegneva il tunnel.)
- **Su rete fidata non spegne la VPN.** Il BSSID si clona con un access point falso (`airbase-ng`):
  spegnere lo scudo su un dato falsificabile è l'attacco. Solo con `AUTO_DOWN=1`, esplicito.
- Non rilancia un tunnel già attivo.
- `WG_PROFILE` (default `proton`) è il nome del profilo. Con `PROTON=1` alza il tunnel con
  `proton_up.sh connect` (serve `protonvpn-cli`); lo script lo cerca in
  `/usr/share/zeroshield/scripts` e accanto a sé, quindi funziona anche copiato in
  `dispatcher.d`.

I log vanno nel journal: `journalctl -t zt-vpn`.

## Test del kill-switch in VM (snapshot prima)

1. Tunnel su, `sudo scripts/vpn_killswitch.sh on <endpoint> proton`, `status` = attivo.
2. Nelle UI: 🔒 protetta.
3. `sudo wg-quick down proton` → nelle UI entro ~5 s: ⛔ offline ma non in chiaro; `tcpdump` su
   un gateway deve restare muto per 60 s.
4. `sudo scripts/vpn_killswitch.sh portal wlan0 30` → login al portal; dopo 30 s si richiude
   (`status` e `nft list set inet zt-killswitch portal_ifaces`).
5. `sudo scripts/vpn_killswitch.sh off` → rete normale, UFW intatto (`sudo ufw status`).

Un solo kill-switch alla volta: o l'app Proton o questo script, mai entrambi.

## Test automatici

```bash
make test-scripts
# = bash scripts/test_nm_vpn.sh      (comandi finti, nessun privilegio)
#   bash scripts/test_proton.sh      (comandi finti)
#   sudo bash scripts/test_killswitch.sh   (network namespace usa e getta: non tocca la rete)
```

Il test del kill-switch copre i difetti trovati nella revisione del 2026-10-05; è stato
verificato che **fallisce** sulla versione precedente dello script.
