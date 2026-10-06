# FEATURE_STUDY — pseudosoluzioni annotate (studio)

> **F1 e F2 sono stati implementati** (`scripts/vpn_killswitch.sh`, `scripts/nm_vpn.sh`) e
> **hanno corretto proprio le trappole che questo studio elenca**, più altre emerse dalla
> revisione: l'applicazione è atomica, il rollback non usa backup né `flush ruleset`, il
> captive portal si chiude da solo per timeout del kernel, la fiducia nel BSSID non spegne mai
> la VPN. Lo pseudocodice qui sotto è storico: la versione che vale è in
> [`VPN_SETUP.md`](VPN_SETUP.md). F3 e F4 restano studio.

Come leggere: per ogni feature, problema → idea → pseudocodice → trappole.
Niente di questo gira: serve a decidere cosa costruire dopo, in che ordine.

## F1. VPN kill-switch (priorità alta)

Problema: su Wi-Fi ostile, se il tunnel cade il traffico esce in chiaro
senza che te ne accorga.

Pseudosoluzione (nftables, idempotente, con rollback):

```sh
# vpn_killswitch.sh on <endpoint> <tunnel-if>
# 1. salva stato: nft list ruleset > /tmp/zt-nft.backup
# 2. tabu OUTPUT: allow solo verso ENDPOINT (udp/443 o porta WG),
#    allow su interfaccia TUNNEL, allow DHCP (67/68) + loopback
# 3. INPUT: allow da TUNNEL + established, drop resto hostili
# vpn_killswitch.sh off  -> ripristina backup
```

Trappole annotate:
- DHCP prima del tunnel: se blocchi tutto tranne VPN, il rinnovo DHCP muore
  e il tunnel non si riallaccia. Ordine: allow DHCP sempre.
- Captive portal: con kill-switch attivo non fai mai login. Serve modo
  `portal` temporaneo (timer 5 min, poi riattiva).
- DNS: solo resolver del tunnel, mai quelli DHCP (già policy DoT esistente).
- Test: kill `wg-quick down` → `tcpdump` su gateway deve restare muto 60s.

## F2. Auto-VPN su SSID ostili (facile)

Problema: dimentichi di alzare il tunnel al bar.

```sh
# /etc/NetworkManager/dispatcher.d/90-zt-vpn.sh
# SSID=$(iwgetid -r); case $SSID in casa|ufficio) wg-quick down ;; *)
#   wg-quick up casa && harden public-wifi ;; esac
```

Trappole: SSID spoofabile (evil-twin "casa") → allowlist su BSSID, non solo
nome. Mai fidarsi del nome rete.

## F3. Egress-filter per processo (costoso, dopo F1+F2)

Problema: malware esfiltra via 443 come tutti, indistinguibile dal browser.

```c
// SEC("cgroup/connect4"): hook su connect(), non su pacchetto.
// Leggi exe_file come in file_open; mappa allow (exe -> porte/ip).
// Sconosciuto -> DENY in enforce, log in audit.
```

Trappole: ogni app legittima nuova va in allowlist (attrito alto); DoH/DoT
bypassano filtri DNS; captive portal si rompe; verifier su helper diversi
da file_open (nuovo codice kernel = nuova VM di test). Valutare nftables
con `cgroupv2 match` prima di scrivere C.

## F4. Gancio antivirus esterno via fanotify (integrazione, non motore)

Problema: non scriviamo motori AV (fuori scopo), ma il watcher canary ha già
il punto di aggancio giusto.

```
// su FAN_OPEN_PERM di file in watch_dirs (non canary):
//   1. sospendi open (perm event blocca da sé)
//   2. passa fd a scanner esterno via socket unix (es. clamd)
//   3. verdetto malevolo -> FAN_DENY + kill + IPC canary-like
//   4. timeout scanner -> ALLOW + log (fail-open: mai bloccare tutto per AV down)
```

Trappole: latenza su ogni open (cache verdetti per dev+ino, invalida su
CLOSE_WRITE); scanner down = fail-open obbligatorio; stesso limite root
del resto. Config `av_socket:` spenta di default.

## Ordine consigliato

F1 (settimane, valore massimo) → F2 (ore) → F4 (hook piccolo, motore altrui)
→ F3 (solo se F1 non basta). Canary già implementato è propedeutico a F4.
