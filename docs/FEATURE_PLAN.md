# FEATURE_PLAN — egress, VPN kill-switch, antivirus

> **Stato (2026-10-05):** F1 (kill-switch) e F2 (auto-VPN) sono **implementati come script**,
> provati in un network namespace e con comandi finti, **mai su una rete reale**: vedi
> [`VPN_SETUP.md`](VPN_SETUP.md). F3 (egress per processo) e F4 (hook antivirus) restano
> pianificazione. Il resto del documento è il piano originale.

Principio: ZeroShield non cifra e non ispeziona traffico altrui. La cifratura
vera su Wi-Fi pubblico è WireGuard; qui si pianifica solo ciò che l'agente può
fare da solo: impedire che traffico in chiaro esca quando non deve.

## 1. VPN kill-switch (priorità alta, fattibile) — implementato, non collaudato su rete reale

Quando il profilo è `public-wifi`/`paranoid` e il tunnel è su:

- nftables/iptables: OUTPUT solo verso endpoint VPN + DNS del tunnel,
  INPUT solo da tunnel + DHCP essenziale. Tutto il resto DROP + log.
- XDP resta per poisoning in ingresso (non vede egress).
- Fail-safe: se il tunnel cade, niente esce (meglio offline che in chiaro).

Serve: opzione `vpn:` in YAML (endpoint, interfaccia tunnel), script
`vpn_killswitch.sh` idempotente + rollback, test in lab (kill tunnel → zero
leak verificato con tcpdump su gateway).

## 2. Auto-VPN su SSID ostili (media, facile) — implementato, non collaudato con NetworkManager vero

Dispatcher NetworkManager: se SSID non in allowlist → `wg-quick up` + profilo
`public-wifi`. Solo script + docs, nessun kernel.

## 3. Egress-filter per processo (bassa, costoso)

Cgroup `INGRESS/EGRESS` eBPF: allowlist binari→porte (es. solo browser su
443). Verifier nuovo, tuning lungo, rompe captive portal. Dopo 1+2.

## 4. Antivirus: fuori scopo, integrazione invece che rewrite

Non scriviamo motori AV. Gancio previsto: fanotify `FAN_OPEN_PERM` (stesso
meccanismo del watcher canary) verso scanner esterno (es. ClamAV on-access).
Il demone nega l'open se lo scanner dice male. Solo hook + config
`av_socket:` — il motore resta altrui.

## Ordine

kill-switch → auto-VPN → (canary fatto e collaudato, propedeutico a 4) → egress.
