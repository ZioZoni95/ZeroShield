# VPN con ProtonVPN + kill-switch ZeroShield

Solo appunti operativi. Teoria in `FEATURE_PLAN.md` (F1/F2).

## Setup tunnel (una volta)

1. account.protonvpn.com → Downloads → WireGuard configuration → server
   (CH/DE veloci) → scarica `.conf`.
2. `sudo wg-quick up ./proton-ch.conf` (rinomina in `wg0.conf` per interfaccia `wg0`).
3. Verifica: `curl ifconfig.me` = IP server, non tuo.

## Kill-switch nostro sopra

```bash
sudo scripts/vpn_killswitch.sh on <IP:porta-del-.conf> <interfaccia>
```

Da qui, tunnel giù = offline (non in chiaro). Un solo kill-switch attivo:
o app Proton o nostro script, mai entrambi.

## Test in VM (snapshot prima)

1. Tunnel su, kill-switch on.
2. `sudo wg-quick down <profilo>` → `tcpdump` su gateway muto 60 s.
3. `sudo scripts/vpn_killswitch.sh off` → rete normale.

## Auto-VPN (facoltativo)

`scripts/nm_vpn.sh` in dispatcher NetworkManager + `/etc/zt-shield/vpn-nets`
con BSSID fidati (mai solo SSID). `WG_PROFILE` = nome tuo `.conf`.
