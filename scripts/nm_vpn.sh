#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Auto-VPN su reti non fidate (vedi docs/FEATURE_PLAN.md F2).
# Installazione: sudo install -m 0755 scripts/nm_vpn.sh /etc/NetworkManager/dispatcher.d/90-zt-vpn
# Configura in /etc/zt-shield/vpn-nets (una riga per rete fidata: "SSID BSSID"):
#   Casa AA:BB:CC:DD:EE:FF
#   Ufficio 11:22:33:44:55:66
# Fiducia su BSSID, MAI solo sul nome (evil-twin "Casa" è banale).
# Richiede: WireGuard + profilo funzionante. Con ProtonVPN: scarica il .conf
# dall'account, mettilo in /etc/wireguard/proton.conf e imposta
# WG_PROFILE=proton (default sotto). Vedi docs/VPN_SETUP.md.
set -euo pipefail

IFACE="${1:-}"
EVENT="${2:-}"
ALLOWFILE="/etc/zt-shield/vpn-nets"
WG_PROFILE="${WG_PROFILE:-proton}"
# PROTON=1: alza via app Proton (scripts/proton_up.sh) invece di wg-quick.
# Serve protonvpn-cli + login fatto una volta; senza, logga e non fa danni.
PROTON="${PROTON:-0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

[ "$EVENT" = "up" ] || exit 0
[ -f "$ALLOWFILE" ] || exit 0  # senza allowlist: non toccare nulla

SSID="$(iwgetid -r 2>/dev/null || true)"
BSSID="$(iwgetid -a -r 2>/dev/null | tr 'a-z' 'A-Z' || true)"
if grep -qiF "$BSSID" "$ALLOWFILE" 2>/dev/null; then
    logger -t zt-vpn "rete fidata ($SSID $BSSID): tunnel giù"
    wg-quick down "$WG_PROFILE" 2>/dev/null || true
else
    logger -t zt-vpn "rete non fidata ($SSID $BSSID): alzo VPN"
    if [ "$PROTON" = "1" ]; then
        "$SCRIPT_DIR/proton_up.sh" connect || logger -t zt-vpn "ERRORE: proton_up fallito, resta scoperto"
    else
        wg-quick up "$WG_PROFILE" || logger -t zt-vpn "ERRORE: tunnel non partito, resta scoperto"
    fi
fi
