#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Rileva la connessione ProtonVPN attiva (GUI, non CLI) e stampa i valori
# per shield.yaml + vpn_killswitch.sh. Solo lettura: non connette, non tocca nulla.
# Uso: bash scripts/proton_current.sh
# Ignora volutamente altre VPN (es. tunnel di lavoro già attivi).
set -uo pipefail

# 1. Interfacce WireGuard attive (Proton GUI crea proton0/wg0-like via NM)
found=""
for d in /sys/class/net/*; do
    ifc="$(basename "$d")"
    [ "$ifc" = "lo" ] && continue
    if [ -d "/sys/class/net/$ifc/wireless" ]; then continue; fi
    # euristica: interfaccia punto-punto senza MAC wifi/eth, con peer wg
    if wg show "$ifc" endpoints 2>/dev/null | grep -q .; then
        found="$ifc"
        break
    fi
done
if [ -z "$found" ]; then
    # fallback: connessione NM di tipo wireguard attiva
    found="$(nmcli -t -f NAME,TYPE,STATE connection show --active 2>/dev/null | awk -F: '$2=="wireguard" && $3~/activated/ {print $1; exit}')"
fi
if [ -z "$found" ]; then
    echo "ℹ️  Nessuna connessione WireGuard attiva (Proton GUI spenta o disconnessa)."
    echo "    Connettiti dalla app Proton, poi rilancia questo script."
    exit 1
fi
echo "Interfaccia: $found"
wg show "$found" endpoints 2>/dev/null | while read -r _ ep; do
    echo "Endpoint:  $ep"
done
echo
echo "Per shield.yaml:"
echo "  vpn:"
echo "    enabled: true"
echo "    endpoint: \"<Endpoint sopra>\""
echo "    tunnel: \"$found\""
