#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Installa un .conf WireGuard di ProtonVPN come profilo 'proton'.
# Uso: sudo scripts/proton_setup.sh /percorso/scaricato.conf
# Il .conf lo scarichi TU da account.protonvpn.com (Downloads → WireGuard):
# richiede il tuo login, nessuno può farlo al posto tuo.
# Non connette nulla: installa solo il file con permessi 0600.
set -euo pipefail

SRC="${1:-}"
[ -n "$SRC" ] || { echo "Uso: sudo $0 /percorso/proton.conf"; exit 1; }
[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
[ -f "$SRC" ] || { echo "❌ File non trovato: $SRC"; exit 1; }
grep -q "^\[Interface\]" "$SRC" || { echo "❌ Non sembra un .conf WireGuard ([Interface] assente)"; exit 1; }
grep -q "^PrivateKey" "$SRC" || { echo "❌ Manca PrivateKey: config incompleto"; exit 1; }
ENDPOINT="$(grep -m1 "^Endpoint" "$SRC" | cut -d= -f2 | tr -d ' ')"
[ -n "$ENDPOINT" ] || { echo "❌ Manca Endpoint nel .conf"; exit 1; }

install -d -o root -g root -m 0755 /etc/wireguard
install -o root -g root -m 0600 "$SRC" /etc/wireguard/proton.conf
echo "✅ Installato in /etc/wireguard/proton.conf (0600, solo root)."
echo
echo "Metti in /etc/zt-shield/shield.yaml:"
echo "  vpn:"
echo "    enabled: true"
echo "    endpoint: \"$ENDPOINT\""
echo "    tunnel: \"proton\""
echo
echo "Poi, in VM con snapshot (mai qui senza test):"
echo "  sudo wg-quick up proton   # alza il tunnel (questo SÌ connette)"
