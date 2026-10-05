#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Installa un .conf WireGuard di ProtonVPN come profilo 'proton'.
# Uso: sudo scripts/proton_setup.sh [--remove-source] /percorso/scaricato.conf
#
# Il .conf lo scarichi TU da account.protonvpn.com (Downloads → WireGuard): richiede il
# tuo login, nessuno puo' farlo al posto tuo. Non connette nulla: installa solo il file
# con permessi 0600 in /etc/wireguard.
#
# ATTENZIONE: il file scaricato contiene la tua CHIAVE PRIVATA e resta dov'e' (di solito
# ~/Downloads, leggibile da tutti i tuoi processi). Dopo l'installazione cancellalo, o
# usa --remove-source. Su SSD e filesystem copy-on-write nessuna cancellazione e'
# garantita irrecuperabile: se il file e' finito altrove (cloud, backup), considera la
# chiave compromessa e genera una nuova configurazione dall'account Proton.
set -euo pipefail
umask 077

REMOVE=0
if [ "${1:-}" = "--remove-source" ]; then REMOVE=1; shift; fi
SRC="${1:-}"
[ -n "$SRC" ] || { echo "Uso: sudo $0 [--remove-source] /percorso/proton.conf"; exit 1; }
DEST_DIR="${ZT_WG_DIR:-/etc/wireguard}"
# ZT_WG_DIR serve ai test; in uso normale serve root per scrivere in /etc/wireguard.
[ "$(id -u)" -eq 0 ] || [ -n "${ZT_WG_DIR:-}" ] || exec sudo "$0" "$@"
[ -f "$SRC" ] || { echo "❌ File non trovato: $SRC"; exit 1; }
grep -q "^\[Interface\]" "$SRC" || { echo "❌ Non sembra un .conf WireGuard ([Interface] assente)"; exit 1; }
grep -q "^PrivateKey" "$SRC" || { echo "❌ Manca PrivateKey: config incompleto"; exit 1; }
ENDPOINT="$(grep -m1 "^Endpoint" "$SRC" | cut -d= -f2- | tr -d ' ')"
[ -n "$ENDPOINT" ] || { echo "❌ Manca Endpoint nel .conf"; exit 1; }
# Il kill-switch ammette solo IP: senza tunnel non c'e' DNS per risolvere un nome.
if ! [[ "$ENDPOINT" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{1,5}$ || "$ENDPOINT" =~ ^\[[0-9A-Fa-f:.]+\]:[0-9]{1,5}$ ]]; then
    echo "❌ Endpoint '$ENDPOINT' non e' IP:porta. Il kill-switch non puo' usare un nome host:"
    echo "   scarica una configurazione con l'IP del server, oppure risolvilo (getent ahostsv4 <nome>)"
    echo "   e sostituiscilo nel .conf."
    exit 1
fi

# Proprietario root solo in uso normale; con ZT_WG_DIR (test, utente non root) resta quello corrente.
OWN=(-o root -g root)
[ "$(id -u)" -eq 0 ] || OWN=()
install -d "${OWN[@]}" -m 0755 "$DEST_DIR"
install "${OWN[@]}" -m 0600 "$SRC" "$DEST_DIR/proton.conf"
echo "✅ Installato in $DEST_DIR/proton.conf (0600, solo root)."
echo
echo "Metti in /etc/zt-shield/shield.yaml:"
echo "  vpn:"
echo "    enabled: true"
echo "    endpoint: \"$ENDPOINT\""
echo "    tunnel: \"proton\""
echo
if [ "$REMOVE" -eq 1 ]; then
    if command -v shred >/dev/null 2>&1; then shred -u "$SRC"; else rm -f "$SRC"; fi
    echo "🧹 File originale rimosso (best effort: vedi avvertenza su SSD/cloud in testa allo script)."
else
    echo "⚠️  Il file scaricato ($SRC) contiene la tua chiave privata ed e' ancora li'."
    echo "    Cancellalo ora:  shred -u '$SRC'   (o rilancia con --remove-source)"
fi
echo
echo "Poi, in VM con snapshot (mai qui senza test):"
echo "  sudo wg-quick up proton   # alza il tunnel (questo SI' connette)"
