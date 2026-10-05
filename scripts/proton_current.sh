#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Rileva la connessione ProtonVPN attiva (GUI, non CLI) e stampa i valori per
# shield.yaml + vpn_killswitch.sh. Solo lettura: non connette, non tocca nulla.
#
# Uso: sudo bash scripts/proton_current.sh [--iface NOME]
#
# Riconosce Proton dal NOME (interfaccia o connessione NetworkManager che contiene
# "proton" o "pvpn"). Altri tunnel (es. quello di lavoro) vengono elencati ma MAI
# scelti da soli: prima si prendeva la prima interfaccia con un peer WireGuard, che
# poteva essere proprio il tunnel che questo script dichiarava di ignorare, e il
# kill-switch finiva configurato sull'endpoint sbagliato. Con --iface la scelta e' tua.
#
# Serve root per leggere WireGuard (`wg show`).
set -uo pipefail

FORCE=""
case "${1:-}" in
    --iface) FORCE="${2:-}"; [ -n "$FORCE" ] || { echo "Uso: $0 [--iface NOME]"; exit 1; } ;;
    "") ;;
    -h|--help) sed -n 2,14p "$0"; exit 0 ;;
    *) echo "Uso: $0 [--iface NOME]"; exit 1 ;;
esac
if [ -n "$FORCE" ] && ! [[ "$FORCE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
    echo "❌ nome interfaccia non valido: $FORCE"; exit 1
fi

if [ "$(id -u)" -ne 0 ] && [ -z "${ZT_ALLOW_NONROOT:-}" ]; then
    echo "ℹ️  Senza root 'wg show' non vede i tunnel: rilancia con sudo."
fi

SYSNET="${ZT_SYS_NET:-/sys/class/net}"

# 1. Tutte le interfacce con almeno un peer WireGuard, con il loro endpoint.
declare -a names=() endpoints=()
for d in "$SYSNET"/*; do
    ifc="$(basename "$d")"
    [ "$ifc" = "lo" ] && continue
    ep="$(wg show "$ifc" endpoints 2>/dev/null | awk 'NF >= 2 {print $2; exit}')"
    if [ -n "$ep" ] && [ "$ep" != "(none)" ]; then
        names+=("$ifc")
        endpoints+=("$ep")
    fi
done

if [ "${#names[@]}" -eq 0 ]; then
    echo "ℹ️  Nessun tunnel WireGuard attivo (Proton spenta o disconnessa, oppure manca root)."
    echo "    Connettiti dalla app Proton, poi rilancia con sudo."
    exit 1
fi

pick=""
if [ -n "$FORCE" ]; then
    for i in "${!names[@]}"; do [ "${names[$i]}" = "$FORCE" ] && pick="$i"; done
    [ -n "$pick" ] || { echo "❌ $FORCE non e' un tunnel WireGuard attivo. Attivi: ${names[*]}"; exit 1; }
else
    # Candidati riconosciuti come Proton dal nome dell'interfaccia.
    matches=()
    for i in "${!names[@]}"; do
        shopt -s nocasematch
        if [[ "${names[$i]}" == *proton* || "${names[$i]}" == *pvpn* ]]; then matches+=("$i"); fi
        shopt -u nocasematch
    done
    if [ "${#matches[@]}" -eq 1 ]; then
        pick="${matches[0]}"
    else
        echo "⚠️  Tunnel WireGuard attivi, nessuno scelto in automatico:"
        for i in "${!names[@]}"; do echo "    ${names[$i]}  →  ${endpoints[$i]}"; done
        if [ "${#matches[@]}" -gt 1 ]; then
            echo "    (piu' di uno sembra Proton)"
        else
            echo "    (nessuno ha 'proton' nel nome: potrebbe essere il tunnel di lavoro)"
        fi
        echo "    Scegli tu: $0 --iface NOME"
        exit 1
    fi
fi

echo "Interfaccia: ${names[$pick]}"
echo "Endpoint:    ${endpoints[$pick]}"
echo
echo "Per shield.yaml:"
echo "  vpn:"
echo "    enabled: true"
echo "    endpoint: \"${endpoints[$pick]}\""
echo "    tunnel: \"${names[$pick]}\""
echo
echo "Poi applica il kill-switch (solo in VM finche' non e' collaudato):"
echo "  sudo scripts/vpn_killswitch.sh on ${endpoints[$pick]} ${names[$pick]}"
