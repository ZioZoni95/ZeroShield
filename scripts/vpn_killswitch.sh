#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# VPN kill-switch via nftables (vedi docs/FEATURE_PLAN.md F1).
# Uso: sudo scripts/vpn_killswitch.sh on <endpoint-IP:porta> <tunnel-if> [lan-cidr...]
#      sudo scripts/vpn_killswitch.sh off
#      sudo scripts/vpn_killswitch.sh portal   # 5 min per captive portal, poi riattiva
#
# Con 'on' esce SOLO: tunnel, endpoint VPN, DHCP (a meno di BLOCK_DHCP=1),
# loopback e LAN extra passate come argomento. Tutto il resto DROP + log.
# Fail-safe: se il tunnel cade, niente esce (meglio offline che in chiaro).
# MAI eseguire senza aver letto il rollback qui sotto: 'off' ripristina il backup.
set -euo pipefail

CMD="${1:-}"
BACKUP="/tmp/zt-nft.backup"
TABLE="zt-killswitch"

usage() { echo "Uso: sudo $0 on <endpoint-IP:porta> <tunnel-if> [lan-cidr...] | off | portal"; exit 1; }
[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
command -v nft >/dev/null || { echo "❌ nftables mancante: sudo apt install nftables"; exit 1; }

nft_on() {
    local endpoint="$1" tun="$2"; shift 2
    local ep_ip="${endpoint%:*}" ep_port="${endpoint##*:}"
    [ -n "$ep_ip" ] && [ -n "$ep_port" ] && [ "$ep_ip" != "$endpoint" ] \
        || { echo "❌ endpoint deve essere IP:porta (es. 203.0.113.7:51820)"; exit 1; }
    ip link show "$tun" >/dev/null 2>&1 \
        || { echo "❌ interfaccia $tun assente: alza prima il tunnel (wg-quick up)"; exit 1; }
    # Backup una tantum: se esiste già, non sovrascrivere (è il paracadute).
    if [ ! -f "$BACKUP" ]; then
        nft list ruleset > "$BACKUP"
        echo "💾 Backup regole in $BACKUP"
    else
        echo "ℹ️  Backup esistente tenuto: $BACKUP"
    fi
    nft delete table inet "$TABLE" 2>/dev/null || true
    {
        echo "table inet $TABLE {"
        echo "  chain out { type filter hook output priority 0; policy drop;"
        echo "    oifname \"lo\" accept"
        echo "    oifname \"$tun\" accept"
        echo "    ip daddr $ep_ip udp dport $ep_port accept"
        echo "    ip daddr $ep_ip tcp dport $ep_port accept"
        if [ "${BLOCK_DHCP:-0}" != "1" ]; then
            echo "    udp dport 67 accept"
            echo "    udp sport 68 accept"
        fi
        for cidr in "$@"; do echo "    ip daddr $cidr accept"; done
        echo "    limit rate 5/minute log prefix \"zt-ks-drop: \""
        echo "  }"
        echo "  chain in { type filter hook input priority 0; policy drop;"
        echo "    iifname \"lo\" accept"
        echo "    iifname \"$tun\" accept"
        echo "    ct state established,related accept"
        if [ "${BLOCK_DHCP:-0}" != "1" ]; then
            echo "    udp sport 67 udp dport 68 accept"
        fi
        echo "  }"
        echo "}"
    } | nft -f -
    echo "✅ Kill-switch attivo: solo $tun + $endpoint escono."
    echo "   Verifica leak: dal gateway, tcpdump deve restare muto 60s."
}

nft_off() {
    nft delete table inet "$TABLE" 2>/dev/null || true
    if [ -f "$BACKUP" ]; then
        nft flush ruleset
        nft -f "$BACKUP"
        rm -f "$BACKUP"
        echo "✅ Regole ripristinate dal backup."
    else
        echo "ℹ️  Nessun backup: rimossa solo la tabella $TABLE."
    fi
}

case "$CMD" in
    on) [ $# -ge 3 ] || usage; nft_on "$2" "$3" "${@:4}" ;;
    off) nft_off ;;
    portal)
        # Captive portal: 5 minuti aperti, POI RIATTIVA DA SOLO.
        # Non usarlo come scusa per restare senza kill-switch.
        nft_off
        echo "⚠️  Rete aperta 5 minuti per il login al portal, poi richiedo 'on'."
        sleep 300
        echo "❌ Tempo scaduto: riesegui '$0 on ...' a mano (niente auto-on cieco)."
        ;;
    *) usage ;;
esac
