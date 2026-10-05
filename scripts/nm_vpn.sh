#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Auto-VPN su reti non fidate: dispatcher di NetworkManager (vedi docs/VPN_SETUP.md).
#
# Installazione:
#   sudo install -m 0755 scripts/nm_vpn.sh /etc/NetworkManager/dispatcher.d/90-zt-vpn
# (con il pacchetto .deb lo script e' in /usr/share/zeroshield/scripts/)
#
# Reti fidate in /etc/zt-shield/vpn-nets, una per riga ("#" = commento):
#   Casa AA:BB:CC:DD:EE:FF        Wi-Fi: SSID (libero) + BSSID
#   Ufficio 11:22:33:44:55:66
#   wired                         opzionale: considera fidata la rete via cavo
# Senza questo file lo script non fa nulla (la funzione e' opt-in).
#
# Regole di progetto, tutte per fallire dal lato sicuro:
#   - Agisce solo su interfacce FISICHE (Wi-Fi, ethernet, tethering USB). docker0,
#     veth, bridge e lo stesso tunnel WireGuard vengono ignorati.
#   - Decide per l'interfaccia che ha generato l'evento, non per "il primo Wi-Fi".
#   - Rete non riconosciuta, BSSID vuoto o malformato, cavo senza "wired": NON fidata,
#     quindi alza la VPN. Prima un BSSID vuoto (cavo, hotel) risultava "fidato" e
#     spegneva il tunnel: grep -F "" corrisponde a qualsiasi riga.
#   - Su rete fidata NON spegne la VPN da solo (il BSSID si clona con un access point
#     falso, e uno scudo non deve spegnersi su un dato falsificabile). Solo con
#     AUTO_DOWN=1, esplicito.
#   - Non rilancia un tunnel gia' attivo.
set -uo pipefail

IFACE="${1:-}"
EVENT="${2:-}"
# Gli override servono ai test; sotto NetworkManager l'ambiente e' quello di root.
ALLOWFILE="${ZT_VPN_NETS:-/etc/zt-shield/vpn-nets}"
SYSNET="${ZT_SYS_NET:-/sys/class/net}"
LOCKFILE="${ZT_LOCK:-/run/zt-vpn.lock}"
WG_PROFILE="${WG_PROFILE:-proton}"
# PROTON=1: alza via scripts/proton_up.sh invece di wg-quick (serve protonvpn-cli).
PROTON="${PROTON:-0}"
AUTO_DOWN="${AUTO_DOWN:-0}"

log() { logger -t zt-vpn -- "$*" 2>/dev/null || true; }

[ "$EVENT" = "up" ] || exit 0
[[ "$IFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || exit 0
[ -f "$ALLOWFILE" ] || exit 0                 # opt-in: senza allowlist non si tocca nulla
[[ "$WG_PROFILE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || { log "WG_PROFILE non valido: $WG_PROFILE"; exit 0; }
# Solo hardware reale: le interfacce virtuali non hanno il link "device" in sysfs.
[ -e "$SYSNET/$IFACE/device" ] || exit 0

# Un evento alla volta: wifi ed ethernet possono salire insieme.
if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCKFILE"
    flock -w 20 9 || { log "lock occupato, evento su $IFACE saltato"; exit 0; }
fi

trusted=0
what=""
if [ -d "$SYSNET/$IFACE/wireless" ]; then
    bssid="$(iwgetid "$IFACE" -a -r 2>/dev/null | tr '[:lower:]' '[:upper:]' || true)"
    ssid="$(iwgetid "$IFACE" -r 2>/dev/null || true)"
    what="Wi-Fi '$ssid' $bssid"
    # BSSID vuoto o malformato = non identificabile = non fidato.
    if [[ "$bssid" =~ ^([0-9A-F]{2}:){5}[0-9A-F]{2}$ ]]; then
        # Corrispondenza esatta su un campo intero, righe commentate escluse.
        # (grep -F sulla sottostringa dava falsi positivi.)
        if awk -v b="$bssid" '/^[[:space:]]*#/ {next} {for (i = 1; i <= NF; i++) if (toupper($i) == b) found = 1} END {exit !found}' "$ALLOWFILE"; then
            trusted=1
        fi
    fi
else
    what="cavo/altro"
    # Il cavo e' fidato solo se lo dici tu, esplicitamente.
    if awk '/^[[:space:]]*#/ {next} $1 == "wired" && NF == 1 {found = 1} END {exit !found}' "$ALLOWFILE"; then
        trusted=1
    fi
fi

tunnel_up() { ip link show "$WG_PROFILE" >/dev/null 2>&1; }

find_proton_up() {
    local d
    for d in "${ZT_SCRIPTS:-}" "${ZT_SYS_SCRIPTS-/usr/share/zeroshield/scripts}" "$(dirname "$0")" "$(dirname "$0")/../scripts"; do
        [ -n "$d" ] && [ -x "$d/proton_up.sh" ] && { echo "$d/proton_up.sh"; return 0; }
    done
    return 1
}

if [ "$trusted" -eq 0 ]; then
    if tunnel_up; then
        log "rete non fidata ($what su $IFACE): tunnel $WG_PROFILE gia' attivo"
        exit 0
    fi
    log "rete non fidata ($what su $IFACE): alzo la VPN"
    if [ "$PROTON" = "1" ]; then
        if pu="$(find_proton_up)"; then
            "$pu" connect || log "ERRORE: proton_up fallito, resta scoperto"
        else
            log "ERRORE: proton_up.sh non trovato (cercato in /usr/share/zeroshield/scripts e accanto a questo script), resta scoperto"
        fi
    else
        wg-quick up "$WG_PROFILE" || log "ERRORE: tunnel non partito, resta scoperto"
    fi
else
    if [ "$AUTO_DOWN" = "1" ] && tunnel_up; then
        log "rete fidata ($what su $IFACE), AUTO_DOWN=1: tunnel $WG_PROFILE giu'"
        wg-quick down "$WG_PROFILE" 2>/dev/null || true
    else
        log "rete fidata ($what su $IFACE): VPN non richiesta (non la spengo da solo; AUTO_DOWN=1 per farlo)"
    fi
fi
exit 0
