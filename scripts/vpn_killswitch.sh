#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# VPN kill-switch via nftables (vedi docs/VPN_SETUP.md).
#
# Uso: sudo vpn_killswitch.sh on <endpoint> <tunnel-if> [lan-cidr...]
#      sudo vpn_killswitch.sh off
#      sudo vpn_killswitch.sh status
#      sudo vpn_killswitch.sh portal [interfaccia] [secondi]
#
# <endpoint>  IPv4:porta oppure [IPv6]:porta (mai un nome host: senza tunnel non c'e' DNS)
#
# Con 'on' esce SOLO: tunnel, endpoint VPN, DHCP (a meno di BLOCK_DHCP=1), loopback e
# le LAN passate come argomento. Tutto il resto DROP + log. Se il tunnel cade, niente
# esce: meglio offline che in chiaro.
#
# Principio di progetto: lo script crea e cancella UNA tabella, "inet zt-killswitch", e
# non tocca mai nient'altro. Niente backup del ruleset, niente `flush ruleset`: un
# rollback che ricarica un backup puo' lasciare la macchina senza firewall (se il
# ricaricamento fallisce) o caricare come root un file scritto da altri (se il backup
# sta in /tmp). Tolta la tabella, il resto del firewall e' esattamente com'era.
set -euo pipefail

TABLE="zt-killswitch"
PORTAL_DEFAULT=300
PORTAL_MIN=5
PORTAL_MAX=900

die() { echo "❌ $*" >&2; exit 1; }
usage() {
    cat >&2 <<'USAGE'
Uso: sudo vpn_killswitch.sh on <IPv4:porta | [IPv6]:porta> <tunnel-if> [lan-cidr...]
     sudo vpn_killswitch.sh off
     sudo vpn_killswitch.sh status
     sudo vpn_killswitch.sh portal [interfaccia] [secondi]
USAGE
    exit 1
}

[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
command -v nft >/dev/null || die "nftables mancante: sudo apt install nftables"

# --- Validazione --------------------------------------------------------------------
# Tutto cio' che finisce nel ruleset passa di qui PRIMA di costruirlo. Il ruleset e'
# poi controllato da nft stesso (-c) prima di essere applicato: due barriere.

valid_ipv4() {
    local ip="$1" o
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -ra octets <<<"$ip"
    for o in "${octets[@]}"; do
        # 10# forza la base 10: "08" non e' ottale non valido.
        [ "$((10#$o))" -le 255 ] || return 1
    done
}
valid_ipv6() { [[ "$1" =~ ^[0-9A-Fa-f:.]+$ && "$1" == *:* ]]; }
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$((10#$1))" -ge 1 ] && [ "$((10#$1))" -le 65535 ]; }
valid_iface() { [[ "$1" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; }
valid_cidr() {
    local addr="${1%/*}" len="${1#*/}"
    [ "$addr" != "$1" ] && [[ "$len" =~ ^[0-9]{1,3}$ ]] || return 1
    if valid_ipv4 "$addr"; then [ "$((10#$len))" -le 32 ]
    elif valid_ipv6 "$addr"; then [ "$((10#$len))" -le 128 ]
    else return 1; fi
}

# Famiglia nft per un indirizzo gia' validato: "ip" o "ip6".
family() { if valid_ipv4 "$1"; then echo ip; else echo ip6; fi; }

# --- Ruleset ------------------------------------------------------------------------
# Un unico file: "add table" + "delete table" + "table ...". nft lo applica come UNA
# transazione, quindi la vecchia tabella viene sostituita in modo atomico: se qualcosa
# non va, non cambia niente (prima la tabella veniva cancellata e POI applicata la
# nuova: un errore lasciava la macchina senza kill-switch).
render_ruleset() {
    local ep_ip="$1" ep_port="$2" tun="$3"; shift 3
    local fam; fam="$(family "$ep_ip")"
    echo "add table inet $TABLE"
    echo "delete table inet $TABLE"
    echo "table inet $TABLE {"
    # Interfacce con il login-captive-portal aperto, ognuna con la sua scadenza:
    # la chiude il kernel, senza processi di appoggio che possano morire.
    echo "  set portal_ifaces { type ifname; flags timeout; }"
    echo "  chain out { type filter hook output priority 0; policy drop;"
    echo "    oifname \"lo\" accept"
    echo "    oifname \"$tun\" accept"
    echo "    $fam daddr $ep_ip udp dport $ep_port accept"
    echo "    $fam daddr $ep_ip tcp dport $ep_port accept"
    if [ "${BLOCK_DHCP:-0}" != "1" ]; then
        echo "    udp sport 68 udp dport 67 accept"
    fi
    echo "    oifname @portal_ifaces tcp dport { 80, 443 } accept"
    echo "    oifname @portal_ifaces udp dport 53 accept"
    echo "    oifname @portal_ifaces tcp dport 53 accept"
    local cidr
    for cidr in "$@"; do
        echo "    $(family "${cidr%/*}") daddr $cidr accept"
    done
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
}

table_exists() { nft list table inet "$TABLE" >/dev/null 2>&1; }

cmd_on() {
    [ $# -ge 2 ] || usage
    local endpoint="$1" tun="$2"; shift 2
    local ep_ip ep_port
    if [[ "$endpoint" == \[*\]:* ]]; then
        ep_ip="${endpoint#\[}"; ep_ip="${ep_ip%%\]*}"; ep_port="${endpoint##*\]:}"
        valid_ipv6 "$ep_ip" || die "endpoint IPv6 non valido: $endpoint (es. [2001:db8::1]:51820)"
    else
        ep_ip="${endpoint%:*}"; ep_port="${endpoint##*:}"
        # shellcheck disable=SC2015  # A && B || die: se A o B falliscono si muore, voluto
        [ "$ep_ip" != "$endpoint" ] && valid_ipv4 "$ep_ip" \
            || die "endpoint non valido: $endpoint (serve IPv4:porta o [IPv6]:porta, mai un nome host)"
    fi
    valid_port "$ep_port" || die "porta non valida: $ep_port (1-65535)"
    ep_port="$((10#$ep_port))"
    valid_iface "$tun" || die "nome interfaccia non valido: $tun"
    ip link show "$tun" >/dev/null 2>&1 \
        || die "interfaccia $tun assente: alza prima il tunnel (wg-quick up)"
    local cidr
    for cidr in "$@"; do valid_cidr "$cidr" || die "CIDR non valido: $cidr"; done

    # Controllo preventivo: nft verifica sintassi e semantica senza applicare nulla.
    render_ruleset "$ep_ip" "$ep_port" "$tun" "$@" | nft -c -f - \
        || die "il ruleset non e' valido per nft: niente applicato, kill-switch invariato"
    render_ruleset "$ep_ip" "$ep_port" "$tun" "$@" | nft -f - \
        || die "applicazione fallita: kill-switch invariato"
    echo "✅ Kill-switch attivo: solo $tun + $ep_ip:$ep_port escono."
    echo "   Verifica leak: dal gateway, tcpdump deve restare muto 60 s."
}

cmd_off() {
    if table_exists; then
        nft delete table inet "$TABLE"
        echo "✅ Kill-switch disattivato (tolta solo la tabella $TABLE, il resto del firewall non e' stato toccato)."
    else
        echo "ℹ️  Nessun kill-switch attivo."
    fi
}

cmd_status() {
    if table_exists; then
        echo "🔒 Kill-switch ATTIVO"
        nft list set inet "$TABLE" portal_ifaces 2>/dev/null | grep -E "elements|timeout" || true
    else
        echo "🔓 Kill-switch NON attivo"
        exit 3
    fi
}

# Captive portal: apre per N secondi SOLO web (80/443) e DNS sull'interfaccia fisica.
# Scade da solo nel kernel (timeout dell'elemento nel set): niente da ricordarsi di
# richiudere, e se questo script o la sessione muoiono, si chiude lo stesso.
cmd_portal() {
    table_exists || die "kill-switch non attivo: niente da aprire (usa 'on' prima)"
    local iface="${1:-}" secs="${2:-$PORTAL_DEFAULT}"
    if [ -z "$iface" ]; then
        # La rotta di default fisica (wg-quick tiene il tunnel su una tabella a parte).
        iface="$(ip -o route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')"
        [ -n "$iface" ] || die "interfaccia non rilevata: indicala, es. 'portal wlan0'"
    fi
    valid_iface "$iface" || die "nome interfaccia non valido: $iface"
    # shellcheck disable=SC2015  # A && B || die: se A o B falliscono si muore, voluto
    [[ "$secs" =~ ^[0-9]{1,4}$ ]] && [ "$((10#$secs))" -ge "$PORTAL_MIN" ] && [ "$((10#$secs))" -le "$PORTAL_MAX" ] \
        || die "secondi non validi: $secs (tra $PORTAL_MIN e $PORTAL_MAX)"
    secs="$((10#$secs))"
    nft add element inet "$TABLE" portal_ifaces "{ \"$iface\" timeout ${secs}s }"
    echo "⚠️  Portal aperto su $iface per ${secs}s: solo web (80/443) e DNS. Poi si richiude da solo."
}

CMD="${1:-}"
[ $# -gt 0 ] && shift
case "$CMD" in
    on) cmd_on "$@" ;;
    off) cmd_off ;;
    status) cmd_status ;;
    portal) cmd_portal "$@" ;;
    *) usage ;;
esac
