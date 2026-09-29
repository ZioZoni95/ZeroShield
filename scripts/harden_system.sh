#!/bin/bash
# Hardening di sistema per profilo: firewall, resolver, sysctl di rete.
# Uso: sudo scripts/harden_system.sh [home|corporate|public-wifi|paranoid]
set -euo pipefail

PROFILE="${1:-home}"
case "$PROFILE" in
    home|corporate|public-wifi|paranoid) ;;
    *) echo "Uso: $0 [home|corporate|public-wifi|paranoid]"; exit 1 ;;
esac
[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"

echo "🧱 Profilo: $PROFILE"

# --- Firewall ---
if command -v ufw >/dev/null; then
    ufw default deny incoming
    ufw default allow outgoing
    case "$PROFILE" in public-wifi|paranoid) ufw logging low ;; esac
    ufw --force enable
else
    echo "⚠️  ufw non installato, salto il firewall"
fi

# --- systemd-resolved: niente LLMNR/mDNS; DNS cifrato dove ha senso ---
RESOLVED_CONF="/etc/systemd/resolved.conf"
set_resolved() { # chiave valore (idempotente, sezione [Resolve])
    if grep -qE "^#?$1=" "$RESOLVED_CONF"; then
        sed -i -E "s|^#?$1=.*|$1=$2|" "$RESOLVED_CONF"
    else
        sed -i "/^\[Resolve\]/a $1=$2" "$RESOLVED_CONF"
    fi
}
if [ -f "$RESOLVED_CONF" ]; then
    cp -n "$RESOLVED_CONF" "$RESOLVED_CONF.zt-backup"
    set_resolved LLMNR no
    set_resolved MulticastDNS no
    case "$PROFILE" in
        public-wifi|paranoid)
            # Ignora i DNS forniti dalla rete (DHCP) e usa resolver cifrati globali.
            # Rompe i nomi interni e può richiedere il captive portal senza DoT (public-wifi = opportunistic).
            set_resolved DNS "1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net"
            set_resolved Domains "~."
            set_resolved DNSSEC allow-downgrade
            [ "$PROFILE" = "paranoid" ] && set_resolved DNSOverTLS yes || set_resolved DNSOverTLS opportunistic
            ;;
        *)
            echo "ℹ️  DNS di rete mantenuti (profilo $PROFILE): DoT non forzato per non rompere i nomi interni."
            ;;
    esac
    systemctl restart systemd-resolved
fi

# --- sysctl di rete ---
SYSCTL_FILE="/etc/sysctl.d/99-zt-shield.conf"
{
    echo "# Generato da zt-shield harden_system.sh (profilo: $PROFILE)"
    cat << 'CONF'
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.all.log_martians = 1
CONF
    case "$PROFILE" in public-wifi|paranoid)
        # Meno informazioni ARP verso reti ostili (host discovery/spoofing)
        echo "net.ipv4.conf.all.arp_ignore = 1"
        echo "net.ipv4.conf.all.arp_announce = 2"
        ;;
    esac
} > "$SYSCTL_FILE"
sysctl --system > /dev/null

# --- Servizi di discovery su LAN ostili ---
case "$PROFILE" in public-wifi|paranoid)
    if systemctl is-enabled avahi-daemon >/dev/null 2>&1; then
        systemctl disable --now avahi-daemon.service avahi-daemon.socket
        echo "🔇 avahi-daemon disabilitato"
    fi
    ;;
esac

echo "✅ Hardening applicato. Su reti non fidate usa anche una VPN (WireGuard): questi controlli non cifrano il traffico."
