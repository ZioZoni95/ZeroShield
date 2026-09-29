#!/bin/bash
# Installa zt-shield come servizio systemd. Uso: sudo scripts/install_service.sh <utente-da-proteggere> [profilo]
set -euo pipefail

TARGET_USER="${1:-${SUDO_USER:-}}"
PROFILE="${2:-home}"
[ -n "$TARGET_USER" ] || { echo "Uso: sudo $0 <utente> [profilo]"; exit 1; }
[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
[ -x bin/zt-shield ] || { echo "❌ bin/zt-shield mancante: esegui 'make build'"; exit 1; }

install -o root -g root -m 0755 bin/zt-shield /usr/local/sbin/zt-shield
install -d -o root -g root -m 0755 /etc/zt-shield

if [ ! -f /etc/zt-shield/shield.yaml ]; then
    printf 'profile: %s\nuser: %s\n' "$PROFILE" "$TARGET_USER" > /etc/zt-shield/shield.yaml
    chmod 0644 /etc/zt-shield/shield.yaml
    echo "📝 Creato /etc/zt-shield/shield.yaml (vedi configs/shield.example.yaml per le opzioni)"
fi

cat > /etc/systemd/system/zt-shield.service << 'UNIT'
[Unit]
Description=Local Zero-Trust Shield (eBPF)
After=network-online.target

[Service]
ExecStart=/usr/local/sbin/zt-shield -config /etc/zt-shield/shield.yaml
Restart=on-failure
NoNewPrivileges=yes
ProtectHome=read-only
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now zt-shield
echo "✅ Servizio attivo. Log: journalctl -u zt-shield -f"
echo "ℹ️  Profilo '$PROFILE': se è 'home' parte in modalità audit (non blocca). Passa a 'mode: enforce' quando i log sono puliti."
