#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Configura e avvia il servizio zt-shield installato dal pacchetto .deb.
# Uso: sudo configure_service.sh <utente-da-proteggere> [profilo]
#
# Differenza da install_service.sh (che e' per chi compila dai sorgenti): questo script
# NON copia binari e NON scrive la unit systemd, usa quelli del pacchetto. Scrive soltanto
# user: e profile: nel config (con una copia di sicurezza) e avvia il servizio.
# Il primo avvio e' SEMPRE in audit: logga senza bloccare nulla.
set -euo pipefail

TARGET_USER="${1:-${SUDO_USER:-}}"
PROFILE="${2:-home}"
CONFIG=/etc/zt-shield/shield.yaml
UNIT=/usr/lib/systemd/system/zt-shield.service
BIN=/usr/sbin/zt-shield
DROPIN_DIR=/etc/systemd/system/zt-shield.service.d
SYSTEMCTL=systemctl
TESTMODE=""

# Percorsi e comandi finti SOLO per i test e SOLO da non-root: come root queste variabili
# non hanno nessun effetto (chi lancia sudo/pkexec non puo' dirottare dove scrive root).
if [ "$(id -u)" -ne 0 ] && [ -n "${ZT_TEST_DIR:-}" ]; then
    TESTMODE=1
    CONFIG="$ZT_TEST_DIR/shield.yaml"
    UNIT="$ZT_TEST_DIR/zt-shield.service"
    BIN="$ZT_TEST_DIR/zt-shield"
    DROPIN_DIR="$ZT_TEST_DIR/dropin"
    SYSTEMCTL="${ZT_TEST_SYSTEMCTL:-systemctl}"
fi

[ -n "$TARGET_USER" ] || { echo "Uso: sudo $0 <utente> [profilo]"; exit 1; }
case "$PROFILE" in
    home | corporate | public-wifi | paranoid) ;;
    *) echo "❌ Profilo non valido: $PROFILE (usa home, corporate, public-wifi o paranoid)"; exit 1 ;;
esac
[[ "$TARGET_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || { echo "❌ Nome utente non valido: $TARGET_USER"; exit 1; }
[ "$TARGET_USER" != root ] || { echo "❌ L'utente da proteggere non puo' essere root"; exit 1; }

if [ -z "$TESTMODE" ]; then
    [ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
    id -u "$TARGET_USER" > /dev/null 2>&1 || { echo "❌ L'utente '$TARGET_USER' non esiste"; exit 1; }
fi
[ -f "$UNIT" ] || {
    echo "❌ $UNIT non trovato: il servizio non e' stato installato da un pacchetto."
    echo "   Se hai compilato dai sorgenti usa: sudo scripts/install_service.sh $TARGET_USER $PROFILE"
    exit 1
}

install -d -m 0755 "$(dirname "$CONFIG")"
if [ -f "$CONFIG" ]; then
    cp -p "$CONFIG" "$CONFIG.bak-$(date +%Y%m%d%H%M%S)"
else
    : > "$CONFIG"
fi
# Il file deve finire con un a-capo, altrimenti la riga aggiunta si attacca all'ultima.
if [ -s "$CONFIG" ] && [ -n "$(tail -c1 "$CONFIG")" ]; then echo >> "$CONFIG"; fi

# Sostituisce la riga attiva "chiave:" (non quelle commentate) oppure la aggiunge in fondo.
# Valori gia' validati sopra: niente caratteri speciali per sed.
set_key() {
    if grep -qE "^$1:" "$CONFIG"; then
        sed -i -E "s|^$1:.*|$1: $2|" "$CONFIG"
    else
        printf '%s: %s\n' "$1" "$2" >> "$CONFIG"
    fi
}
set_key profile "$PROFILE"
set_key user "$TARGET_USER"
# Primo avvio in audit anche con profili che di default sarebbero enforce.
if ! grep -qE '^mode:' "$CONFIG"; then
    printf '# primo avvio: audit (logga senza bloccare). Passa a enforce a log puliti.\nmode: audit\n' >> "$CONFIG"
fi
chmod 0644 "$CONFIG"
echo "📝 Aggiornato $CONFIG (profilo $PROFILE, utente $TARGET_USER)"

# Canary: sotto ProtectHome=read-only le esche non si possono creare. Se il canary e' attivo
# nel config, il demone genera il drop-in con le sole cartelle necessarie.
DROPIN=""
[ -x "$BIN" ] && DROPIN="$("$BIN" -config "$CONFIG" dropin 2> /dev/null || true)"
if [ -n "$DROPIN" ]; then
    install -d -m 0755 "$DROPIN_DIR"
    printf '%s\n' "$DROPIN" > "$DROPIN_DIR/canary.conf"
    chmod 0644 "$DROPIN_DIR/canary.conf"
    echo "🐤 Drop-in canary: $DROPIN_DIR/canary.conf"
else
    rm -f "$DROPIN_DIR/canary.conf"
fi

"$SYSTEMCTL" daemon-reload
if ! "$SYSTEMCTL" enable --now zt-shield; then
    echo "❌ Il servizio non e' partito. Il config e' stato comunque aggiornato."
    echo "   Causa piu' comune: 'bpf' assente tra gli LSM del kernel (cat /sys/kernel/security/lsm)."
    echo "   Dettagli: journalctl -u zt-shield -n 30"
    exit 1
fi
echo "✅ Servizio attivo in audit. Log: journalctl -u zt-shield -f"
echo "ℹ️  Passa a enforce solo quando in Eventi non compaiono piu' accessi legittimi."
