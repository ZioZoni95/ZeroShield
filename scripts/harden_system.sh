#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Hardening di sistema per profilo: firewall, resolver, sysctl di rete.
# Uso: sudo scripts/harden_system.sh [home|corporate|public-wifi|paranoid]
#
# Cosa fa, e cosa NON fa:
#   - chiude l'ingresso con ufw
#   - spegne LLMNR/mDNS in systemd-resolved, e nei profili ostili forza DNS cifrato
#   - irrigidisce i sysctl di rete (redirect, source route, martians)
#   - spegne avahi nelle reti non fidate
#
# Cosa non fa, e perche' conta:
#   - non cifra nulla. Tutto il traffico resta in chiaro: su una rete ostile serve
#     anche una VPN (WireGuard), come dice l'output finale di questo script.
#   - non protegge /home. Se la partizione non e' cifrata (LUKS), chi ha root legge
#     i tuoi segreti senza dover superare nessuna di queste regole. E' il controllo
#     con il rapporto protezione/costo piu' alto di tutta l'operazione, e richiede
#     reinstallazione o riformattazione, quindi non puo' essere fatto da qui.
set -euo pipefail

# Uso: harden_system.sh [profilo] [--dry-run]. Con --dry-run (o ZT_DRY_RUN=1) non tocca il
# sistema: lavora su copie temporanee dei file e mostra il diff di cio' che cambierebbe,
# e stampa i comandi (ufw, systemctl, sysctl) invece di eseguirli. Non serve root.
# Provalo SEMPRE prima della prima esecuzione vera.
DRY_RUN="${ZT_DRY_RUN:-0}"
PROFILE=""
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        home|corporate|public-wifi|paranoid) PROFILE="$arg" ;;
        *) echo "Uso: $0 [home|corporate|public-wifi|paranoid] [--dry-run]"; exit 1 ;;
    esac
done
# Validazione esplicita dell'argomento: senza, un refuso diventa un profilo
# silenzosamente sbagliato, e 'case' in bash non fallisce su un valore inatteso.
PROFILE="${PROFILE:-home}"
# Riesegui come root invece di fallire (non in dry-run: li' non si scrive nulla).
if [ "$DRY_RUN" != 1 ] && [ "$(id -u)" -ne 0 ]; then exec sudo "$0" "$@"; fi

# run: esegue il comando, oppure lo stampa in dry-run.
run() {
    if [ "$DRY_RUN" = 1 ]; then echo "   [dry-run] $*"; else "$@"; fi
}

echo "🧱 Profilo: $PROFILE$([ "$DRY_RUN" = 1 ] && echo " (DRY-RUN: nulla viene modificato)")"

# --- Firewall ---
# FIX applicato: `allow OpenSSH` PRIMA di `enable`. Senza, default deny incoming
# nega l'SSH in ingresso e il lockout si vede alla connessione successiva.
# Senza listener SSH la regola allow e' innocua. Verifica SEMPRE con una seconda
# sessione prima di chiudere la prima.
# ssh_ports: porte TCP su cui sshd ASCOLTA davvero (non assume il 22 ne' il profilo
# "OpenSSH", che non esiste se openssh-server non e' installato: con set -e un
# `ufw allow OpenSSH` fallito abortiva l'intero hardening).
ssh_ports() {
    ss -Hltnp 2>/dev/null | awk '/"sshd"/ { n = split($4, a, ":"); print a[n] }' | sort -un
}
if command -v ufw >/dev/null; then
    run ufw default deny incoming
    run ufw default allow outgoing
    ports="$(ssh_ports)"
    if [ -n "$ports" ]; then
        for p in $ports; do run ufw allow "$p/tcp"; done
    else
        echo "ℹ️  sshd non in ascolto: nessuna regola SSH in ingresso."
    fi
    # Log ridotto nelle reti ostili: la LAN puo' generare volumi di log e riempire /var.
    case "$PROFILE" in public-wifi|paranoid) run ufw logging low ;; esac
    run ufw --force enable
else
    echo "⚠️  ufw non installato, salto il firewall"
fi

# --- systemd-resolved: niente LLMNR/mDNS; DNS cifrato dove ha senso ---
RESOLVED_CONF="${ZT_RESOLVED_CONF:-/etc/systemd/resolved.conf}"
RESOLVED_REAL="$RESOLVED_CONF"
if [ "$DRY_RUN" = 1 ] && [ -f "$RESOLVED_CONF" ]; then
    # In dry-run si modifica una copia e alla fine se ne mostra il diff.
    RESOLVED_CONF="$(mktemp)"
    cp "$RESOLVED_REAL" "$RESOLVED_CONF"
fi
# set_resolved chiave valore: imposta una chiave in modo idempotente.
# Se esiste gia' (commentata o no) la sostituisce, altrimenti la inserisce subito
# dopo [Resolve]. Senza questo controllo, rieseguire lo script duplicerebbe le chiavi.
set_resolved() {
    if grep -qE "^#?$1=" "$RESOLVED_CONF"; then
        sed -i -E "s|^#?$1=.*|$1=$2|" "$RESOLVED_CONF"
    elif grep -q "^\[Resolve\]" "$RESOLVED_CONF"; then
        sed -i "/^\[Resolve\]/a $1=$2" "$RESOLVED_CONF"
    else
        # FIX: prima se mancava la sezione [Resolve] la chiave andava persa in
        # silenzio. Ora si crea la sezione in coda e si avvisa nel log.
        printf '\n[Resolve]\n%s=%s\n' "$1" "$2" >> "$RESOLVED_CONF"
        echo "⚠️  sezione [Resolve] assente, creata in coda a $RESOLVED_CONF"
    fi
}
if [ -f "$RESOLVED_CONF" ]; then
    # Backup una tantum: -n non sovrascrive, quindi il backup originale sopravvive
    # alle riesecuzioni. Non sovrascrivere MAI resolved.conf qui sopra: se lo fai,
    # perdi il file di fabbrica e con esso i default commentati che spiegano le opzioni.
    [ "$DRY_RUN" = 1 ] || cp -n "$RESOLVED_CONF" "$RESOLVED_CONF.zt-backup"
    # LLMNR e mDNS sono i vettori di Responder/Inveigh. spenti in resolved, ma il
    # programma XDP li blocca anche a livello driver: difesa a due livelli.
    set_resolved LLMNR no
    set_resolved MulticastDNS no
    case "$PROFILE" in
        public-wifi|paranoid)
            # Ignora i DNS forniti dal DHCP della rete ostile e usa resolver pubblici
            # cifrati. Il rischio che copre: un DNS aziendale compromesso avvelena la
            # risoluzione dei nomi dei repository interni.
            # Il costo: i nomi interni smettono di risolversi. Su una rete aziendale
            # questo profilo e' la scelta sbagliata, anche se il profilo si chiama public-wifi.
            set_resolved DNS "1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net"
            # ~. = escludi i domini aziendali da questi resolver, per non mandare
            # query interne a Cloudflare. Senso inverso, serve in ambienti misti.
            set_resolved Domains "~."
            set_resolved DNSSEC allow-downgrade
            # paranoid esige DoT; opportunistic sugli altri profili puo' ripiegare in
            # chiaro, il che e' comunque meglio di mandare tutto al DNS del DHCP.
            [ "$PROFILE" = "paranoid" ] && set_resolved DNSOverTLS yes || set_resolved DNSOverTLS opportunistic
            ;;
        *)
            echo "ℹ️  DNS di rete mantenuti (profilo $PROFILE): DoT non forzato per non rompere i nomi interni."
            ;;
    esac
    # FIX: con set -e, un resolver non gestito da systemd faceva abortire lo
    # script qui, prima di sysctl/avahi. Ora tollerante con avviso.
    if [ "$DRY_RUN" = 1 ]; then
        echo "--- diff $RESOLVED_REAL ---"
        diff -u "$RESOLVED_REAL" "$RESOLVED_CONF" || true
        rm -f "$RESOLVED_CONF"
        run systemctl restart systemd-resolved
    else
        systemctl restart systemd-resolved || echo "⚠️  restart systemd-resolved fallito, continuo"
    fi
fi

# --- sysctl di rete ---
# File in /etc/sysctl.d con suffisso 99, cosi' viene applicato per ultimo e sovrascrive
# eventuali default di /etc/sysctl.conf. `sysctl --system` rilegge tutti i file.
SYSCTL_FILE="${ZT_SYSCTL_FILE:-/etc/sysctl.d/99-zt-shield.conf}"
SYSCTL_REAL="$SYSCTL_FILE"
[ "$DRY_RUN" = 1 ] && SYSCTL_FILE="$(mktemp)"
{
    echo "# Generato da zt-shield harden_system.sh (profilo: $PROFILE)"
    cat << 'CONF'
# Redirect ICMP: rifiutati perche' un attaccante puo' redirigere il traffico
# attraverso una macchina sospetta e osservarlo in chiaro.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
# Source routing: obsoleto e mai legittimo, accettarlo permette di scegliere
# un percorso arbitrario e raggiungere host che non dovrebbero essere raggiungibili.
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
# ICMP echo a broadcast: base degli amplification attack, da cui ti prendono.
net.ipv4.icmp_echo_ignore_broadcasts = 1
# rp_filter = 2 (loose): scarta i pacchetti con sorgente non raggiungibile
# tramite l'interfaccia su cui arrivano. Ferma il doppio spoofing.
net.ipv4.conf.all.rp_filter = 2
# log_martians: logga i pacchetti con header incoerenti, utili per capire
# che qualcuno sta provando cose strane sulla rete.
net.ipv4.conf.all.log_martians = 1
CONF
    case "$PROFILE" in public-wifi|paranoid)
        # arp_ignore/arp_announce: limita le risposte ARP alle richieste per gli
        # indirizzi locali, riducendo l'esposizione della tabella ARP agli host
        # discovery e alle poisoning di risposte ARP.
        echo "net.ipv4.conf.all.arp_ignore = 1"
        echo "net.ipv4.conf.all.arp_announce = 2"
        ;;
    esac
} > "$SYSCTL_FILE"
# FIX: `sysctl --system` nascondeva l'output ma con set -e una chiave ignota
# abortiva tutto. Ora mostra gli errori e non blocca il resto.
if [ "$DRY_RUN" = 1 ]; then
    echo "--- $SYSCTL_REAL (nuovo contenuto) ---"
    cat "$SYSCTL_FILE"
    rm -f "$SYSCTL_FILE"
    run sysctl --system
else
    sysctl --system || echo "⚠️  sysctl --system con errori (vedi sopra), continuo"
fi

# --- Servizi di discovery su LAN ostili ---
# avahi implementa mDNS e NBT-NS: se resta attivo, continua a emettere e ad
# accettare traffico di discovery che questo progetto prova a bloccare.
case "$PROFILE" in public-wifi|paranoid)
    # is-enabled fallisce se il servizio non esiste: in quel caso si salta.
    if systemctl is-enabled avahi-daemon >/dev/null 2>&1; then
        run systemctl disable --now avahi-daemon.service avahi-daemon.socket
        echo "🔇 avahi-daemon disabilitato"
    fi
    ;;
esac

# Promemoria finale deliberato: tutto questo e' filtraggio e occultamento del traffico.
# Non e' cifratura, e su una rete controllata dall'attaccante non e' un confine.
[ "$DRY_RUN" = 1 ] && { echo "✅ Dry-run completato: nessuna modifica fatta. Rilancia senza --dry-run per applicare."; exit 0; }
echo "✅ Hardening applicato. Su reti non fidate usa anche una VPN (WireGuard): questi controlli non cifrano il traffico."
