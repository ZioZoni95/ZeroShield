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

PROFILE="${1:-home}"
# Validazione esplicita dell'argomento: senza, un refuso diventa un profilo
# silenzosamente sbagliato, e 'case' in bash non fallisce su un valore inatteso.
case "$PROFILE" in
    home|corporate|public-wifi|paranoid) ;;
    *) echo "Uso: $0 [home|corporate|public-wifi|paranoid]"; exit 1 ;;
esac
# Riesegui come root invece di fallire: comodo, ma perche' accettare sudo qui e non
# in ogni altro script? Lo si fa per compatta'. Tutti i comandi sotto sono gia' root-only.
[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"

echo "🧱 Profilo: $PROFILE"

# --- Firewall ---
# BUG BLOCCANTE: manca `ufw allow OpenSSH` PRIMA di `ufw --force enable`.
# Con default deny incoming e nessuna regola allow, l'ingresso SSH viene negato.
# La sessione corrente sopravvive (catena stateful established/related), quindi
# sembra funzionare: il lockout si manifesta alla connessione successiva, spesso
# dopo un reboot o un cambio di rete, che e' il momento peggiore.
#
# Fix, da inserire prima dell'enable (e solo se si usa SSH):
#   ufw allow OpenSSH
# Poi verificare SEMPRE con una seconda sessione prima di chiudere la prima.
if command -v ufw >/dev/null; then
    ufw default deny incoming
    ufw default allow outgoing
    # Log ridotto nelle reti ostili: la LAN puo' generare volumi di log e riempire /var.
    case "$PROFILE" in public-wifi|paranoid) ufw logging low ;; esac
    ufw --force enable
else
    echo "⚠️  ufw non installato, salto il firewall"
fi

# --- systemd-resolved: niente LLMNR/mDNS; DNS cifrato dove ha senso ---
RESOLVED_CONF="/etc/systemd/resolved.conf"
# set_resolved chiave valore: imposta una chiave in modo idempotente.
# Se esiste gia' (commentata o no) la sostituisce, altrimenti la inserisce subito
# dopo [Resolve]. Senza questo controllo, rieseguire lo script duplicerebbe le chiavi.
set_resolved() {
    if grep -qE "^#?$1=" "$RESOLVED_CONF"; then
        sed -i -E "s|^#?$1=.*|$1=$2|" "$RESOLVED_CONF"
    else
        # Se il file non ha una sezione [Resolve], questa sed non inserisce nulla e
        # non lo segnala: la chiave semplicemente non viene applicata.
        sed -i "/^\[Resolve\]/a $1=$2" "$RESOLVED_CONF"
    fi
}
if [ -f "$RESOLVED_CONF" ]; then
    # Backup una tantum: -n non sovrascrive, quindi il backup originale sopravvive
    # alle riesecuzioni. Non sovrascrivere MAI resolved.conf qui sopra: se lo fai,
    # perdi il file di fabbrica e con esso i default commentati che spiegano le opzioni.
    cp -n "$RESOLVED_CONF" "$RESOLVED_CONF.zt-backup"
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
    systemctl restart systemd-resolved
fi

# --- sysctl di rete ---
# File in /etc/sysctl.d con suffisso 99, cosi' viene applicato per ultimo e sovrascrive
# eventuali default di /etc/sysctl.conf. `sysctl --system` rilegge tutti i file.
SYSCTL_FILE="/etc/sysctl.d/99-zt-shield.conf"
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
sysctl --system > /dev/null

# --- Servizi di discovery su LAN ostili ---
# avahi implementa mDNS e NBT-NS: se resta attivo, continua a emettere e ad
# accettare traffico di discovery che questo progetto prova a bloccare.
case "$PROFILE" in public-wifi|paranoid)
    # is-enabled fallisce se il servizio non esiste: in quel caso si salta.
    if systemctl is-enabled avahi-daemon >/dev/null 2>&1; then
        systemctl disable --now avahi-daemon.service avahi-daemon.socket
        echo "🔇 avahi-daemon disabilitato"
    fi
    ;;
esac

# Promemoria finale deliberato: tutto questo e' filtraggio e occultamento del traffico.
# Non e' cifratura, e su una rete controllata dall'attaccante non e' un confine.
echo "✅ Hardening applicato. Su reti non fidate usa anche una VPN (WireGuard): questi controlli non cifrano il traffico."
