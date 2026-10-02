#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Installa zt-shield come servizio systemd.
# Uso: sudo scripts/install_service.sh <utente-da-proteggere> [profilo]
#
# Prerequisiti: `make build` deve aver prodotto bin/zt-shield, e 'bpf' deve essere
# nella lista /sys/kernel/security/lsm, altrimenti il servizio entra in loop di
# fallimenti (vedi nota su StartLimitBurst qui sotto).
set -euo pipefail

# L'utente da proteggere: argomento, altrimenti chi ha lanciato sudo.
# Serve perche' sotto systemd non esiste SUDO_USER, e $HOME sarebbe /root.
TARGET_USER="${1:-${SUDO_USER:-}}"
PROFILE="${2:-home}"
[ -n "$TARGET_USER" ] || { echo "Uso: sudo $0 <utente> [profilo]"; exit 1; }
[ "$(id -u)" -eq 0 ] || exec sudo "$0" "$@"
# FIX: percorso repo risolto dallo script, non dalla cwd: prima falliva se
# lanciato fuori dalla root del repo.
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
[ -x "$SCRIPT_DIR/bin/zt-shield" ] || { echo "❌ $SCRIPT_DIR/bin/zt-shield mancante: esegui 'make build'"; exit 1; }

# Binario in /usr/local/sbin: non nella home dell'utente, perche' l'utente non deve
# poter sostituirlo (girerebbe con root).
install -o root -g root -m 0755 "$SCRIPT_DIR/bin/zt-shield" /usr/local/sbin/zt-shield
install -d -o root -g root -m 0755 /etc/zt-shield

# Configurazione: non si sovrascrive se esiste gia', per non perdere le regole
# scritte a mano. In quel caso si avvisa e si lascia decidere all'utente.
if [ ! -f /etc/zt-shield/shield.yaml ]; then
    printf 'profile: %s\nuser: %s\n' "$PROFILE" "$TARGET_USER" > /etc/zt-shield/shield.yaml
    # 0644: la config contiene nomi di regole e path, non segreti, e deve essere
    # leggibile dal demone che gira come root (che comunque legge tutto).
    chmod 0644 /etc/zt-shield/shield.yaml
    echo "📝 Creato /etc/zt-shield/shield.yaml (vedi configs/shield.example.yaml per le opzioni)"
else
    echo "ℹ️  /etc/zt-shield/shield.yaml esiste: lasciato inalterato."
fi

# Unit systemd. Delimitatore 'UNIT' quotato: niente espansione della shell, cosi'
# i $ di systemd restano intatti.
cat > /etc/systemd/system/zt-shield.service << 'UNIT'
[Unit]
Description=Local Zero-Trust Shield (eBPF)
After=network-online.target

# FIX: prima con Restart=on-failure e senza limiti, se AttachLSM falliva
# ('bpf' non in lista LSM) systemd riprovava 5 volte e moriva in silenzio,
# annullando il fail-closed proprio quando serviva. Ora: pochi tentativi
# ravvicinati, poi stop visibile + ExecStartPre con messaggio chiaro.
StartLimitBurst=3
StartLimitIntervalSec=60

# (Raccomandati ma non attivi: ProtectSystem=strict, CapabilityBoundingSet con
# CAP_BPF/CAP_NET_ADMIN/CAP_PERFMON. Testare in VM: rischiano di rompere il load.)

[Service]
# Fallisce subito con messaggio chiaro in journal se BPF LSM non e' attivo,
# invece di 5 crash criptici.
ExecStartPre=/bin/sh -c 'grep -qw bpf /sys/kernel/security/lsm || (echo "BPF LSM non attivo: aggiungi bpf alla lista lsm= e riavvia" >&2; exit 1)'
ExecStart=/usr/local/sbin/zt-shield -config /etc/zt-shield/shield.yaml
Restart=on-failure
# Watchdog: il demone pinga a ogni rescan; se hung oltre 30s, restart.
# (Niente pinning bpffs di proposito: hook orfani senza demone sarebbero
# protezione a metà. Vedi internal/watchdog.)
WatchdogSec=30
NotifyAccess=main

# --- Hardening della unit ---
# Il demone ha bisogno di root per caricare eBPF e agganciare XDP/LSM, quindi non
# puo' girare come utente. Queste direttive limitano comunque i danni.

# Nessun gain di privilegi via setuid/binary con bit di setuid. Il demone non ne ha bisogno.
NoNewPrivileges=yes

# La home e' leggibile ma non scrivibile. Serve perche' il demone deve leggere i
# file da proteggere (stat) e non ha motivo di scriverci.
# NON protegge i secret dalla lettura: la protezione la fa l'hook LSM, non systemd.
ProtectHome=read-only

# /tmp e /var/tmp privati, isolati dal namespace degli altri servizi.
PrivateTmp=yes

# NOTA: manca ProtectSystem=strict. Con questa, l'intero filesystem sarebbe
# montato in sola lettura per il processo, e /usr/local/sbin/zt-shield non
# potrebbe essere sostituito nemmeno da root. Ha un costo: i path di mount gia'
# presenti nel namespace systemd sono gia' read-only nel namespace del servizio,
# quindi va verificato che non serva di piu'.

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now zt-shield
echo "✅ Servizio attivo. Log: journalctl -u zt-shield -f"

# Promemoria operativo: in modalita' audit il servizio logga e non blocca.
# Passare a enforce solo dopo aver verificato che nei log non compaiono
# processi legittimi bloccati, altrimenti si blocca da soli kubectl e git.
echo "ℹ️  Profilo '$PROFILE': se è 'home' parte in modalità audit (non blocca). Passa a 'mode: enforce' quando i log sono puliti."

# Verifica utile subito dopo l'installazione: l'hook deve apparire nei programmi
# LSM caricati, altrimenti il servizio e' attivo ma non protegge niente.
echo "ℹ️  Verifica hook: sudo bpftool prog show | grep -i file_open"
