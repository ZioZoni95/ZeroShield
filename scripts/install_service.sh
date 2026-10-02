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
[ -x bin/zt-shield ] || { echo "❌ bin/zt-shield mancante: esegui 'make build'"; exit 1; }

# Binario in /usr/local/sbin: non nella home dell'utente, perche' l'utente non deve
# poter sostituirlo (girerebbe con root).
install -o root -g root -m 0755 bin/zt-shield /usr/local/sbin/zt-shield
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

# BUG: manca StartLimitBurst in [Unit]. Con Restart=on-failure, se AttachLSM
# fallisce (per esempio 'bpf' non e' nella lista LSM) il processo esce non-zero,
# systemd riprova, riprova, e dopo 5 tentativi si arrende DEFINITIVAMENTE.
# Risultato: il servizio e' morto e silenzioso, e il fail-closed di main.go
# (log.Fatal se l'hook non si aggancia) viene annullato proprio quando serviva.
# Fix: StartLimitBurst=3 in [Unit] e StartLimitIntervalSec=60.
#
# Fix ulteriore consigliato in [Service]:
#   ExecStartPre=/bin/sh -c 'grep -qw bpf /sys/kernel/security/lsm'
# Fallisce subito, con un messaggio chiaro in journalctl, invece di ripetere 5 volte.

[Service]
ExecStart=/usr/local/sbin/zt-shield -config /etc/zt-shield/shield.yaml
Restart=on-failure

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
