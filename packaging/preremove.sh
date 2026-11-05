#!/bin/sh
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Ferma il demone prima di togliere i file: gli hook si staccano con lui.
# Solo su rimozione ($1 = remove): su aggiornamento ($1 = upgrade) il servizio
# resta abilitato e dpkg sostituisce il binario sotto un demone ancora attivo.
set -e
if [ "${1:-remove}" = "remove" ] && [ -d /run/systemd/system ]; then
    systemctl disable --now zt-shield >/dev/null 2>&1 || true
    # Icona di stato: via dall'avvio di tutti e ferma nelle sessioni aperte.
    systemctl --global disable zeroshield-tray.service >/dev/null 2>&1 || true
    for uid in $(loginctl list-users --no-legend 2>/dev/null | awk '{print $1}'); do
        systemctl --user --machine="${uid}@.host" stop zeroshield-tray.service >/dev/null 2>&1 || true
    done
fi
