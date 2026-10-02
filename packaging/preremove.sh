#!/bin/sh
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Ferma il demone prima di togliere i file: gli hook si staccano con lui.
# Solo su rimozione ($1 = remove): su aggiornamento ($1 = upgrade) il servizio
# resta abilitato e dpkg sostituisce il binario sotto un demone ancora attivo.
set -e
if [ "${1:-remove}" = "remove" ] && [ -d /run/systemd/system ]; then
    systemctl disable --now zt-shield >/dev/null 2>&1 || true
fi
