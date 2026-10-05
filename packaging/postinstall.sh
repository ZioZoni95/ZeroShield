#!/bin/sh
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Non abilita ne' avvia il servizio: senza `user:` nel config e senza `bpf` tra
# gli LSM attivi il demone si fermerebbe (fail-closed). Lo fa l'amministratore.
set -e
# Solo se systemd e' l'init (non in container/chroot): niente errori spuri.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
cat <<'MSG'
ZeroShield installato (NON avviato).

  1. Imposta l'utente da proteggere:  sudoedit /etc/zt-shield/shield.yaml   (user: ...)
  2. Verifica il kernel:              sudo zt-probe -xdp-lo
     e che /sys/kernel/security/lsm contenga "bpf"
  3. Avvia in audit:                  sudo systemctl enable --now zt-shield
  4. Log / interfaccia:               journalctl -u zt-shield -f   |   zt-tui

VPN (facoltativa, provala prima in VM): /usr/share/doc/zeroshield/VPN_SETUP.md
  script in /usr/share/zeroshield/scripts/ (vpn_killswitch.sh, nm_vpn.sh, proton_*.sh)

Progetto sperimentale: leggi /usr/share/doc/zeroshield/TEST_SANDBOX.md
MSG
