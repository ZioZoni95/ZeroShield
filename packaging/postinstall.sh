#!/bin/sh
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Prima installazione: non abilita ne' avvia il servizio, perche' senza `user:` nel config
# (e senza `bpf` tra gli LSM attivi) il demone si fermerebbe (fail-closed): lo fa l'utente con
# configure_service.sh o dalla GUI. Se invece il config ha gia' `user:` (aggiornamento di un
# sistema configurato) il demone viene abilitato all'avvio e, se gira, riavviato col binario nuovo.
set -e
# Solo se systemd e' l'init (non in container/chroot): niente errori spuri.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # Icona di stato: abilitata per tutti gli utenti (symlink in /usr/lib/systemd/user/...wants).
    systemctl --global enable zeroshield-tray.service >/dev/null 2>&1 || true
    # Demone: solo se l'amministratore l'ha gia' configurato (riga `user:` non commentata e non vuota).
    if grep -Eq '^user:[[:space:]]*[^[:space:]#]' /etc/zt-shield/shield.yaml 2>/dev/null; then
        systemctl enable zt-shield.service >/dev/null 2>&1 || true
        systemctl try-restart zt-shield.service >/dev/null 2>&1 || true
    fi
    # Chi ha gia' una sessione grafica aperta la ottiene subito; chi aveva la versione vecchia la
    # vede riavviata con il binario nuovo (un processo gia' in corso userebbe ancora il vecchio).
    # Best effort: niente deve far fallire l'installazione.
    for uid in $(loginctl list-users --no-legend 2>/dev/null | awk '{print $1}'); do
        if systemctl --user --machine="${uid}@.host" is-active --quiet graphical-session.target 2>/dev/null; then
            systemctl --user --machine="${uid}@.host" restart zeroshield-tray.service >/dev/null 2>&1 || true
        fi
    done
fi
cat <<'MSG'
ZeroShield installato (NON avviato).

  1. Verifica il kernel:              sudo zt-probe -xdp-lo
     e che /sys/kernel/security/lsm contenga "bpf"
  2. Imposta l'utente e avvia in audit (un solo comando):
       sudo /usr/share/zeroshield/scripts/configure_service.sh $USER home
     oppure dalla GUI (zt-gui): «Installa e attiva».
     A mano: sudoedit /etc/zt-shield/shield.yaml (user: ...) e sudo systemctl enable --now zt-shield
  3. Log / interfaccia:               journalctl -u zt-shield -f   |   zt-tui   |   zt-gui (menu applicazioni)
  4. Icona di stato nella barra:       servizio utente, parte con la sessione (GNOME: serve gnome-shell-extension-appindicator)

VPN (facoltativa, provala prima in VM): /usr/share/doc/zeroshield/VPN_SETUP.md
  script in /usr/share/zeroshield/scripts/ (vpn_killswitch.sh, nm_vpn.sh, proton_*.sh)

Progetto sperimentale: leggi /usr/share/doc/zeroshield/TEST_SANDBOX.md
MSG
