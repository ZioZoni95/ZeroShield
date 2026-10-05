#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Alza/abbassa ProtonVPN senza GUI (vedi docs/VPN_SETUP.md).
# Uso: scripts/proton_up.sh [connect [server]|disconnect|status]
# Strategia, in ordine:
#   1. protonvpn-cli ufficiale (stesso account della GUI, niente password
#      extra dopo il primo login). Installazione: pacchetto dal sito Proton
#      oppure pip; poi `protonvpn-cli login`.
#   2. Se manca: NON automatizza la GUI (click simulati = fragili e pericolosi).
#      Dice cosa fare e rimanda a proton_current.sh per leggere endpoint dopo.
# Non connette mai da solo senza credenziali già presenti: niente login
# interattivi dentro gli script (le password non girano nei log).
set -uo pipefail

CMD="${1:-connect}"
ARG="${2:-}"

have_cli() { command -v protonvpn-cli >/dev/null 2>&1; }

case "$CMD" in
    status)
        if have_cli; then exec protonvpn-cli status; fi
        if pgrep -f "proton\.vpn\.daemon" >/dev/null; then
            echo "ℹ️  Demone Proton attivo (GUI). Stato live: aprila o usa proton_current.sh dopo la connessione."
        else
            echo "ℹ️  Proton non attivo."
        fi
        ;;
    connect)
        if have_cli; then exec protonvpn-cli connect ${ARG:+--server "$ARG"}; fi
        if pgrep -f "proton\.vpn\.daemon" >/dev/null; then
            echo "❌ protonvpn-cli assente e GUI già in gestione."
            echo "   Installa la CLI (sito Proton) + 'protonvpn-cli login', poi rilancia."
            echo "   Alternativa ora: connettiti dalla GUI, poi 'bash scripts/proton_current.sh'."
            exit 2
        fi
        echo "❌ Né CLI né demone Proton trovati. Installa app o CLI dal sito Proton."
        exit 2
        ;;
    disconnect)
        if have_cli; then exec protonvpn-cli disconnect; fi
        echo "❌ protonvpn-cli assente: disconnetti dalla GUI."
        exit 2
        ;;
    *) echo "Uso: $0 [connect [server]|disconnect|status]"; exit 1 ;;
esac
