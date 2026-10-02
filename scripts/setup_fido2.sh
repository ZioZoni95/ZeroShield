#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Genera una chiave SSH FIDO2 residente (o ripiega su ED25519 software) e configura la firma dei commit Git.
#
# Questo e' l'unico livello di protezione di zt-shield che regge davvero a una
# compromissione di root: la chiave privata sta sul token e non esce mai, quindi
# un attaccante con accesso completo al filesystem non puo' firmare commit a tuo nome.
# Tutto il resto (XDP, LSM) un attaccante con root lo può staccare: vedi README.
set -euo pipefail

SK_KEY="$HOME/.ssh/id_ed25519_sk"
SW_KEY="$HOME/.ssh/id_ed25519"
# 700: la directory non deve essere leggibile da altri utenti, altrimenti i permessi
# sui singoli file non proteggono piu' nulla (ssh lo segnala e rifiuta la chiave).
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"

# Genera solo se non esiste gia' niente: sovrascrivere una chiave esistente la
# distruggerebbe, insieme a tutti gli host authorized_keys che la contengono.
if [ ! -f "$SK_KEY" ] && [ ! -f "$SW_KEY" ]; then
    # -L elenca i token collegati. Se l'hardware c'e' ma e' bloccato o ha il PIN
    # sbagliato, l'elenco e' comunque popolato e la generazione fallisce: in quel
    # caso non si ripiega sul software, perche' la chiave hardware va risolta.
    if command -v fido2-token >/dev/null && [ -n "$(fido2-token -L 2>/dev/null)" ]; then
        echo "🔑 Token FIDO2 rilevato: genero chiave ed25519-sk (PIN + tocco richiesti)"
        # resident      = la chiave resta nel token e si richiama per nome (ssh ne ha bisogno).
        # verify-required = PIN + tocco fisico a ogni operazione.
        #
        # NOTA: resident + verify-required e' la combinazione piu' scomoda possibile:
        # chiede PIN e tocco a ogni singolo commit. Dopo due settimane lo disattivi
        # (genera con -O verify=-1, il default: tocco fisico comunque obbligatorio).
        ssh-keygen -t ed25519-sk -O resident -O verify-required -f "$SK_KEY" -C "zt-shield-hardware-key"
    else
        echo "⚠️  Nessun token FIDO2: genero una chiave ED25519 software (usa una passphrase robusta)."
        echo "    Protezione più debole: il segreto è sul disco. Con zt-shield attivo resta protetto dalla regola 'ssh-keys'."
        # Attenzione: con una chiave software la passphrase e' l'unica barriera.
        # Se e' vuota, la chiave e' leggibile da qualunque processo del tuo utente,
        # inclusa la regola 'ssh-keys' di zt-shield che la protegge solo finche' l'hook e' attivo.
        ssh-keygen -t ed25519 -f "$SW_KEY" -C "zt-shield-software-key"
    fi
fi

# Chiave pubblica da usare per la firma: la sk se esiste, altrimenti la software.
KEY_PATH="$SK_KEY.pub"
[ -f "$KEY_PATH" ] || KEY_PATH="$SW_KEY.pub"

# Serve l'email per comporre la riga di allowed_signers: il formato e'
# "<email> <chiave pubblica>". Senza email non c'e' modo di firmare.
EMAIL="$(git config --global user.email || true)"
if [ -z "$EMAIL" ]; then
    echo "❌ Imposta prima: git config --global user.email <tua-email>"
    exit 1
fi

# --- Firma dei commit via chiave SSH ---
# gpg.format ssh: git usa il backend OpenSSH invece di gpg(1). Non richiede
# agent gpg e funziona con chiavi FIDO2, che gpg non sa usare.
git config --global gpg.format ssh
git config --global user.signingkey "$KEY_PATH"
# Obbligatorio: senza questo, firmare e' facoltativo e basta non passare -S.
git config --global commit.gpgsign true

# --- allowed_signers: chi puo' firmare come te ---
# Necessario per `git log --show-signature` e `git verify-commit` a mostrare
# "Good signature" invece di "No signature". Non serve per firmare.
SIGNERS="$HOME/.ssh/allowed_signers"
LINE="$EMAIL $(cat "$KEY_PATH")"
touch "$SIGNERS"
# grep -qxF: la riga deve esistere ESATTAMENTE, per non duplicarla a ogni esecuzione.
grep -qxF "$LINE" "$SIGNERS" || echo "$LINE" >> "$SIGNERS"
git config --global gpg.ssh.allowedSignersFile "$SIGNERS"

# Permessi: git si rifiuta di usare un allowed_signers leggibile da altri.
chmod 600 "$SIGNERS"

echo "✅ Firma commit configurata con $KEY_PATH"
echo "ℹ️  Carica la chiave pubblica su GitHub/GitLab come 'Signing key' per vedere i commit 'Verified'."

# Promemoria: la firma crittografica prova che la chiave era nel token, non che
# il codice fosse corretto. Un commit firmato resta un vettore di supply chain:
# verificare sempre la provenienza prima di eseguire.
echo "ℹ️  La firma prova la presenza del token, non la correttezza del codice. Verifica la provenienza prima di eseguire."
