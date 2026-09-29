#!/bin/bash
# Genera una chiave SSH FIDO2 residente (o ripiega su ED25519 software) e configura la firma dei commit Git.
set -euo pipefail

SK_KEY="$HOME/.ssh/id_ed25519_sk"
SW_KEY="$HOME/.ssh/id_ed25519"
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"

if [ ! -f "$SK_KEY" ] && [ ! -f "$SW_KEY" ]; then
    if command -v fido2-token >/dev/null && [ -n "$(fido2-token -L 2>/dev/null)" ]; then
        echo "🔑 Token FIDO2 rilevato: genero chiave ed25519-sk (PIN + tocco richiesti)"
        ssh-keygen -t ed25519-sk -O resident -O verify-required -f "$SK_KEY" -C "zt-shield-hardware-key"
    else
        echo "⚠️  Nessun token FIDO2: genero una chiave ED25519 software (usa una passphrase robusta)."
        echo "    Protezione più debole: il segreto è sul disco. Con zt-shield attivo resta protetto dalla regola 'ssh-keys'."
        ssh-keygen -t ed25519 -f "$SW_KEY" -C "zt-shield-software-key"
    fi
fi

KEY_PATH="$SK_KEY.pub"
[ -f "$KEY_PATH" ] || KEY_PATH="$SW_KEY.pub"

EMAIL="$(git config --global user.email || true)"
if [ -z "$EMAIL" ]; then
    echo "❌ Imposta prima: git config --global user.email <tua-email>"
    exit 1
fi

git config --global gpg.format ssh
git config --global user.signingkey "$KEY_PATH"
git config --global commit.gpgsign true

SIGNERS="$HOME/.ssh/allowed_signers"
LINE="$EMAIL $(cat "$KEY_PATH")"
touch "$SIGNERS"
grep -qxF "$LINE" "$SIGNERS" || echo "$LINE" >> "$SIGNERS"
git config --global gpg.ssh.allowedSignersFile "$SIGNERS"

echo "✅ Firma commit configurata con $KEY_PATH"
echo "ℹ️  Carica la chiave pubblica su GitHub/GitLab come 'Signing key' per vedere i commit 'Verified'."
