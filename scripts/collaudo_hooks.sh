#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Collaudo degli hook LSM su file FINTI (docs/COLLAUDO_HARDENING.md, sezioni 1 e 2). Non usa
# privilegi e non tocca segreti veri: lavora in ~/zs-collaudo (o ZS_DIR).
# Uso: collaudo_hooks.sh prepara | prova [deny_write]
set -uo pipefail
D="${ZS_DIR:-$HOME/zs-collaudo}"
MV="$(readlink -f "$(command -v mv)")"
CAT="$(readlink -f "$(command -v cat)")"

# Ricrea i file e aspetta il rescan del demone (inode nuovi = mappe da aggiornare).
reset_files() {
    rm -f "$D"/n2 "$D"/n3 "$D"/a1.hard "$D"/a1.bak 2>/dev/null
    local f
    for f in a1 a2 b1 n1; do [ -e "$D/$f" ] || echo "segreto-$f" > "$D/$f"; done
    sleep 3
}

case "${1:-}" in
prepara)
    mkdir -p "$D"; reset_files
    echo "File finti in $D. Ora nella GUI → Regole → «Proteggi un mio file», due protezioni in Blocca:"
    echo "  zs-a : $D/a1 e $D/a2  — programma autorizzato: $MV"
    echo "  zs-b : $D/b1          — programma autorizzato: $CAT"
    echo "Poi: $0 prova"
    exit 0 ;;
prova) ;;
*) echo "Uso: $0 prepara | prova [deny_write]"; exit 1 ;;
esac

[ -e "$D/a1" ] || { echo "Prima lancia: $0 prepara"; exit 1; }
# a1 deve essere illeggibile per cat (autorizzato solo per zs-b), altrimenti ogni esito e' falso.
if "$CAT" "$D/a1" >/dev/null 2>&1; then
    echo "❌ Le regole di prova non sono attive (cat legge $D/a1): crea le protezioni in Blocca e riprova."
    exit 2
fi

FAIL=0
# t <passa|negato> <descrizione> <comando...>
t() {
    local want="$1" desc="$2" got=passa
    shift 2
    "$@" >/dev/null 2>&1 || got=negato
    if [ "$got" = "$want" ]; then echo "✅ $desc: $got"; else echo "❌ $desc: $got (atteso: $want)"; FAIL=1; fi
}
sh_() { bash -c "cd '$D' && $1"; }

if [ "${2:-}" = deny_write ]; then
    echo "== zs-a con deny_write"
    reset_files
    t negato "append da programma non autorizzato" sh_ 'echo x >> a1'
    t passa  "mv autorizzato (andata e ritorno)" sh_ "$MV a1 a1.bak && $MV a1.bak a1"
    t negato "open in scrittura da python" sh_ "python3 -c \"open('a1','w')\""
else
    echo "== rename"
    reset_files
    t passa  "mv autorizzato verso nome non protetto" sh_ "$MV a2 n2"
    t passa  "mv di ritorno" sh_ "$MV n2 a2"
    reset_files
    t negato "mv da zs-a sopra un file di zs-b" sh_ "$MV a2 b1"
    reset_files
    t negato "mv di file libero sopra zs-b" sh_ "$MV n1 b1"
    reset_files
    t passa  "cat autorizzato su zs-b" sh_ "$CAT b1"
    t negato "cat non autorizzato su zs-a" sh_ "$CAT a1"
    t negato "rename da python" sh_ "python3 -c \"import os; os.rename('a1','n3')\""
    echo "== modifiche senza deny_write"
    reset_files
    t passa  "append (consentito senza deny_write)" sh_ 'echo x >> a1'
    t negato "sovrascrittura (O_TRUNC)" sh_ 'echo x > a1'
    reset_files
    t negato "hard link" sh_ 'ln a1 a1.hard'
    t negato "truncate (path_truncate)" sh_ 'truncate -s0 a1'
    t negato "ftruncate (file_truncate, kernel >= 6.2)" sh_ "python3 -c \"f=open('a1','r+'); f.truncate(0)\""
    t negato "cancellazione" sh_ 'rm -f a1'
fi
reset_files
echo
if [ "$FAIL" -eq 0 ]; then echo "Tutto come atteso."; else echo "Ci sono differenze: copia l'output qui sopra."; fi
echo "Alla fine: elimina zs-a e zs-b dalla GUI, poi rm -r $D"
exit "$FAIL"
