#!/bin/bash
# before/out/rc sono letti da check() dentro stringhe valutate con eval: shellcheck non li vede.
# shellcheck disable=SC2034
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Test di configure_service.sh con comandi e percorsi finti: nessun privilegio, nessun
# servizio vero. Copre: user/profile scritti nel config senza perdere i commenti, primo
# avvio sempre in audit, copia di sicurezza, input ostili rifiutati, errore chiaro se il
# servizio non parte o se manca la unit del pacchetto.
# shellcheck disable=SC2016  # i comandi dei check sono stringhe valutate da eval
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
if [ -z "$T" ] || [ ! -d "$T" ]; then echo "ERRORE: mktemp fallito"; exit 2; fi
trap 'rm -rf "${T:?}"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ✅ $1"; }
ko() { FAIL=$((FAIL + 1)); echo "  ❌ $1"; }
check() { if eval "$2"; then ok "$1"; else ko "$1   [$2]"; fi; }

# systemctl finto: registra i comandi; con FAKE_FAIL=1 'enable' fallisce.
cat > "$T/systemctl" <<STUB
#!/bin/sh
echo "\$*" >> "$T/systemctl.log"
[ "\$1" = enable ] && [ -n "\${FAKE_FAIL:-}" ] && exit 1
exit 0
STUB
chmod +x "$T/systemctl"

fresh() {
    rm -rf "${T:?}/d" && mkdir -p "$T/d"
    : > "$T/systemctl.log"
    : > "$T/d/zt-shield.service"
    cat > "$T/d/shield.yaml" <<'CFG'
# esempio del pacchetto
profile: home
user: ""
# mode: enforce
log_format: text
CFG
}
run() { env ZT_TEST_DIR="$T/d" ZT_TEST_SYSTEMCTL="$T/systemctl" "$HERE/configure_service.sh" "$@" 2>&1; }

if [ "$(id -u)" -eq 0 ]; then
    echo "Esegui questo test come utente normale: come root le variabili di test sono ignorate."
    exit 2
fi

echo "== configurazione del config"
fresh
out="$(run alice home)"
check "esce con successo e dice che il servizio e' attivo in audit" 'echo "$out" | grep -q "attivo in audit"'
check "scrive user: nella riga attiva (era vuota)" 'grep -qx "user: alice" "$T/d/shield.yaml"'
check "non lascia la vecchia riga user: \"\"" '! grep -q "^user: \"\"" "$T/d/shield.yaml"'
check "i commenti e le altre chiavi restano" 'grep -q "^# esempio del pacchetto" "$T/d/shield.yaml" && grep -q "^log_format: text" "$T/d/shield.yaml"'
check "la riga commentata # mode: enforce non viene toccata" 'grep -qx "# mode: enforce" "$T/d/shield.yaml"'
check "primo avvio sempre in audit (mode: audit aggiunto)" 'grep -qx "mode: audit" "$T/d/shield.yaml"'
check "crea una copia di sicurezza del config precedente" 'ls "$T/d"/shield.yaml.bak-* > /dev/null 2>&1'
check "daemon-reload poi enable --now" 'grep -qx "daemon-reload" "$T/systemctl.log" && grep -qx "enable --now zt-shield" "$T/systemctl.log"'

echo "== profilo e mode esistente"
fresh
printf 'mode: enforce\n' >> "$T/d/shield.yaml"
run bob corporate > /dev/null
check "profilo cambiato" 'grep -qx "profile: corporate" "$T/d/shield.yaml"'
check "un mode: gia' presente non viene sovrascritto" 'grep -qx "mode: enforce" "$T/d/shield.yaml" && ! grep -qx "mode: audit" "$T/d/shield.yaml"'

echo "== config assente e file senza a-capo finale"
fresh
rm "$T/d/shield.yaml"
run carol home > /dev/null
check "config creato da zero con user e profile" 'grep -qx "user: carol" "$T/d/shield.yaml" && grep -qx "profile: home" "$T/d/shield.yaml"'
fresh
printf 'log_format: json' > "$T/d/shield.yaml"
run dave home > /dev/null
check "senza a-capo finale la riga aggiunta non si attacca alla precedente" 'grep -qx "log_format: json" "$T/d/shield.yaml" && grep -qx "user: dave" "$T/d/shield.yaml"'

echo "== input rifiutati"
fresh
before="$(cat "$T/d/shield.yaml")"
for bad in 'root' 'Alice' 'a b' 'x;rm -rf /' '$(id)' '../x' ''; do
    run "$bad" home > /dev/null; rc=$?
    check "utente '$bad' rifiutato" '[ "$rc" -ne 0 ]'
done
run alice nonsense > /dev/null; rc=$?
check "profilo sconosciuto rifiutato" '[ "$rc" -ne 0 ]'
check "dopo i rifiuti il config e' identico e systemctl non e' stato chiamato" '[ "$(cat "$T/d/shield.yaml")" = "$before" ] && [ ! -s "$T/systemctl.log" ]'

echo "== servizio che non parte, unit mancante"
fresh
out="$(FAKE_FAIL=1 run erin home)"; rc=$?
check "se enable fallisce esce con errore e spiega la causa (bpf) e il journal" '[ "$rc" -ne 0 ] && echo "$out" | grep -q "bpf" && echo "$out" | grep -q "journalctl"'
check "...ma il config e' stato comunque aggiornato" 'grep -qx "user: erin" "$T/d/shield.yaml"'
fresh
rm "$T/d/zt-shield.service"
out="$(run frank home)"; rc=$?
check "senza unit del pacchetto rimanda a install_service.sh e non tocca il config" '[ "$rc" -ne 0 ] && echo "$out" | grep -q install_service.sh && grep -q "^user: \"\"" "$T/d/shield.yaml"'

echo
echo "Passati: $PASS   Falliti: $FAIL"
[ "$FAIL" -eq 0 ]
