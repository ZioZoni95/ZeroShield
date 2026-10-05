#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Test di proton_current.sh e proton_setup.sh con comandi finti: nessuna rete, nessun
# privilegio. Copre: il tunnel di lavoro non viene mai scelto al posto di Proton,
# endpoint non-IP rifiutato, chiave privata lasciata in Downloads segnalata.
# shellcheck disable=SC2016,SC2034  # i comandi dei check sono stringhe valutate da eval
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
# Guardia: senza una directory temporanea valida non si procede. Ogni rm -rf qui sotto
# usa ${T:?}: con T vuota lo script si ferma invece di espandersi in "/sys", "/wg"...
if [ -z "$T" ] || [ ! -d "$T" ]; then echo "ERRORE: mktemp fallito"; exit 2; fi
trap 'rm -rf "${T:?}"' EXIT
mkdir -p "$T/bin" "$T/sys"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ✅ $1"; }
ko() { FAIL=$((FAIL + 1)); echo "  ❌ $1"; }
check() { if eval "$2"; then ok "$1"; else ko "$1   [$2]"; fi; }

# wg finto: `wg show <if> endpoints` risponde secondo $T/wg_<if>
cat > "$T/bin/wg" <<STUB
#!/bin/sh
f="$T/wg_\$2"
[ -f "\$f" ] && cat "\$f"
exit 0
STUB
chmod +x "$T/bin/wg"

setup() {
    rm -rf "${T:?}/sys" && mkdir -p "$T/sys/lo"
    rm -f "${T:?}"/wg_*
    local i
    for i in "$@"; do mkdir -p "$T/sys/$i"; done
}
tunnel() { printf 'PUBKEY=\t%s\n' "$2" > "$T/wg_$1"; }
current() { env PATH="$T/bin:$PATH" ZT_SYS_NET="$T/sys" ZT_ALLOW_NONROOT=1 "$HERE/proton_current.sh" "$@" 2>&1; }

echo "== proton_current.sh"
setup wlan0 wg-work proton0
tunnel wg-work 198.51.100.9:51820
tunnel proton0 185.107.80.5:51820
out="$(current)"; rc=$?
check "con tunnel di lavoro E Proton sceglie Proton (per nome)" '[ $rc -eq 0 ] && echo "$out" | grep -q "Interfaccia: proton0" && echo "$out" | grep -q "185.107.80.5:51820"'
check "...e non stampa l'endpoint del tunnel di lavoro" '! echo "$out" | grep -q "198.51.100.9"'

setup wlan0 wg-work
tunnel wg-work 198.51.100.9:51820
out="$(current)"; rc=$?
check "con SOLO il tunnel di lavoro rifiuta di sceglierlo (rc 1)" '[ $rc -eq 1 ]'
check "...lo elenca e spiega" 'echo "$out" | grep -q "wg-work" && echo "$out" | grep -q "nessun"'
check "...non stampa la stanza vpn: da copiare" '! echo "$out" | grep -q "enabled: true"'
out="$(current --iface wg-work)"; rc=$?
check "--iface sceglie esplicitamente" '[ $rc -eq 0 ] && echo "$out" | grep -q "tunnel: \"wg-work\""'
out="$(current --iface nonesiste)"; rc=$?
check "--iface su tunnel inesistente: errore" '[ $rc -eq 1 ]'
out="$(current --iface "x;y")"; rc=$?
check "--iface con caratteri strani rifiutato" '[ $rc -eq 1 ]'

setup wlan0 proton0 pvpn1
tunnel proton0 1.1.1.1:51820
tunnel pvpn1 2.2.2.2:51820
out="$(current)"; rc=$?
check "due candidati Proton: non ne sceglie uno a caso" '[ $rc -eq 1 ] && echo "$out" | grep -q "piu. di uno"'

setup wlan0
out="$(current)"; rc=$?
check "nessun tunnel: rc 1 con messaggio" '[ $rc -eq 1 ] && echo "$out" | grep -q "Nessun tunnel"'

echo "== proton_setup.sh"
cat > "$T/ok.conf" <<CONF
[Interface]
PrivateKey = SEGRETO
Address = 10.2.0.2/32
[Peer]
PublicKey = PUB
Endpoint = 185.107.80.5:51820
AllowedIPs = 0.0.0.0/0
CONF
setupc() { env ZT_WG_DIR="$T/wg" "$HERE/proton_setup.sh" "$@" 2>&1; }

cp "$T/ok.conf" "$T/dl.conf"
out="$(setupc "$T/dl.conf")"; rc=$?
check "conf valido installato" '[ $rc -eq 0 ] && [ -f "$T/wg/proton.conf" ]'
check "permessi 0600" '[ "$(stat -c %a "$T/wg/proton.conf")" = "600" ]'
check "snippet con endpoint e tunnel" 'echo "$out" | grep -q "endpoint: \"185.107.80.5:51820\"" && echo "$out" | grep -q "tunnel: \"proton\""'
check "avvisa che la chiave privata e' rimasta nel file scaricato" 'echo "$out" | grep -q "chiave privata" && [ -f "$T/dl.conf" ]'

cp "$T/ok.conf" "$T/dl2.conf"
out="$(setupc --remove-source "$T/dl2.conf")"; rc=$?
check "--remove-source cancella l'originale" '[ $rc -eq 0 ] && [ ! -e "$T/dl2.conf" ]'

sed 's/^Endpoint.*/Endpoint = nl-free-1.protonvpn.net:51820/' "$T/ok.conf" > "$T/host.conf"
rm -rf "${T:?}/wg"
out="$(setupc "$T/host.conf")"; rc=$?
check "endpoint con nome host rifiutato (il kill-switch vuole un IP)" '[ $rc -eq 1 ] && [ ! -e "$T/wg/proton.conf" ]'

sed 's/^Endpoint.*/Endpoint = [2001:db8::1]:51820/' "$T/ok.conf" > "$T/v6.conf"
out="$(setupc "$T/v6.conf")"; rc=$?
check "endpoint IPv6 tra parentesi accettato" '[ $rc -eq 0 ]'

printf '[Interface]\nAddress = 10.0.0.1/32\n' > "$T/nokey.conf"
out="$(setupc "$T/nokey.conf")"; rc=$?
check "senza PrivateKey rifiutato" '[ $rc -eq 1 ]'

out="$(setupc /nonexistent.conf)"; rc=$?
check "file inesistente rifiutato" '[ $rc -eq 1 ]'

echo
echo "Risultato: $PASS ok, $FAIL falliti"
[ "$FAIL" -eq 0 ]
