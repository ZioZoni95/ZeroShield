#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Test di nm_vpn.sh con comandi finti (wg-quick, ip, iwgetid, logger) e uno sysfs
# finto: nessuna rete toccata, nessun privilegio necessario.
#
#   scripts/test_nm_vpn.sh
#
# Copre i difetti trovati nella revisione del 2026-10-05: BSSID vuoto trattato come
# rete fidata (VPN spenta sul cavo), eventi su interfacce virtuali, tunnel gia' attivo
# rilanciato, proton_up.sh non trovato quando lo script e' installato in dispatcher.d.
# shellcheck disable=SC2016,SC2034  # i comandi dei check sono stringhe valutate da eval
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NM="${NM:-$HERE/nm_vpn.sh}"
T="$(mktemp -d)"
# Senza una directory temporanea valida non si procede; rm usa ${T:?} per fermarsi se T e' vuota.
if [ -z "$T" ] || [ ! -d "$T" ]; then echo "ERRORE: mktemp fallito"; exit 2; fi
trap 'rm -rf "${T:?}"' EXIT
mkdir -p "$T/bin" "$T/sys/class/net" "$T/scripts"

# --- sysfs finto: wlan0 (wifi), eth0 (cavo), docker0 e wg0 (virtuali: niente "device")
mkdir -p "$T/sys/class/net/wlan0/wireless" "$T/sys/class/net/eth0" "$T/sys/class/net/docker0" "$T/sys/class/net/proton"
touch "$T/sys/class/net/wlan0/device" "$T/sys/class/net/eth0/device"

# --- comandi finti: registrano le chiamate in $T/calls
cat > "$T/bin/wg-quick" <<EOF
#!/bin/sh
echo "wg-quick \$*" >> "$T/calls"
[ "\$1" = up ] && touch "$T/tunnel_up"
[ "\$1" = down ] && rm -f "$T/tunnel_up"
exit 0
EOF
cat > "$T/bin/logger" <<EOF
#!/bin/sh
shift 2; echo "log: \$*" >> "$T/calls"
EOF
cat > "$T/bin/ip" <<EOF
#!/bin/sh
# solo "ip link show <if>": riesce se il tunnel e' "su"
[ -e "$T/tunnel_up" ]
EOF
# iwgetid <iface> [-a] -r : risponde solo per l'interfaccia richiesta, secondo \$T/wifi_<iface>
cat > "$T/bin/iwgetid" <<EOF
#!/bin/sh
ifc="\$1"; shift
f="$T/wifi_\$ifc"
[ -f "\$f" ] || exit 0
for a in "\$@"; do
    if [ "\$a" = "-a" ]; then sed -n 2p "\$f"; exit 0; fi
done
sed -n 1p "\$f"
EOF
chmod +x "$T/bin/"*

# Allowlist: due reti Wi-Fi fidate, una riga commentata, il cavo NON fidato.
cat > "$T/nets" <<'EOF'
# reti fidate
Casa AA:BB:CC:DD:EE:FF
Ufficio Centrale 11:22:33:44:55:66
# Vecchia 99:99:99:99:99:99
EOF

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ✅ $1"; }
ko() { FAIL=$((FAIL + 1)); echo "  ❌ $1"; }
check() { if eval "$2"; then ok "$1"; else ko "$1   [$2]"; fi; }

run() { # run <iface> <evento> [VAR=val...]
    local ifc="$1" ev="$2"; shift 2
    : > "$T/calls"
    env PATH="$T/bin:$PATH" ZT_VPN_NETS="${NETS:-$T/nets}" ZT_SYS_NET="$T/sys/class/net" \
        ZT_LOCK="$T/lock" ZT_SCRIPTS="$T/scripts" "$@" "$NM" "$ifc" "$ev" >/dev/null 2>&1
}
wifi() { printf '%s\n%s\n' "$1" "$2" > "$T/wifi_wlan0"; }
calls() { cat "$T/calls"; }
no_vpn_action() { ! grep -q "^wg-quick" "$T/calls"; }
reset() { rm -f "$T/tunnel_up" "$T"/wifi_* "$T/scripts/proton_up.sh"; : > "$T/calls"; }

echo "== evento e interfaccia"
reset; wifi CaffeBar 66:77:88:99:AA:BB
run wlan0 down;  check "evento 'down' ignorato" 'no_vpn_action'
run wlan0 dhcp4-change; check "evento diverso da 'up' ignorato" 'no_vpn_action'
run docker0 up;  check "interfaccia virtuale (docker0) ignorata anche su rete ostile" 'no_vpn_action'
run proton up;   check "il tunnel stesso non genera azioni" 'no_vpn_action'
run 'wl;an0' up; check "nome interfaccia malformato ignorato" 'no_vpn_action'
NETS=/nonexistent run wlan0 up; check "senza allowlist non si tocca nulla (opt-in)" 'no_vpn_action'

echo "== Wi-Fi non fidato = VPN su"
reset; wifi CaffeBar 66:77:88:99:AA:BB
run wlan0 up; check "BSSID sconosciuto: wg-quick up" 'grep -q "^wg-quick up proton" "$T/calls"'
reset; wifi Casa-evil-twin 66:77:88:99:AA:BB
run wlan0 up; check "SSID uguale ma BSSID diverso (evil-twin): VPN su" 'grep -q "^wg-quick up" "$T/calls"'
reset; wifi Vecchia 99:99:99:99:99:99
run wlan0 up; check "BSSID solo in una riga commentata: non fidato" 'grep -q "^wg-quick up" "$T/calls"'
reset; wifi X AA:BB:CC:DD:EE:F
run wlan0 up; check "BSSID troncato (sottostringa di uno fidato): non fidato" 'grep -q "^wg-quick up" "$T/calls"'
reset; wifi X ""
run wlan0 up; check "BSSID vuoto: non identificabile = non fidato" 'grep -q "^wg-quick up" "$T/calls"'
reset
run wlan0 up; check "iwgetid senza output (niente Wi-Fi): non fidato" 'grep -q "^wg-quick up" "$T/calls"'
reset; wifi X "non-un-mac"
run wlan0 up; check "BSSID malformato: non fidato" 'grep -q "^wg-quick up" "$T/calls"'

echo "== Wi-Fi fidato"
reset; wifi Casa AA:BB:CC:DD:EE:FF
run wlan0 up; check "BSSID in allowlist: VPN non richiesta" 'no_vpn_action'
reset; wifi Casa aa:bb:cc:dd:ee:ff
run wlan0 up; check "BSSID in minuscolo riconosciuto" 'no_vpn_action'
reset; wifi "Ufficio Centrale" 11:22:33:44:55:66
run wlan0 up; check "SSID con spazi: conta il BSSID" 'no_vpn_action'
reset; wifi Casa AA:BB:CC:DD:EE:FF; touch "$T/tunnel_up"
run wlan0 up; check "rete fidata + tunnel su: NON lo spegne (default)" 'no_vpn_action'
reset; wifi Casa AA:BB:CC:DD:EE:FF; touch "$T/tunnel_up"
run wlan0 up AUTO_DOWN=1; check "AUTO_DOWN=1 esplicito: lo spegne" 'grep -q "^wg-quick down proton" "$T/calls"'
reset; wifi Casa AA:BB:CC:DD:EE:FF
run wlan0 up AUTO_DOWN=1; check "AUTO_DOWN=1 senza tunnel su: nessun down inutile" 'no_vpn_action'

echo "== cavo (BSSID vuoto): il caso che spegneva la VPN"
reset
run eth0 up; check "cavo senza 'wired' in allowlist: VPN SU (prima: giu')" 'grep -q "^wg-quick up proton" "$T/calls"'
reset; touch "$T/tunnel_up"
run eth0 up; check "cavo + tunnel su: nessuna azione, soprattutto nessun down" 'no_vpn_action'
printf 'Casa AA:BB:CC:DD:EE:FF\nwired\n' > "$T/nets2"
reset
NETS="$T/nets2" run eth0 up; check "cavo con 'wired' esplicito: fidato, nessuna azione" 'no_vpn_action'
printf 'Casa AA:BB:CC:DD:EE:FF\n# wired\n' > "$T/nets3"
reset
NETS="$T/nets3" run eth0 up; check "'wired' commentato non conta" 'grep -q "^wg-quick up" "$T/calls"'

echo "== idempotenza"
reset; wifi CaffeBar 66:77:88:99:AA:BB; touch "$T/tunnel_up"
run wlan0 up; check "rete ostile con tunnel gia' su: nessun secondo wg-quick up" 'no_vpn_action'
run wlan0 up; check "...ripetuto: ancora nessuna azione" 'no_vpn_action'

echo "== Proton (PROTON=1)"
reset; wifi CaffeBar 66:77:88:99:AA:BB
printf '#!/bin/sh\necho "proton_up $*" >> "%s/calls"\n' "$T" > "$T/scripts/proton_up.sh"; chmod +x "$T/scripts/proton_up.sh"
run wlan0 up PROTON=1; check "proton_up.sh trovato e chiamato con 'connect'" 'grep -q "^proton_up connect" "$T/calls" && no_vpn_action'

echo "== installato come dispatcher.d (script copiato senza i fratelli)"
mkdir -p "$T/dispatcher.d"; cp "$NM" "$T/dispatcher.d/90-zt-vpn"
reset; wifi CaffeBar 66:77:88:99:AA:BB
printf '#!/bin/sh\necho "proton_up $*" >> "%s/calls"\n' "$T" > "$T/scripts/proton_up.sh"; chmod +x "$T/scripts/proton_up.sh"
: > "$T/calls"
env PATH="$T/bin:$PATH" ZT_VPN_NETS="$T/nets" ZT_SYS_NET="$T/sys/class/net" ZT_LOCK="$T/lock" ZT_SCRIPTS="$T/scripts" PROTON=1 "$T/dispatcher.d/90-zt-vpn" wlan0 up >/dev/null 2>&1
check "proton_up.sh trovato anche con lo script copiato in dispatcher.d" 'grep -q "^proton_up connect" "$T/calls"'
rm -f "$T/scripts/proton_up.sh"

reset; wifi CaffeBar 66:77:88:99:AA:BB
: > "$T/calls"
env PATH="$T/bin:$PATH" ZT_VPN_NETS="$T/nets" ZT_SYS_NET="$T/sys/class/net" ZT_LOCK="$T/lock" ZT_SCRIPTS="$T/niente" ZT_SYS_SCRIPTS="$T/niente" PROTON=1 "$T/dispatcher.d/90-zt-vpn" wlan0 up >/dev/null 2>&1
check "proton_up.sh davvero assente: errore esplicito nel log, nessun wg-quick" 'grep -q "ERRORE: proton_up.sh non trovato" "$T/calls" && no_vpn_action'

echo
echo "Risultato: $PASS ok, $FAIL falliti"
[ "$FAIL" -eq 0 ]
