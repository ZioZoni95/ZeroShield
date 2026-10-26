#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Test di harden_system.sh con comandi finti (ufw, systemctl, sysctl, ss): nessun
# privilegio, nessuna modifica al sistema. Copre: il dry-run non tocca nulla e mostra il
# diff, nessun `ufw allow OpenSSH` (che con set -e abortiva l'hardening senza il profilo),
# la porta di sshd rilevata davvero, idempotenza delle modifiche a resolved.conf.
# shellcheck disable=SC2016,SC2034  # i comandi dei check sono stringhe valutate da eval
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
if [ -z "$T" ] || [ ! -d "$T" ]; then echo "ERRORE: mktemp fallito"; exit 2; fi
trap 'rm -rf "${T:?}"' EXIT
mkdir -p "$T/bin"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ✅ $1"; }
ko() { FAIL=$((FAIL + 1)); echo "  ❌ $1"; }
check() { if eval "$2"; then ok "$1"; else ko "$1   [$2]"; fi; }

# Ogni comando finto registra la chiamata in $T/calls.
for c in ufw systemctl sysctl; do
    cat > "$T/bin/$c" <<STUB
#!/bin/sh
echo "$c \$*" >> "$T/calls"
exit 0
STUB
    chmod +x "$T/bin/$c"
done
# ss finto: elenca sshd sulla porta scritta in $T/sshd_port (se il file esiste).
cat > "$T/bin/ss" <<STUB
#!/bin/sh
[ -f "$T/sshd_port" ] && printf 'LISTEN 0 128 0.0.0.0:%s 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n' "\$(cat "$T/sshd_port")"
exit 0
STUB
chmod +x "$T/bin/ss"

fresh() {
    rm -f "$T/calls" "$T/sshd_port" "$T/sysctl.conf"
    printf '[Resolve]\n#LLMNR=yes\n#MulticastDNS=yes\n#DNS=\n' > "$T/resolved.conf"
}
harden() {
    env PATH="$T/bin:$PATH" ZT_RESOLVED_CONF="$T/resolved.conf" ZT_SYSCTL_FILE="$T/sysctl.conf" \
        "$HERE/harden_system.sh" "$@" 2>&1
}

echo "== dry-run"
fresh
before="$(cat "$T/resolved.conf")"
out="$(harden public-wifi --dry-run)"; rc=$?
check "esce 0 senza root" '[ $rc -eq 0 ]'
check "non modifica resolved.conf" '[ "$(cat "$T/resolved.conf")" = "$before" ]'
check "non crea il file sysctl" '[ ! -e "$T/sysctl.conf" ]'
# Solo interrogazioni di sola lettura (ss per le porte di sshd, systemctl is-enabled).
check "non esegue nessun comando che modifica" '! grep -vE "^(ss -|systemctl is-enabled)" "$T/calls"'
check "stampa i comandi come [dry-run]" 'echo "$out" | grep -q "\[dry-run\] ufw --force enable"'
check "mostra il diff di resolved.conf" 'echo "$out" | grep -q "^+LLMNR=no" && echo "$out" | grep -q "^+DNSOverTLS=opportunistic"'
check "mostra il nuovo contenuto sysctl" 'echo "$out" | grep -q "net.ipv4.conf.all.accept_redirects = 0"'
check "dice che non ha modificato nulla" 'echo "$out" | grep -q "nessuna modifica fatta"'
check "ZT_DRY_RUN=1 equivale a --dry-run" '(fresh; ZT_DRY_RUN=1 harden home >/dev/null; ! grep -vE "^(ss -|systemctl is-enabled)" "$T/calls")'

echo "== esecuzione reale (comandi finti)"
fresh
out="$(harden paranoid)"; rc=$?
# Il test gira da non root: harden_system.sh farebbe `exec sudo`. Se sudo manca o chiede la
# password il test salta questa parte invece di fallire per un motivo estraneo.
if [ "$(id -u)" -ne 0 ]; then
    echo "  ⏭️  non root: sezione saltata (si esegue con sudo in CI)"
else
    check "esce 0" '[ $rc -eq 0 ]'
    check "non invoca mai 'ufw allow OpenSSH'" '! grep -q "OpenSSH" "$T/calls"'
    check "senza sshd non apre nessuna porta in ingresso" '! grep -q "ufw allow" "$T/calls"'
    check "abilita ufw con deny incoming" 'grep -q "ufw default deny incoming" "$T/calls" && grep -q "ufw --force enable" "$T/calls"'
    check "scrive LLMNR=no e MulticastDNS=no" 'grep -q "^LLMNR=no" "$T/resolved.conf" && grep -q "^MulticastDNS=no" "$T/resolved.conf"'
    check "paranoid forza DNSOverTLS=yes" 'grep -q "^DNSOverTLS=yes" "$T/resolved.conf"'
    check "backup di resolved.conf creato una volta" '[ -f "$T/resolved.conf.zt-backup" ]'
    sums="$(md5sum < "$T/resolved.conf")"
    harden paranoid >/dev/null
    check "idempotente: la seconda esecuzione non cambia resolved.conf" '[ "$(md5sum < "$T/resolved.conf")" = "$sums" ]'
    check "...e non duplica le chiavi" '[ "$(grep -c "^LLMNR=" "$T/resolved.conf")" -eq 1 ]'

    fresh; echo 2222 > "$T/sshd_port"
    harden home >/dev/null
    check "con sshd sulla 2222 apre esattamente 2222/tcp" 'grep -q "ufw allow 2222/tcp" "$T/calls" && [ "$(grep -c "ufw allow" "$T/calls")" -eq 1 ]'
    check "il profilo home non forza DNS" '! grep -q "^DNS=" "$T/resolved.conf"'
fi

echo "== argomenti"
out="$(harden profilo-inventato --dry-run)"; rc=$?
check "profilo sconosciuto: errore" '[ $rc -eq 1 ] && echo "$out" | grep -q "Uso:"'

echo
echo "Risultato: $PASS ok, $FAIL falliti"
[ "$FAIL" -eq 0 ]
