#!/bin/bash
# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Test di vpn_killswitch.sh in un network namespace usa e getta: non tocca la rete
# della macchina. Serve root, unshare e nft; altrimenti si salta (exit 0).
#
#   sudo scripts/test_killswitch.sh
#
# Copre i difetti trovati nella revisione del 2026-10-05: rollback che cancellava il
# firewall dell'utente, backup in /tmp caricato come root, riapplicazione non atomica,
# endpoint IPv6, modalita' portal che non si richiudeva.
# shellcheck disable=SC2016,SC2034  # i comandi dei check sono stringhe valutate da eval
set -uo pipefail

if [ "${ZT_IN_NETNS:-}" != "1" ]; then
    [ "$(id -u)" -eq 0 ] || { echo "SKIP: serve root"; exit 0; }
    command -v nft >/dev/null || { echo "SKIP: nft mancante"; exit 0; }
    command -v unshare >/dev/null || { echo "SKIP: unshare mancante"; exit 0; }
    unshare -n true 2>/dev/null || { echo "SKIP: network namespace non disponibili"; exit 0; }
    ZT_ORIG_NETNS="$(readlink /proc/self/ns/net)" ZT_IN_NETNS=1 exec unshare -n bash "$0" "$@"
fi

# --- GUARD BEGIN
# Rete di sicurezza: tutto cio' che segue fa `nft flush ruleset` e applica un kill-switch che
# scarta il traffico. Il re-exec qui sopra registra il namespace di rete di PARTENZA
# (ZT_ORIG_NETNS) e qui si verifica che quello attuale sia diverso. Se non lo e' (ZT_IN_NETNS=1
# impostata a mano senza passare dal re-exec, un unshare andato storto) ci si ferma PRIMA di
# toccare il firewall della macchina. Una variabile d'ambiente da sola non e' una garanzia:
# si confronta il namespace reale.
ns_self="$(readlink /proc/self/ns/net 2>/dev/null || true)"
if [ -z "${ZT_ORIG_NETNS:-}" ] || [ -z "$ns_self" ] || [ "$ns_self" = "$ZT_ORIG_NETNS" ]; then
    echo "ERRORE: non sono in un network namespace separato da quello di partenza (${ns_self:-?} / ${ZT_ORIG_NETNS:-?})."
    echo "        Rifiuto di continuare: toccherei il firewall di QUESTA macchina."
    exit 2
fi
# --- GUARD END

# nftables nel namespace puo' mancare sul kernel (moduli): e' l'ambiente, non il codice.
if ! nft add table inet zt_probe 2>/dev/null; then
    echo "SKIP: nftables non utilizzabile in un network namespace su questo kernel"
    exit 0
fi
nft delete table inet zt_probe 2>/dev/null || true

KS="${KS:-$(cd "$(dirname "$0")" && pwd)/vpn_killswitch.sh}"
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ✅ $1"; }
ko() { FAIL=$((FAIL + 1)); echo "  ❌ $1"; }
check() { if eval "$2"; then ok "$1"; else ko "$1   [$2]"; fi; }
tables() { nft list tables | sort | tr '\n' ' '; }
ruleset_of() { nft list table inet zt-killswitch 2>/dev/null; }

# Firewall "dell'utente" (stand-in di ufw): deve sopravvivere a tutto.
userfw() {
    nft flush ruleset
    nft -f - <<'R'
table inet userfw {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iifname "lo" accept
  }
}
R
}
reset() { userfw; rm -f /tmp/zt-nft.backup; }

echo "== T1: on valido, status, idempotenza"
reset
check "on IPv4 riesce" '$KS on 203.0.113.7:51820 lo >/dev/null 2>&1'
check "la tabella esiste" 'nft list table inet zt-killswitch >/dev/null 2>&1'
check "status = attivo (rc 0)" '$KS status >/dev/null 2>&1'
check "policy drop su output e input" '[ "$(ruleset_of | grep -c "policy drop")" -eq 2 ]'
check "il firewall dell’utente e’ ancora li’" 'nft list tables | grep -q userfw'
before="$(ruleset_of)"
check "riapplicare con gli stessi valori riesce" '$KS on 203.0.113.7:51820 lo >/dev/null 2>&1'
check "...e il ruleset e' identico" '[ "$(ruleset_of)" = "$before" ]'

echo "== T2: riapplicazione con valore sbagliato = atomica (prima toglieva il kill-switch attivo)"
before="$(ruleset_of)"
for bad in 'vpn.example.com:51820' '203.0.113.7' '203.0.113.7:0' '203.0.113.7:70000' '999.1.1.1:51820' \
           '1.2.3.4;flush ruleset:51820' '[zzzz]:51820' '203.0.113.7:51820 ' ; do
    $KS on "$bad" lo >/dev/null 2>&1
    rc=$?
    check "endpoint '$bad' rifiutato (rc=$rc)" '[ "$rc" -ne 0 ]'
    check "  kill-switch ancora attivo e invariato" '[ "$(ruleset_of)" = "$before" ]'
done

echo "== T3: altri input non validi rifiutati, nessuna modifica"
for args in 'on 203.0.113.7:51820 wg;ls' 'on 203.0.113.7:51820 nonexistent0' 'on 203.0.113.7:51820 lo 10.0.0.0/8;drop' \
            'on 203.0.113.7:51820 lo 192.168.1.1' 'on 203.0.113.7:51820 lo 10.0.0.0/33' 'on 203.0.113.7:51820 abcdefghijklmnop'; do
    # shellcheck disable=SC2086  # gli argomenti vanno separati di proposito
    $KS $args >/dev/null 2>&1
    rc=$?
    check "'$args' rifiutato (rc=$rc)" '[ "$rc" -ne 0 ]'
done
check "ruleset invariato dopo tutti i rifiuti" '[ "$(ruleset_of)" = "$before" ]'

echo "== T4: IPv6, LAN extra, DHCP"
reset
check "endpoint IPv6 accettato" '$KS on "[2001:db8::1]:51820" lo 192.168.1.0/24 fd00::/8 >/dev/null 2>&1'
check "usa ip6 daddr per l’endpoint" 'ruleset_of | grep -q "ip6 daddr 2001:db8::1"'
check "LAN v4 e v6 presenti" 'ruleset_of | grep -q "ip daddr 192.168.1.0/24" && ruleset_of | grep -q "ip6 daddr fd00::/8"'
check "DHCP consentito di default" 'ruleset_of | grep -q "dport 67"'
BLOCK_DHCP=1 $KS on 203.0.113.7:51820 lo >/dev/null 2>&1
check "BLOCK_DHCP=1 toglie il DHCP" '! ruleset_of | grep -q "dport 67"'

echo "== T5: off tocca SOLO la propria tabella (prima: flush ruleset + ricarica del backup)"
reset
nft add table inet altro
$KS on 203.0.113.7:51820 lo >/dev/null 2>&1
check "off riesce" '$KS off >/dev/null 2>&1'
check "la tabella del kill-switch e' sparita" '! nft list table inet zt-killswitch >/dev/null 2>&1'
check "il firewall dell’utente e' intatto" 'nft list tables | grep -q userfw'
check "una tabella estranea e' intatta" 'nft list tables | grep -q altro'
check "off ripetuto e' innocuo (rc 0)" '$KS off >/dev/null 2>&1'
check "status = non attivo (rc 3)" '$KS status >/dev/null 2>&1; [ $? -eq 3 ]'

echo "== T6: un backup piazzato in /tmp da altri NON viene mai caricato"
reset
cat > /tmp/zt-nft.backup <<'R'
table inet attacker_marker {
  chain input { type filter hook input priority -300; policy accept; counter }
}
R
chown 1234:1234 /tmp/zt-nft.backup
sum_before="$(md5sum /tmp/zt-nft.backup)"
$KS on 203.0.113.7:51820 lo >/dev/null 2>&1
$KS off >/dev/null 2>&1
check "la tabella dell’attaccante non e' stata caricata" '! nft list tables | grep -q attacker_marker'
check "il firewall dell’utente e' ancora li’" 'nft list tables | grep -q userfw'
check "lo script non ha letto ne' toccato il file" '[ "$(md5sum /tmp/zt-nft.backup)" = "$sum_before" ]'
rm -f /tmp/zt-nft.backup

echo "== T7: portal = apertura a tempo gestita dal kernel"
reset
check "portal senza kill-switch attivo e' un errore" '! $KS portal lo 10 >/dev/null 2>&1'
$KS on 203.0.113.7:51820 lo >/dev/null 2>&1
check "portal con secondi fuori scala rifiutato" '! $KS portal lo 3 >/dev/null 2>&1 && ! $KS portal lo 5000 >/dev/null 2>&1'
check "portal con interfaccia non valida rifiutato" '! $KS portal "lo;x" 10 >/dev/null 2>&1'
check "portal 6s riesce" '$KS portal lo 6 >/dev/null 2>&1'
check "l’elemento e' nel set subito dopo" 'nft list set inet zt-killswitch portal_ifaces | grep -q "\"lo\""'
check "apre solo web e DNS (non tutto)" 'ruleset_of | grep -q "oifname @portal_ifaces tcp dport { 80, 443 } accept"'
check "il kill-switch resta (policy drop)" '[ "$(ruleset_of | grep -c "policy drop")" -eq 2 ]'
sleep 8
check "dopo la scadenza l’elemento e' sparito, senza alcun processo" '! nft list set inet zt-killswitch portal_ifaces | grep -q "\"lo\""'
check "...e il kill-switch e' ancora attivo" 'nft list table inet zt-killswitch >/dev/null 2>&1'

echo "== T8: nessun file di stato o backup creato"
reset
$KS on 203.0.113.7:51820 lo >/dev/null 2>&1
$KS off >/dev/null 2>&1
check "niente /tmp/zt-nft.backup" '[ ! -e /tmp/zt-nft.backup ]'

echo
echo "Risultato: $PASS ok, $FAIL falliti"
[ "$FAIL" -eq 0 ]
