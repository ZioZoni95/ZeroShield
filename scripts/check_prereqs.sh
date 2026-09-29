#!/bin/bash
# Verifica kernel, BTF, LSM bpf e toolchain. Exit != 0 se manca qualcosa di bloccante.
set -uo pipefail

FAIL=0
ok()   { echo "✅ $1"; }
ko()   { echo "❌ $1"; FAIL=1; }
warn() { echo "⚠️  $1"; }

KVER=$(uname -r | cut -d. -f1-2)
if [ "$(printf '%s\n5.15\n' "$KVER" | sort -V | head -1)" = "5.15" ]; then ok "Kernel $KVER (>= 5.15)"; else ko "Kernel $KVER < 5.15"; fi

[ -f /sys/kernel/btf/vmlinux ] && ok "BTF presente" || ko "BTF assente (/sys/kernel/btf/vmlinux): serve un kernel con CONFIG_DEBUG_INFO_BTF"

if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    ok "BPF LSM attivo"
else
    ko "BPF LSM non attivo. Aggiungi 'bpf' alla lista lsm= nel bootloader (vedi README) e riavvia"
fi

for t in clang bpftool go make; do
    command -v "$t" >/dev/null && ok "$t trovato" || ko "$t mancante"
done

if command -v go >/dev/null; then
    MINOR=$(go version | sed -E 's/.*go1\.([0-9]+).*/\1/')
    [ "${MINOR:-0}" -ge 22 ] && ok "Go >= 1.22" || ko "Go troppo vecchio: $(go version)"
fi

command -v ufw >/dev/null && ok "ufw trovato" || warn "ufw mancante (serve per harden_system.sh)"
command -v ssh-keygen >/dev/null && ok "ssh-keygen trovato" || warn "openssh-client mancante"
command -v fido2-token >/dev/null && ok "fido2-tools trovato" || warn "fido2-tools mancante (serve per setup_fido2.sh)"

if [ "$FAIL" -eq 0 ]; then echo; echo "Tutto pronto."; else echo; echo "Prerequisiti mancanti."; fi
exit "$FAIL"
