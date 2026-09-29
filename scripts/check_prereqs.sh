#!/bin/bash
# Verifica kernel, BTF, LSM bpf e toolchain. Exit != 0 se manca qualcosa di bloccante.
#
# Usato come gate prima di `make build`: fallire qui con un messaggio chiaro e'
# preferibile a un errore di compilazione o a un fallimento del verifier piu' avanti.
set -uo pipefail
# NOTA: niente -e di proposito. Qui si vuole eseguire TUTTI i check e riferire
# tutti i problemi insieme: con -e si fermerebbe al primo, costringendo a
# rieseguire lo script piu' volte. L'uscita e' gestita da $FAIL a fondo.

FAIL=0
ok()   { echo "✅ $1"; }
ko()   { echo "❌ $1"; FAIL=1; }
warn() { echo "⚠️  $1"; }  # non bloccante

# --- Kernel ---
# 5.15 e' il minimo per il supporto LSM in BPF e per la sintassi delle mappe usate.
# Si confronta in ordine di versione, non lessicografico: `sort -V` e' quello che
# tratta 5.9 come maggiore di 5.15 (che lessicograficamente e' il contrario).
KVER=$(uname -r | cut -d. -f1-2)
if [ "$(printf '%s\n5.15\n' "$KVER" | sort -V | head -1)" = "5.15" ]; then ok "Kernel $KVER (>= 5.15)"; else ko "Kernel $KVER < 5.15"; fi

# --- BTF ---
# Necessario per due cose: generare vmlinux.h (da cui dipendono le struct dei tipi
# kernel) e per CO-RE (la rilocazione dei field letti con BPF_CORE_READ).
# Senza BTF questo progetto non e' costruibile: non e' un warning.
[ -f /sys/kernel/btf/vmlinux ] && ok "BTF presente" || ko "BTF assente (/sys/kernel/btf/vmlinux): serve un kernel con CONFIG_DEBUG_INFO_BTF"

# --- BPF LSM ---
# Il punto che blocca tutto. `bpf` deve essere nella lista dei moduli LSM ATTIVI,
# non solo compilati nel kernel: CONFIG_BPF_LSM=y dice solo che il codice c'e'.
# Senza questo, link.AttachLSM fallisce e il servizio non parte.
# Abilitazione: append di 'bpf' alla lista corrente in GRUB_CMDLINE_LINUX_DEFAULT,
# poi update-grub e reboot. Vedi README.
if grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    ok "BPF LSM attivo"
else
    echo "   lista attuale: $(cat /sys/kernel/security/lsm 2>/dev/null || echo 'non leggibile')"
    ko "BPF LSM non attivo. Aggiungi 'bpf' alla lista lsm= nel bootloader (vedi README) e riavvia"
fi

# bpffs: serve solo se in futuro si aggiunge il pinning. Per ora non e' bloccante,
# quindi resta un warning e non un ko.
[ -d /sys/fs/bpf ] && ok "bpffs montato" || warn "bpffs non montato: necessario se in futuro si aggiunge il pinning degli hook"

# --- Toolchain di build ---
# make serve al target `generate`; bpftool per il dump BTF; clang per compilare
# zerotrust.c; go per bpf2go e per il binario.
for t in clang bpftool go make; do
    command -v "$t" >/dev/null && ok "$t trovato" || ko "$t mancante"
done

# --- Versione Go ---
# cilium/ebpf richiede Go 1.22 o successivo.
if command -v go >/dev/null; then
    MINOR=$(go version | sed -E 's/.*go1\.([0-9]+).*/\1/')
    [ "${MINOR:-0}" -ge 22 ] && ok "Go >= 1.22" || ko "Go troppo vecchio: $(go version)"
fi

# --- Dipendenze per gli script opzionali ---
# Non bloccanti perche' servono solo a harden_system.sh e setup_fido2.sh,
# non al demone.
command -v ufw >/dev/null && ok "ufw trovato" || warn "ufw mancante (serve per harden_system.sh)"
command -v ssh-keygen >/dev/null && ok "ssh-keygen trovato" || warn "openssh-client mancante (serve per setup_fido2.sh)"
command -v fido2-token >/dev/null && ok "fido2-tools trovato" || warn "fido2-tools mancante (serve per setup_fido2.sh)"

# --- Esito ---
# Exit code diverso da zero: questo script e' usabile come gate in un Makefile o
# in una pipeline, non solo come output per umani.
if [ "$FAIL" -eq 0 ]; then echo; echo "Tutto pronto."; else echo; echo "Prerequisiti mancanti."; fi
exit "$FAIL"
