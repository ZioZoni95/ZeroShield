// Package bpf contiene il codice eBPF (zerotrust.c) e gli stub Go generati da bpf2go.
//
// bpf2go compila zerotrust.c con clang, poi genera shield_*_bpfel.go: gli stub
// contengono i byte dell'oggetto ELF e le funzioni di caricamento. In questo repo
// il pacchetto e' `bpf`, quindi i simboli generati sono bpf.ShieldObjects,
// bpf.LoadShieldObjects, bpf.ShieldXdpShield (programma "xdp_shield"),
// bpf.ShieldZtFileOpen (programma "zt_file_open"), ecc.
//
// Gli artefatti generati (shield_*_bpfel.go e .o) e vmlinux.h sono in .gitignore:
// dipendono dal kernel locale e vanno rigenerati su ciascuna macchina.
//
// Flag di bpf2go:
//
//	-no-strip        conserva il BTF/DWARF nell'oggetto, necessario per il caricamento
//	                 e per non richiedere llvm-strip (che su Ubuntu è in un pacchetto
//	                 separato). L'oggetto e' piu' grande, ma su un desktop e' irrilevante.
//	-target native   genera codice per l'architettura corrente. Alternativa: -target bpf
//	                 (un ELF Linux BPF) che richiede un loader diverso; native e' il
//	                 percorso supportato con link.AttachXDP / link.AttachLSM.
//	Shield           nome del file .c da cui generare gli stub (shield_*_bpfel.go).
//	-I.              include path: serve per trovare vmlinux.h generato dal Makefile.
//
// Requisiti per rigenerare: vmlinux.h (target `make vmlinux`), clang, e un kernel con
// CONFIG_DEBUG_INFO_BTF, cioe' /sys/kernel/btf/vmlinux leggibile.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -target native Shield zerotrust.c -- -I.
