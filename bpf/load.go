// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package bpf

import (
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// ProgZtFileTruncate: hook lsm/file_truncate (ftruncate su fd aperto, kernel >= 6.2).
// OPZIONALE: sui kernel senza security_file_truncate il simbolo bpf_lsm_file_truncate non
// esiste e un programma che lo richiede non si carica. bpf2go, invece, tratta tutti i
// programmi come obbligatori (ShieldObjects fallirebbe su un kernel 5.15/6.1). Load qui
// sotto decide a runtime se caricarlo.
const ProgZtFileTruncate = "zt_file_truncate"

// CorePrograms: i programmi presenti su ogni kernel supportato. Deve coincidere con
// ShieldPrograms meno ProgZtFileTruncate (lo verifica TestCoreProgramsMatchSpec).
type CorePrograms struct {
	XdpShield      *ebpf.Program `ebpf:"xdp_shield"`
	ZtFileOpen     *ebpf.Program `ebpf:"zt_file_open"`
	ZtFileRename   *ebpf.Program `ebpf:"zt_file_rename"`
	ZtFileUnlink   *ebpf.Program `ebpf:"zt_file_unlink"`
	ZtPathTruncate *ebpf.Program `ebpf:"zt_path_truncate"`
}

type coreObjects struct {
	CorePrograms
	ShieldMaps
}

type truncObjects struct {
	CorePrograms
	ShieldMaps
	ZtFileTruncate *ebpf.Program `ebpf:"zt_file_truncate"`
}

// Objects: tutto cio' che il demone usa. ZtFileTruncate e' nil se il kernel non lo
// supporta (o se il suo caricamento e' fallito: in quel caso Load avvisa e prosegue).
type Objects struct {
	CorePrograms
	ShieldMaps
	ZtFileTruncate *ebpf.Program
}

var (
	kbtfOnce sync.Once
	kbtf     *btf.Spec
	kbtfErr  error
)

// KernelHasLSMHook dice se il kernel espone l'hook LSM `name` (es. "file_truncate"),
// cercando bpf_lsm_<name> nel BTF del kernel. In dubbio (BTF illeggibile) risponde false:
// meglio una copertura in meno che un demone che non parte.
func KernelHasLSMHook(name string) bool {
	kbtfOnce.Do(func() { kbtf, kbtfErr = btf.LoadKernelSpec() })
	if kbtfErr != nil {
		return false
	}
	_, err := kbtf.AnyTypeByName("bpf_lsm_" + name)
	return err == nil
}

// Load carica programmi e mappe. Sostituisce LoadShieldObjects.
func Load() (*Objects, error) {
	spec, err := LoadShield()
	if err != nil {
		return nil, fmt.Errorf("spec eBPF: %w", err)
	}
	if KernelHasLSMHook("file_truncate") {
		t := truncObjects{}
		if err := spec.Copy().LoadAndAssign(&t, nil); err == nil {
			return &Objects{CorePrograms: t.CorePrograms, ShieldMaps: t.ShieldMaps, ZtFileTruncate: t.ZtFileTruncate}, nil
		} else {
			// Copertura extra: un suo rifiuto non deve fermare lo scudo. Si dice chiaramente.
			log.Printf("⚠️ hook lsm/file_truncate non caricato (%v): ftruncate su fd aperto resta scoperto", err)
		}
	} else {
		log.Printf("ℹ️ kernel senza security_file_truncate (< 6.2): ftruncate su fd aperto non coperto da questo hook")
	}
	delete(spec.Programs, ProgZtFileTruncate)
	c := coreObjects{}
	if err := spec.LoadAndAssign(&c, nil); err != nil {
		return nil, err
	}
	return &Objects{CorePrograms: c.CorePrograms, ShieldMaps: c.ShieldMaps}, nil
}

// LSMPrograms: gli hook LSM da agganciare, nell'ordine; include file_truncate se caricato.
func (o *Objects) LSMPrograms() []*ebpf.Program {
	progs := []*ebpf.Program{o.ZtFileOpen, o.ZtFileUnlink, o.ZtFileRename, o.ZtPathTruncate}
	if o.ZtFileTruncate != nil {
		progs = append(progs, o.ZtFileTruncate)
	}
	return progs
}

// Close rilascia programmi e mappe.
func (o *Objects) Close() error {
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	for _, p := range []*ebpf.Program{o.XdpShield, o.ZtFileOpen, o.ZtFileRename, o.ZtFileUnlink, o.ZtPathTruncate, o.ZtFileTruncate} {
		if p != nil {
			keep(p.Close())
		}
	}
	keep(o.ShieldMaps.Close())
	return first
}
