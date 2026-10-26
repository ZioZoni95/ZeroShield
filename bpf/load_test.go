// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package bpf

import (
	"reflect"
	"sort"
	"testing"
)

// CorePrograms e' scritto a mano: se si aggiunge un programma a zerotrust.c e ci si
// scorda di elencarlo, il demone non lo caricherebbe e nessuno se ne accorgerebbe.
func TestCoreProgramsMatchSpec(t *testing.T) {
	spec, err := LoadShield()
	if err != nil {
		t.Fatal(err)
	}
	var inSpec []string
	for n := range spec.Programs {
		if n != ProgZtFileTruncate {
			inSpec = append(inSpec, n)
		}
	}
	var inStruct []string
	rt := reflect.TypeOf(CorePrograms{})
	for i := 0; i < rt.NumField(); i++ {
		inStruct = append(inStruct, rt.Field(i).Tag.Get("ebpf"))
	}
	sort.Strings(inSpec)
	sort.Strings(inStruct)
	if !reflect.DeepEqual(inSpec, inStruct) {
		t.Fatalf("programmi in zerotrust.c %v != CorePrograms %v", inSpec, inStruct)
	}
	if _, ok := spec.Programs[ProgZtFileTruncate]; !ok {
		t.Errorf("%s assente dalla spec", ProgZtFileTruncate)
	}
}
