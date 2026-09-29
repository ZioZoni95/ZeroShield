// Package bpf contiene il codice eBPF (zerotrust.c) e gli stub Go generati da bpf2go.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -target native Shield zerotrust.c -- -I.
