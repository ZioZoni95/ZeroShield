# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Build di zt-shield.
#
# La catena e' obbligata: vmlinux.h -> bpf2go -> go build. Il .o eBPF viene
# incorporato nel binario Go, quindi `go build` da solo produce un eseguibile
# che non contiene i programmi kernel.

.PHONY: all deps vmlinux generate build build-tui build-mock gui test lint check clean

all: build

# Dipendenze Go. Va eseguito una tantum e quando si aggiunge un import.
deps:
	go mod tidy

# Header BTF del kernel corrente, generato come header C.
# Perche' serve: espone le struct dei tipi kernel (struct inode, struct task_struct,
# struct super_block) necessarie a BPF_CORE_READ, e senza di esse zerotrust.c
# non compila. E' specifico della macchina, quindi e' in .gitignore e va
# rigenerato su ogni sistema.
#
# Nota su bpftool: va usata la versione compatibile con il kernel in esecuzione,
# altrimenti il dump puo' fallire o produrre tipi incoerenti. Su Ubuntu il pacchetto
# linux-tools-$(uname -r) fornisce la versione giusta.
bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Sottoscritto, non semplice: `make vmlinux` quando il file esiste gia' dice
# "up to date" senza fare nulla, e `generate` non dipenderebbe dal file.
vmlinux: bpf/vmlinux.h

# bpf2go: compila zerotrust.c con clang e genera bpf/shield_*_bpfel.{go,o}.
# Il flag del go:generate e' in bpf/gen.go.
generate: bpf/vmlinux.h
	go generate ./bpf/...

# -o specifica la directory: il binario va in bin/ per non sporcare la root del repo.
build: generate build-tui
	go build -o bin/zt-shield ./cmd/zt-shield

# TUI: pura Go, nessuna toolchain eBPF. Compila anche senza kernel/BTF.
build-tui:
	go build -o bin/zt-tui ./cmd/zt-tui

# Mock: finto demone per verificare la TUI senza root/eBPF (dati inventati).
# Uso sicuro ovunque: ./bin/zt-mockd & ./bin/zt-tui
build-mock:
	go build -o bin/zt-mockd ./cmd/zt-mockd

# GUI desktop (Wails, stile macOS). Richiede: wails CLI, Node,
# libgtk-3-dev + libwebkit2gtk-4.1-dev (Ubuntu 24.04: tag webkit2_41).
# Lancia: ./zt-gui/build/bin/zt-gui (con demone o mock attivi).
gui:
	cd zt-gui && wails build -tags webkit2_41

# Test: solo i pacchetti con logica testabile, quindi config.
# Nessun test richiede root o eBPF: per quello c'è TESTING.md.
test:
	go test ./internal/...

lint:
	go vet ./...
	gofmt -l .

# Gate completo: prerequisiti + build + test. Uso: `make check` prima di installare.
check: lint test build
	bash scripts/check_prereqs.sh

# clean: rimuove anche i .o generati, non solo i .go, perche' bpf2go li ricrea
# comunque e occupano un megabyte.
clean:
	rm -rf bin bpf/shield_*.go bpf/shield_*.o
