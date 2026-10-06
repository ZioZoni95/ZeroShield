# Copyright (c) 2026 ZioZoni95
# SPDX-License-Identifier: MIT
# Build di zt-shield.
#
# La catena e' obbligata: vmlinux.h -> bpf2go -> go build. Il .o eBPF viene
# incorporato nel binario Go, quindi `go build` da solo produce un eseguibile
# che non contiene i programmi kernel.

.PHONY: all deps vmlinux generate build build-tui build-mock build-probe probe gui gui-bin test test-root test-scripts lint check package package-gui clean

# Versione nei binari e nei pacchetti: dal tag git (v0.1.0 -> 0.1.0), altrimenti
# 0.0.0~dev+<commit> (il ~ ordina le dev prima di qualsiasi release in dpkg).
VERSION ?= $(shell v=$$(git describe --tags --exact-match 2>/dev/null); if [ -n "$$v" ]; then echo $${v#v}; else echo 0.0.0~dev+$$(git rev-parse --short HEAD 2>/dev/null || echo unknown); fi)
ARCH ?= $(shell go env GOARCH)
LDFLAGS := -s -w -X main.version=$(VERSION)
NFPM ?= go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0

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
# BPFTOOL sovrascrivibile: in CI (e su Ubuntu senza wrapper) il binario sta in
# /usr/lib/linux-tools/<versione>/bpftool. Es: make generate BPFTOOL=/percorso/bpftool
# Default: bpftool nel PATH, altrimenti il primo in /usr/lib/linux-tools (Ubuntu
# 24.04 non ha un pacchetto `bpftool`: lo porta linux-tools-generic).
BPFTOOL ?= $(shell command -v bpftool 2>/dev/null || ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1)

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Sottoscritto, non semplice: `make vmlinux` quando il file esiste gia' dice
# "up to date" senza fare nulla, e `generate` non dipenderebbe dal file.
vmlinux: bpf/vmlinux.h

# bpf2go: compila zerotrust.c con clang e genera bpf/shield_*_bpfel.{go,o}.
# Il flag del go:generate e' in bpf/gen.go.
generate: bpf/vmlinux.h
	go generate ./bpf/...

# -o specifica la directory: il binario va in bin/ per non sporcare la root del repo.
build: generate build-tui
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/zt-shield ./cmd/zt-shield

# TUI: pura Go, nessuna toolchain eBPF. Compila anche senza kernel/BTF.
build-tui:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/zt-tui ./cmd/zt-tui

# Probe: carica ogni programma eBPF da solo e prova XDP su loopback, senza
# avviare il demone. Primo passo su una macchina nuova (vedi docs/TEST_SANDBOX.md).
build-probe: generate
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/zt-probe ./cmd/zt-probe

probe: build-probe
	sudo ./bin/zt-probe -xdp-lo

# Mock: finto demone per verificare la TUI senza root/eBPF (dati inventati).
# Uso sicuro ovunque: ./bin/zt-mockd & ./bin/zt-tui
build-mock:
	go build -o bin/zt-mockd ./cmd/zt-mockd

# GUI desktop (Wails, stile macOS). Richiede: wails CLI, Node,
# libgtk-3-dev + libwebkit2gtk-4.1-dev (Ubuntu 24.04: tag webkit2_41).
# Lancia: ./zt-gui/build/bin/zt-gui (con demone o mock attivi).
gui:
	cd zt-gui && wails build -tags webkit2_41

# GUI senza CLI Wails: build "production" con go build, frontend con Vite.
# Richiede Node + libgtk-3-dev + libwebkit2gtk-4.1-dev. Usata dal pacchetto.
gui-bin:
	cd zt-gui/frontend && npm ci && npm run build
	cd zt-gui && go build -tags desktop,production,webkit2_41 -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o ../bin/zt-gui .

# Pacchetti .deb in dist/ (nfpm). Il demone include gli stub eBPF, quindi serve
# la toolchain di `make build`. Installazione: sudo apt install ./dist/zeroshield_*.deb
package: build build-probe build-mock
	mkdir -p dist
	VERSION="$(VERSION)" ARCH="$(ARCH)" $(NFPM) package --config packaging/nfpm.yaml --packager deb --target dist/

package-gui: gui-bin
	mkdir -p dist
	VERSION="$(VERSION)" ARCH="$(ARCH)" $(NFPM) package --config packaging/nfpm-gui.yaml --packager deb --target dist/

# Test: solo i pacchetti con logica testabile, quindi config.
# Nessun test richiede root o eBPF: per quello c'è TESTING.md.
test:
	go test ./internal/... ./pkg/...

# Script VPN: nm_vpn e proton con comandi finti (nessun privilegio), kill-switch in un
# network namespace usa e getta (serve root: non tocca la rete della macchina).
test-scripts:
	bash scripts/test_nm_vpn.sh
	bash scripts/test_proton.sh
	sudo bash scripts/test_killswitch.sh

# Test che richiedono root (fanotify reale del canary). In CI girano con sudo.
test-root:
	sudo -E env "PATH=$(PATH)" go test -count=1 -run Root -v ./internal/canary

lint:
	go vet ./...
	gofmt -l .

# Gate completo: prerequisiti + build + test. Uso: `make check` prima di installare.
check: lint test build
	bash scripts/check_prereqs.sh

# clean: rimuove anche i .o generati, non solo i .go, perche' bpf2go li ricrea
# comunque e occupano un megabyte.
clean:
	rm -rf bin dist bpf/shield_*.go bpf/shield_*.o
