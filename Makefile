.PHONY: all deps vmlinux generate build test clean

all: build

deps:
	go mod tidy

bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

vmlinux: bpf/vmlinux.h

generate: bpf/vmlinux.h
	go generate ./bpf/...

build: generate
	go build -o bin/zt-shield ./cmd/zt-shield

test:
	go test ./internal/...

clean:
	rm -rf bin bpf/shield_*.go bpf/shield_*.o
