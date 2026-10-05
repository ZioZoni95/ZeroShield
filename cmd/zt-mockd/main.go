// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// zt-mockd: finto demone per verificare la TUI in locale senza root/eBPF.
//
// Espone via socket IPC stato finto ed eventi sintetici periodici.
// La TUI non distingue mock da vero (stesso protocollo).
//
// SICURO ovunque: non carica programmi kernel, non tocca firewall/config,
// non legge i tuoi file. Solo dati inventati su socket locale.
//
// Uso (niente root, socket in /tmp via ZT_SOCKET):
//
//	ZT_SOCKET=/tmp/zt-shield.sock ./bin/zt-mockd &
//	ZT_SOCKET=/tmp/zt-shield.sock ./bin/zt-tui
//	# esci dalla TUI con q, poi: kill %1
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"zt-shield/pkg/ipc"
)

// script sintetico: cicla all'infinito, niente rete, niente file veri.
var script = []ipc.WireEvent{
	{Action: "audit", PID: 4211, Comm: "cat", Exe: "/usr/bin/cat", Rule: "cloud-creds", Inode: 9740993},
	{Action: "audit", PID: 4220, Comm: "python3", Exe: "/usr/bin/python3.12", Rule: "ssh-keys", Inode: 112345},
	{Action: "blocked", PID: 48921, Comm: "cat", Exe: "/usr/bin/cat", Rule: "cloud-creds", Inode: 9740993},
	{Action: "audit", PID: 5102, Comm: "chrome", Exe: "/opt/google/chrome/chrome", Rule: "browser-secrets", Inode: 778812},
	{Action: "blocked", PID: 5317, Comm: "ssh", Exe: "/tmp/ssh", Rule: "ssh-keys", Inode: 112345},
}

func main() {
	srv, err := ipc.NewServer()
	if err != nil {
		// Caso tipico: socket occupato dal demone vero o da altro mock.
		// Non forzare: due server sullo stesso path si pestano.
		log.Fatalf("mockd: %v (forse demone vero o altro mock attivo?)", err)
	}
	defer srv.Close()

	home := os.Getenv("HOME")
	if home == "" {
		home = "/home/utente"
	}
	srv.UpdateStatus(ipc.Status{
		Profile: "home", Mode: "audit", Home: home,
		HookLSM: true, XDP: []string{"enp0s3 (mock)"},
		Protected: 42, Allowed: 18,
		BlockPoisoning: true, BlockSubnets: []string{"192.168.100.0/24"},
		Vpn: ipc.VpnStatus{Enabled: true, Endpoint: "203.0.113.7:51820", Tunnel: "wg0", Up: false},
		Listening: []ipc.ListenEntry{
			{Proto: "tcp", Addr: "127.0.0.1", Port: 631, PID: 1234, Exe: "/usr/sbin/cupsd"},
			{Proto: "tcp", Addr: "0.0.0.0", Port: 8080, Exe: ""},
		},
		TopSources: []ipc.SourceStat{
			{IP: "192.168.100.7", Poison: 34, Subnet: 0, Total: 34, LastSeen: "2026-10-02T10:35:01Z"},
			{IP: "192.168.100.23", Poison: 0, Subnet: 128, Total: 128, LastSeen: "2026-10-02T10:35:00Z"},
			{IP: "10.201.50.99", Poison: 5, Subnet: 0, Total: 5, LastSeen: "2026-10-02T10:34:12Z"},
		},
		Rules: []ipc.RuleSummary{
			{Name: "ssh-keys", Paths: []string{".ssh/id_*"}, Allow: []string{"ssh", "ssh-add", "ssh-agent"}},
			{Name: "cloud-creds", Paths: []string{".kube/config", ".aws/credentials"}, Allow: []string{"kubectl", "helm"}},
			{Name: "dev-tokens", Paths: []string{".git-credentials", ".docker/config.json"}, Allow: []string{"git", "gh"}},
		},
	})
	fmt.Fprintln(os.Stderr, "mockd: socket attivo, eventi sintetici ogni 1.5s. Ctrl+C per fermare.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	// Canary finto ogni ~7s per vedere righe 🐤 e toast senza kernel.
	canaryTick := time.NewTicker(7 * time.Second)
	defer canaryTick.Stop()
	i := 0
	for {
		select {
		case <-ticker.C:
			srv.Publish(script[i%len(script)])
			i++
		case <-canaryTick.C:
			srv.PublishCanary(ipc.CanaryAlert{
				Action: "killed", PID: 6666, Exe: "/usr/bin/python3",
				Path: "/home/utente/Documents/.canary-accounts.xlsx",
				Kind: "write", Reason: "tocco esca canary (mock)",
			})
		case <-stop:
			fmt.Fprintln(os.Stderr, "mockd: stop.")
			return
		}
	}
}
