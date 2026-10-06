// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package priv: canale di controllo privilegiato del demone.
//
// Oggi pkg/ipc e' sola lettura per chiunque. Questo canale e' l'opposto:
// socket root-only (0600) + verifica peer-cred (SO_PEERCRED): solo uid 0
// esegue azioni. Le UI girano da utente e NON passano di qui finche' non
// arriva polkit (prossimo passo): il canale esiste per CLI root e servizio,
// con protocollo stabile per tutti i client futuri (TUI/GUI/CLI identici).
//
// Protocollo: una riga JSON {"action":"...","args":{...}} -> una riga JSON
// {"ok":bool,"data":...,"error":"..."}.
package priv

import (
	"fmt"
	"net"
	"os"
	"sync"
)

// SocketPath del canale di controllo. Override ZT_CONTROL per test senza root.
var SocketPath = socketPath()

func socketPath() string {
	if p := os.Getenv("ZT_CONTROL"); p != "" {
		return p
	}
	return "/run/zt-shield/control.sock"
}

// Request dal client, Response al client.
type Request struct {
	Action string         `json:"action"`
	Args   map[string]any `json:"args,omitempty"`
}

type Response struct {
	OK    bool   `json:"ok"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// Handler: name -> func(uid, args) (data, error).
type Server struct {
	mu       sync.Mutex
	handlers map[string]func(uid uint32, args map[string]any) (any, error)
	lis      net.Listener
	closed   bool
}

func NewServer() (*Server, error) {
	return listen(SocketPath, 0o600)
}

func listen(path string, mode os.FileMode) (*Server, error) {
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("priv listen: %w", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		lis.Close()
		return nil, err
	}
	s := &Server{handlers: map[string]func(uint32, map[string]any) (any, error){}, lis: lis}
	go s.accept()
	return s, nil
}

// On registra un'azione. Solo uid 0 la esegue (controllo in serve).
func (s *Server) On(action string, fn func(uid uint32, args map[string]any) (any, error)) {
	s.mu.Lock()
	s.handlers[action] = fn
	s.mu.Unlock()
}

func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	s.lis.Close()
	_ = os.Remove(SocketPath)
}
