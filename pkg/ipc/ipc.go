// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package ipc espone stato ed eventi del demone alle UI (TUI/GUI) via Unix socket.
//
// Il demone gira root (eBPF), le UI girano come utente: il socket e' il confine.
// Protocollo: JSON delimitato da newline. Alla connessione il server invia prima
// una riga `status`, poi una riga `event` per ogni evento di audit.
// Solo lettura per ora: le azioni privilegiate (cambio mode) restano via config +
// restart + polkit in futuro, non via socket senza auth.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SocketPath: percorso fisso del demone vero (/run, serve root per crearlo).
// Override per test locali senza root: ZT_SOCKET=/tmp/zt-shield.sock
// (usato da mockd e TUI; il demone root ignora l'override e resta su /run).
var SocketPath = socketPath()

func socketPath() string {
	if p := os.Getenv("ZT_SOCKET"); p != "" {
		return p
	}
	return "/run/zt-shield/api.sock"
}

// RuleSummary: una regola in forma leggibile per le UI (niente inode qui).
type RuleSummary struct {
	Name  string   `json:"name"`
	Paths []string `json:"paths"`
	Allow []string `json:"allow"`
}

// SourceStat: una sorgente droppata da XDP, per il radar delle UI.
// Total = Poison+Subnet. LastSeen wall-clock del demone (ktime kernel non
// convertibile direttamente: il demone timestampa quando vede crescere i contatori).
type SourceStat struct {
	IP       string `json:"ip"`
	Poison   uint32 `json:"poison"`
	Subnet   uint32 `json:"subnet"`
	Total    uint32 `json:"total"`
	LastSeen string `json:"last_seen"`
}

// CanaryAlert: trip esca o massa rilevati dal watcher fanotify.
// Action: "killed" (enforce, PID terminato) o "alert" (loggato e basta).
type CanaryAlert struct {
	Type   string `json:"-"`
	Time   string `json:"time"`
	Action string `json:"action"`
	PID    int    `json:"pid"`
	Comm   string `json:"comm,omitempty"`
	Exe    string `json:"exe,omitempty"`
	Path   string `json:"path,omitempty"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// VpnStatus: kill-switch configurato + tunnel su o giù (verifica interfaccia).
// Up=false con Enabled=true = scoperto: la UI lo mostra rosso.
type VpnStatus struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint,omitempty"`
	Tunnel   string `json:"tunnel,omitempty"`
	Up       bool   `json:"up"`
}

// Status: fotografia del demone. Inviata a ogni nuova connessione e su UpdateStatus.
type Status struct {
	Type           string        `json:"-"`
	Profile        string        `json:"profile"`
	Mode           string        `json:"mode"`
	Home           string        `json:"home"`
	HookLSM        bool          `json:"hook_lsm"`
	XDP            []string      `json:"xdp"`
	Protected      int           `json:"protected"`
	Allowed        int           `json:"allowed"`
	BlockPoisoning bool          `json:"block_poisoning"`
	BlockSubnets   []string      `json:"block_subnets"`
	Vpn            VpnStatus     `json:"vpn"`
	TopSources     []SourceStat  `json:"top_sources"`
	Rules          []RuleSummary `json:"rules"`
	Time           string        `json:"time"`
}

// WireEvent: un evento di audit serializzato (stessi campi del log JSON).
type WireEvent struct {
	Type   string `json:"-"`
	Time   string `json:"time"`
	Action string `json:"action"` // audit | blocked
	PID    uint32 `json:"pid"`
	Comm   string `json:"comm"`
	Exe    string `json:"exe,omitempty"`
	Rule   string `json:"rule"`
	Inode  uint64 `json:"inode"`
}

// envelope distingue i tipi sulla stessa connessione.
type envelope struct {
	Type string `json:"type"`
}

// Server: listener Unix + fan-out eventi ai subscriber connessi.
type Server struct {
	mu     sync.Mutex
	subs   map[chan []byte]struct{}
	status []byte // ultima riga status (già con \n)

	lis    net.Listener
	closed bool
}

// NewServer crea /run/zt-shield e apre il socket (permessi larghi di proposito:
// gli eventi rivelano pattern di accesso locali; su workstation personale va bene,
// su multiutente va ristretto — vedi nota in README/UI_RESEARCH).
func NewServer() (*Server, error) {
	dir := filepath.Dir(SocketPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("ipc mkdir: %w", err)
	}
	// Socket stale da crash precedente: rimuove, altrimenti Listen fallisce.
	_ = os.Remove(SocketPath)
	lis, err := net.Listen("unix", SocketPath)
	if err != nil {
		return nil, fmt.Errorf("ipc listen: %w", err)
	}
	// 0666: qualunque utente locale puo' leggere stato/eventi. Scrittura di
	// controllo non esiste in questo protocollo, quindi niente auth da fare.
	if err := os.Chmod(SocketPath, 0o666); err != nil {
		lis.Close()
		return nil, fmt.Errorf("ipc chmod: %w", err)
	}
	s := &Server{subs: map[chan []byte]struct{}{}, lis: lis}
	go s.accept()
	return s, nil
}

// UpdateStatus memorizza e ritrasmette lo stato ai nuovi client.
// I client già connessi ricevono la riga status come aggiornamento live.
func (s *Server) UpdateStatus(st Status) {
	st.Time = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.Marshal(st)
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	line := markType(raw, "status")
	s.mu.Lock()
	s.status = line
	for ch := range s.subs {
		select {
		case ch <- line:
		default:
			// Subscriber lento: salta, non blocca il demone. Il client TUI
			// ricarica lo stato al prossimo poll in ogni caso.
		}
	}
	s.mu.Unlock()
}

// Publish invia un evento a tutti i connessi (drop se pieni, mai blocco).
func (s *Server) Publish(ev WireEvent) {
	ev.Time = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.Marshal(ev)
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	line := markType(raw, "event")
	s.mu.Lock()
	for ch := range s.subs {
		select {
		case ch <- line:
		default:
		}
	}
	s.mu.Unlock()
}

// PublishCanary invia un alert canary a tutti i connessi (drop se pieni).
func (s *Server) PublishCanary(a CanaryAlert) {
	a.Time = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.Marshal(a)
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	line := markType(raw, "canary")
	s.mu.Lock()
	for ch := range s.subs {
		select {
		case ch <- line:
		default:
		}
	}
	s.mu.Unlock()
}

// Close chiude listener, connessioni e rimuove il socket.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	for ch := range s.subs {
		close(ch)
	}
	s.subs = map[chan []byte]struct{}{}
	s.mu.Unlock()
	s.lis.Close()
	_ = os.Remove(SocketPath)
}

func (s *Server) accept() {
	for {
		conn, err := s.lis.Accept()
		if err != nil {
			return // listener chiuso
		}
		go s.serve(conn)
	}
}

func (s *Server) serve(conn net.Conn) {
	defer conn.Close()
	ch := make(chan []byte, 128)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.subs[ch] = struct{}{}
	status := s.status
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}()
	w := bufio.NewWriter(conn)
	if len(status) > 0 {
		if _, err := w.Write(status); err != nil {
			return
		}
		if err := w.Flush(); err != nil {
			return
		}
	}
	for line := range ch {
		if _, err := w.Write(line); err != nil {
			return
		}
		if err := w.Flush(); err != nil {
			return
		}
	}
}

// markType aggiunge {"type":...} in testa senza rimarshal: sostituisce il primo '{'.
// Le struct non hanno campo type nel JSON, quindi l'iniezione e' sicura.
func markType(raw []byte, t string) []byte {
	out := make([]byte, 0, len(raw)+16)
	out = append(out, []byte(`{"type":"`+t+`",`)...)
	out = append(out, raw[1:]...)
	return out
}

// GetStatus diala, legge la prima riga e chiude. Errore se demone non attivo.
func GetStatus() (Status, error) {
	var st Status
	conn, err := net.DialTimeout("unix", SocketPath, 2*time.Second)
	if err != nil {
		return st, err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return st, err
	}
	// Rimuove l'envelope: decodifica in map e poi nella struct (type ignorato).
	if err := json.Unmarshal(line, &st); err != nil {
		return st, err
	}
	return st, nil
}

// Subscribe resta connesso e chiama fn per ogni evento (salta le altre righe).
// Ritorna alla cancellazione del contesto o a errore di rete.
func Subscribe(ctx context.Context, fn func(WireEvent)) error {
	return subscribeType(ctx, "event", func(raw []byte) {
		var ev WireEvent
		if err := json.Unmarshal(raw, &ev); err == nil {
			fn(ev)
		}
	})
}

// SubscribeCanary come Subscribe ma per gli alert canary (fanotify).
func SubscribeCanary(ctx context.Context, fn func(CanaryAlert)) error {
	return subscribeType(ctx, "canary", func(raw []byte) {
		var a CanaryAlert
		if err := json.Unmarshal(raw, &a); err == nil {
			fn(a)
		}
	})
}

func subscribeType(ctx context.Context, typ string, fn func(raw []byte)) error {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "unix", SocketPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var env envelope
		if err := json.Unmarshal(sc.Bytes(), &env); err != nil {
			continue
		}
		if env.Type != typ {
			continue
		}
		fn(sc.Bytes())
	}
	return sc.Err()
}
