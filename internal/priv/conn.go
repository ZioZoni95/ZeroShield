// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package priv

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func dirOf(p string) string { return filepath.Dir(p) }

func (s *Server) accept() {
	for {
		conn, err := s.lis.Accept()
		if err != nil {
			return
		}
		go s.serve(conn)
	}
}

// serve: una richiesta per riga, auth via SO_PEERCRED (uid+pid reali del peer,
// non falsificabili: li dice il kernel, non il client).
func (s *Server) serve(conn net.Conn) {
	defer conn.Close()
	uid, pid := peerCred(conn)
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	w := bufio.NewWriter(conn)
	for sc.Scan() {
		var req Request
		resp := Response{OK: true}
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			resp = Response{Error: "richiesta non JSON"}
		} else {
			s.mu.Lock()
			fn := s.handlers[req.Action]
			s.mu.Unlock()
			if fn == nil {
				resp = Response{Error: "azione sconosciuta: " + req.Action}
			} else if err := authorize(uid, pid); err != nil {
				// Root passa diretto; utente via polkit; senza dbus/policy:
				// negato esplicito, mai silenzio.
				resp = Response{Error: err.Error()}
			} else if data, err := fn(uid, req.Args); err != nil {
				resp = Response{Error: err.Error()}
			} else {
				resp = Response{OK: true, Data: data}
			}
		}
		raw, _ := json.Marshal(resp)
		raw = append(raw, '\n')
		if _, err := w.Write(raw); err != nil {
			return
		}
		if err := w.Flush(); err != nil {
			return
		}
	}
}

// peerCred legge uid+pid dal socket Unix (Linux SO_PEERCRED).
// 0xFFFFFFFF = non verificabile: authorize nega comunque i non-root.
func peerCred(conn net.Conn) (uint32, uint32) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0xFFFFFFFF, 0
	}
	f, err := uc.File()
	if err != nil {
		return 0xFFFFFFFF, 0
	}
	defer f.Close()
	cred, err := unix.GetsockoptUcred(int(f.Fd()), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return 0xFFFFFFFF, 0
	}
	if cred.Pid < 0 {
		return cred.Uid, 0
	}
	return cred.Uid, uint32(cred.Pid)
}

// Call invia un'azione e attende la risposta. Client condiviso per CLI/TUI/GUI:
// stesso canale per tutte le UI, come da architettura obiettivo.
func Call(action string, args map[string]any) (any, error) {
	conn, err := net.DialTimeout("unix", SocketPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	raw, _ := json.Marshal(Request{Action: action, Args: args})
	raw = append(raw, '\n')
	if _, err := conn.Write(raw); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Data, nil
}

// Ping verifica che il canale risponda (action registrata dal demone).
func Ping() (any, error) { return Call("ping", nil) }
