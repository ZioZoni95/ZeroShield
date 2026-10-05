// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package netstat: snapshot delle socket TCP in LISTEN da /proc, con PID/exe.
//
// Perche' qui e non `ss`: zero dipendenze esterne, parsing puro Go, funziona
// anche in container minimi. Il demone (root) vede i processi di tutti;
// da utente vedi solo i tuoi (kernel filtra i readlink altrui).
// Solo TCP LISTEN: e' cio' che espone superficie ("chi puo' parlarmi?").
// UDP e' connectionless: niente stato, fuori da questo snapshot.
package netstat

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Entry: una porta in ascolto con proprietario best-effort.
type Entry struct {
	Proto string `json:"proto"` // tcp / tcp6
	Addr  string `json:"addr"`
	Port  uint16 `json:"port"`
	PID   int    `json:"pid,omitempty"`
	Exe   string `json:"exe,omitempty"`
}

// Listening fotografa /proc/net/tcp e tcp6 in stato LISTEN (0A).
func Listening() []Entry {
	var out []Entry
	inodes := map[string][]int{} // "socket:[ino]" -> pid (raccolto dopo)
	out = append(out, scanProto("/proc/net/tcp", "tcp")...)
	out = append(out, scanProto("/proc/net/tcp6", "tcp6")...)
	if len(out) == 0 {
		return out
	}
	// Mappa inode->pid dai fd di tutti i processi visibili.
	pids, _ := filepath.Glob("/proc/[0-9]*")
	for _, p := range pids {
		pid, err := strconv.Atoi(filepath.Base(p))
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(p, "fd"))
		if err != nil {
			continue // processo altrui o uscito: normale
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(p, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino := link[len("socket:[") : len(link)-1]
			inodes[ino] = append(inodes[ino], pid)
		}
	}
	for i, e := range out {
		if pids := inodes[e.ino]; len(pids) > 0 {
			out[i].PID = pids[0]
			if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pids[0])); err == nil {
				out[i].Exe = exe
			}
		}
	}
	return out
}

// scanProto parsa una tabella /proc/net/{tcp,tcp6} tenendo solo LISTEN.
// Formato riga: sl local rem st ... inode. IP esadecimale network order
// (per v6 con word da 32 bit invertite: conversione standard).
func scanProto(path, proto string) []scanned {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []scanned
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 10 || f[3] != "0A" {
			continue // solo LISTEN
		}
		addr, port, ok := splitAddr(f[1], proto == "tcp6")
		if !ok {
			continue
		}
		out = append(out, scanned{Entry: Entry{Proto: proto, Addr: addr, Port: port}, ino: f[9]})
	}
	return out
}

type scanned struct {
	Entry
	ino string
}

func splitAddr(s string, v6 bool) (string, uint16, bool) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, false
	}
	if !v6 {
		// /proc scrive l'u32 little-endian in hex ("0100007F" = 127.0.0.1):
		// le coppie vanno lette al contrario.
		if len(ipHex) != 8 {
			return "", 0, false
		}
		var b [4]byte
		for i := 0; i < 4; i++ {
			n, err := strconv.ParseUint(ipHex[i*2:i*2+2], 16, 8)
			if err != nil {
				return "", 0, false
			}
			b[3-i] = byte(n)
		}
		return net.IPv4(b[0], b[1], b[2], b[3]).String(), uint16(port), true
	}
	if len(ipHex) != 32 {
		return "", 0, false
	}
	// /proc scrive ogni word32 little-endian: va ribaltata a gruppi di 8 hex.
	var b [16]byte
	for i := 0; i < 4; i++ {
		w, err := strconv.ParseUint(ipHex[i*8:i*8+8], 16, 32)
		if err != nil {
			return "", 0, false
		}
		b[i*4] = byte(w)
		b[i*4+1] = byte(w >> 8)
		b[i*4+2] = byte(w >> 16)
		b[i*4+3] = byte(w >> 24)
	}
	return net.IP(b[:]).String(), uint16(port), true
}
