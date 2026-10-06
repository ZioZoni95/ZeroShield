// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package netstat: snapshot delle socket TCP in LISTEN e UDP in ascolto da /proc,
// con PID/exe del proprietario.
//
// Perche' qui e non `ss`: zero dipendenze esterne, parsing puro Go, funziona
// anche in container minimi. Il demone (root) vede i processi di tutti; da utente
// vedi solo i tuoi (il kernel filtra i readlink altrui). Per questo il socket IPC
// che pubblica questo dato e' di proprieta' dell'utente protetto (pkg/ipc).
//
// UDP incluso perche' le superfici che ZeroShield difende sono proprio UDP:
// mDNS (5353) e LLMNR (5355). Un socket UDP "in ascolto" e' uno bound senza peer:
// stato 07 e indirizzo remoto tutto zero.
package netstat

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Entry: una porta in ascolto con proprietario best-effort.
type Entry struct {
	Proto string `json:"proto"` // tcp, tcp6, udp, udp6
	Addr  string `json:"addr"`
	Port  uint16 `json:"port"`
	PID   int    `json:"pid,omitempty"`
	Exe   string `json:"exe,omitempty"`
}

// Listening fotografa /proc e restituisce al massimo max voci, ordinate (proto,
// porta, indirizzo) cosi' le UI non sfarfallano, piu' il totale trovato. Se
// total > len(entries) la lista e' stata troncata: chi mostra deve dirlo.
//
// Il tetto serve perche' ogni voce viaggia nello status a ogni client: un host
// con migliaia di socket (Docker, server) supererebbe il buffer di riga del client
// IPC (1 MiB) e l'interfaccia smetterebbe di aggiornarsi.
func Listening(max int) (entries []Entry, total int) {
	return listening("/proc", max)
}

func listening(root string, max int) ([]Entry, int) {
	var found []scanned
	found = append(found, scanProto(filepath.Join(root, "net/tcp"), "tcp", false)...)
	found = append(found, scanProto(filepath.Join(root, "net/tcp6"), "tcp6", false)...)
	found = append(found, scanProto(filepath.Join(root, "net/udp"), "udp", true)...)
	found = append(found, scanProto(filepath.Join(root, "net/udp6"), "udp6", true)...)
	if len(found) == 0 {
		return nil, 0
	}
	sort.Slice(found, func(i, j int) bool {
		a, b := found[i].Entry, found[j].Entry
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Addr < b.Addr
	})
	total := len(found)
	if max > 0 && len(found) > max {
		found = found[:max]
	}

	// Mappa inode->pid dai fd dei processi visibili. Con piu' processi sullo stesso
	// socket (fork) vince il PID piu' basso: Glob ordina in modo lessicografico
	// ("1000" < "999") e il "primo" cambiava da un giro all'altro.
	owners := inodeOwners(root)
	out := make([]Entry, 0, len(found))
	for _, s := range found {
		e := s.Entry
		if pid, ok := owners[s.ino]; ok {
			e.PID = pid
			if exe, err := os.Readlink(filepath.Join(root, strconv.Itoa(pid), "exe")); err == nil {
				e.Exe = exe
			}
		}
		out = append(out, e)
	}
	return out, total
}

func inodeOwners(root string) map[string]int {
	owners := map[string]int{}
	dirs, _ := filepath.Glob(filepath.Join(root, "[0-9]*"))
	for _, p := range dirs {
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
			if err != nil || !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
				continue
			}
			ino := link[len("socket:[") : len(link)-1]
			if cur, ok := owners[ino]; !ok || pid < cur {
				owners[ino] = pid
			}
		}
	}
	return owners
}

type scanned struct {
	Entry
	ino string
}

// scanProto parsa una tabella /proc/net/{tcp,tcp6,udp,udp6}.
// Formato riga: sl local rem st ... inode. TCP: tiene solo LISTEN (0A).
// UDP: tiene i socket bound senza peer (stato 07 e remoto tutto zero).
// IP esadecimale con word da 32 bit little-endian (vedi splitAddr).
func scanProto(path, proto string, udp bool) []scanned {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil
	}
	var out []scanned
	for _, line := range lines[1:] { // la prima riga e' l'intestazione
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		if udp {
			if f[3] != "07" || strings.Trim(f[2], "0:") != "" {
				continue // UDP connesso a un peer: non e' "in ascolto"
			}
		} else if f[3] != "0A" {
			continue
		}
		addr, port, ok := splitAddr(f[1], strings.HasSuffix(proto, "6"))
		if !ok {
			continue
		}
		out = append(out, scanned{Entry: Entry{Proto: proto, Addr: addr, Port: port}, ino: f[9]})
	}
	return out
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
