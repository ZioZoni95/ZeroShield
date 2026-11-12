// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package audit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"zt-shield/pkg/ipc"
)

// EgressRaw ha lo stesso layout di egress_event in zerotrust.c:
//
//	pid@0 (4) | comm@4 (16) | rule@20 (4) | family@24 (2) | port@26 (2) | addr@28 (16) | pad@44 (4) | exe_ino@48 (8) | exe_dev@56 (8) = 64 byte
//
// La porta arriva in network byte order e l'indirizzo e' grezzo (IPv4 nei primi 4 byte).
type EgressRaw struct {
	PID    uint32
	Comm   [16]byte
	Rule   uint32
	Family uint16
	Port   uint16
	Addr   [16]byte
	ExeIno uint64
	ExeDev uint64
}

const (
	afInet  = 2
	afInet6 = 10
)

// DecodeEgress legge un egress_event dal payload grezzo del ring buffer.
func DecodeEgress(raw []byte) (EgressRaw, bool) {
	var e EgressRaw
	if len(raw) < 64 {
		return e, false
	}
	e.PID = binary.LittleEndian.Uint32(raw[0:4])
	copy(e.Comm[:], raw[4:20])
	e.Rule = binary.LittleEndian.Uint32(raw[20:24])
	e.Family = binary.LittleEndian.Uint16(raw[24:26])
	e.Port = binary.BigEndian.Uint16(raw[26:28]) // arriva in network order: la si porta in ordine normale
	copy(e.Addr[:], raw[28:44])
	e.ExeIno = binary.LittleEndian.Uint64(raw[48:56])
	e.ExeDev = binary.LittleEndian.Uint64(raw[56:64])
	return e, true
}

// IP restituisce l'indirizzo di destinazione (nil se la famiglia non e' IP).
func (e EgressRaw) IP() net.IP {
	switch e.Family {
	case afInet:
		return net.IPv4(e.Addr[0], e.Addr[1], e.Addr[2], e.Addr[3])
	case afInet6:
		ip := make(net.IP, 16)
		copy(ip, e.Addr[:])
		return ip
	}
	return nil
}

// Local dice se la destinazione e' la macchina stessa. Su Linux connettersi a 0.0.0.0 (o a ::) significa connettersi a
// localhost: e' traffico locale come il loopback, non rete locale (visto dal vivo: 19 eventi verso 0.0.0.0:45233 di un
// port-forward di kubectl/k9s segnati «lan»). Questi eventi non si segnalano.
func Local(ip net.IP) bool {
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// Scope classifica la destinazione: "lan" (rete locale, indirizzi privati e link-local) o "internet".
func Scope(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return "lan"
	}
	return "internet"
}

// EgressEvent: una connessione in uscita nuova (programma + destinazione mai viste), da un processo che ha appena letto un segreto.
type EgressEvent struct {
	PID   uint32
	Comm  string
	Exe   string
	Rule  string
	Dest  string // "1.2.3.4:443" o "[2001:db8::1]:443"
	Scope string // lan | internet
}

// firstSeen ricorda le coppie (programma, destinazione) gia' viste: si segnala solo la PRIMA volta, altrimenti ogni
// `kubectl get pods` riempirebbe il registro. Si svuota oltre il tetto (la prima volta dopo lo svuotamento rispunta).
type firstSeen struct {
	mu   sync.Mutex
	seen map[string]struct{}
	max  int
}

func newFirstSeen(max int) *firstSeen { return &firstSeen{seen: map[string]struct{}{}, max: max} }

// Add dice se la chiave e' nuova (e la registra).
func (f *firstSeen) Add(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.seen[key]; ok {
		return false
	}
	if len(f.seen) >= f.max {
		f.seen = map[string]struct{}{}
	}
	f.seen[key] = struct{}{}
	return true
}

// RunEgress consuma il ring buffer delle connessioni in uscita. Segnala solo le coppie (exe, destinazione) nuove, con un
// tetto di eventi al secondo. Ritorna quando il reader viene chiuso.
func RunEgress(rd *ringbuf.Reader, ruleName func(uint32) string, resolve ExeResolver, emit func(EgressEvent)) {
	seen := newFirstSeen(8192)
	const maxPerSec = 20
	windowStart := time.Now()
	inWindow := 0
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		raw, ok := DecodeEgress(rec.RawSample)
		if !ok {
			continue
		}
		ip := raw.IP()
		if ip == nil || Local(ip) {
			continue
		}
		comm := ipc.SafeText(string(bytes.TrimRight(raw.Comm[:], "\x00")))
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", raw.PID))
		if exe == "" && resolve != nil && raw.ExeIno != 0 {
			if p, ok := resolve(raw.ExeDev, raw.ExeIno, comm); ok {
				exe = p
			}
		}
		exe = ipc.SafeText(exe)
		dest := net.JoinHostPort(ip.String(), fmt.Sprint(raw.Port))
		key := exe + "|" + comm + "|" + dest
		if exe == "" {
			key = fmt.Sprintf("ino%d|%s|%s", raw.ExeIno, comm, dest)
		}
		if !seen.Add(key) {
			continue
		}
		now := time.Now()
		if now.Sub(windowStart) >= time.Second {
			windowStart, inWindow = now, 0
		}
		if inWindow >= maxPerSec {
			continue
		}
		inWindow++
		ev := EgressEvent{PID: raw.PID, Comm: comm, Exe: exe, Rule: ruleName(raw.Rule), Dest: dest, Scope: Scope(ip)}
		if emit != nil {
			emit(ev)
		}
		log.Printf("📤 [USCITA] regola=%s PID=%d comm='%s' exe=%s → %s (%s, nuova destinazione)", ev.Rule, ev.PID, comm, exe, dest, ev.Scope)
	}
}
