// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package audit

import (
	"encoding/binary"
	"net"
	"testing"
)

func egressRaw(family uint16, port uint16, addr []byte) []byte {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b[0:], 4242)
	copy(b[4:], "kubectl")
	binary.LittleEndian.PutUint32(b[20:], 2)
	binary.LittleEndian.PutUint16(b[24:], family)
	binary.BigEndian.PutUint16(b[26:], port) // il kernel copia la porta in network order
	copy(b[28:], addr)
	binary.LittleEndian.PutUint64(b[48:], 99)
	binary.LittleEndian.PutUint64(b[56:], 7)
	return b
}

func TestDecodeEgressIPv4(t *testing.T) {
	e, ok := DecodeEgress(egressRaw(afInet, 443, []byte{93, 184, 216, 34}))
	if !ok || e.PID != 4242 || e.Rule != 2 || e.Port != 443 || e.ExeIno != 99 || e.ExeDev != 7 {
		t.Fatalf("decodifica errata: %+v ok=%v", e, ok)
	}
	if got := e.IP().String(); got != "93.184.216.34" {
		t.Errorf("IP = %s", got)
	}
}

func TestDecodeEgressIPv6AndShort(t *testing.T) {
	v6 := net.ParseIP("2001:db8::1")
	e, ok := DecodeEgress(egressRaw(afInet6, 8443, v6.To16()))
	if !ok || e.IP().String() != "2001:db8::1" || e.Port != 8443 {
		t.Fatalf("v6: %+v", e)
	}
	if _, ok := DecodeEgress(make([]byte, 63)); ok {
		t.Error("un payload corto va scartato")
	}
	if e, _ := DecodeEgress(egressRaw(1, 0, nil)); e.IP() != nil {
		t.Error("una famiglia diversa da IP non ha indirizzo")
	}
}

func TestLocalIsNotReported(t *testing.T) {
	for ip, want := range map[string]bool{
		"0.0.0.0":          true, // connect() verso 0.0.0.0 = localhost
		"::":               true,
		"127.0.0.1":        true,
		"::1":              true,
		"::ffff:0.0.0.0":   true,
		"::ffff:127.0.0.1": true,
		"10.157.40.57":     false, // rete locale vera: si segnala
		"93.184.216.34":    false,
		"2606:4700::1":     false,
		"169.254.169.254":  false,
	} {
		if got := Local(net.ParseIP(ip)); got != want {
			t.Errorf("Local(%s) = %v, atteso %v", ip, got, want)
		}
	}
	if Local(nil) {
		t.Error("un indirizzo assente non è locale")
	}
}

func TestScope(t *testing.T) {
	for ip, want := range map[string]string{
		"10.209.4.62":   "lan",
		"192.168.1.5":   "lan",
		"172.17.0.2":    "lan",
		"169.254.1.1":   "lan",
		"fe80::1":       "lan",
		"fd00::1":       "lan",
		"93.184.216.34": "internet",
		"2606:4700::1":  "internet",
	} {
		if got := Scope(net.ParseIP(ip)); got != want {
			t.Errorf("%s: %q, atteso %q", ip, got, want)
		}
	}
}

func TestFirstSeenReportsOnlyNewPairs(t *testing.T) {
	f := newFirstSeen(3)
	if !f.Add("a") || f.Add("a") {
		t.Fatal("la stessa coppia si segnala una volta sola")
	}
	f.Add("b")
	f.Add("c")
	// oltre il tetto si svuota: la prima voce rispunta come nuova, senza crescere senza limite
	if !f.Add("d") {
		t.Error("una voce nuova va segnalata")
	}
	if len(f.seen) > 3 {
		t.Errorf("tetto superato: %d", len(f.seen))
	}
}
