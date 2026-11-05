// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package audit

import (
	"encoding/binary"
	"testing"
)

// payload di 40 byte con layout C: pid@0, comm@4(16), rule@20, ino@24(8), action@32, pad@36.
func sampleRaw() []byte {
	raw := make([]byte, 40)
	binary.LittleEndian.PutUint32(raw[0:4], 48921)
	copy(raw[4:20], "cat\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	binary.LittleEndian.PutUint32(raw[20:24], 2)
	binary.LittleEndian.PutUint64(raw[24:32], 9740993)
	binary.LittleEndian.PutUint32(raw[32:36], 1)
	return raw
}

func TestDecodeEventLayout(t *testing.T) {
	ev, ok := decodeEvent(sampleRaw())
	if !ok {
		t.Fatal("payload valido scartato")
	}
	if ev.PID != 48921 || ev.Rule != 2 || ev.Inode != 9740993 || ev.Action != 1 {
		t.Errorf("campi sfasati (layout C/Go divergente?): %+v", ev)
	}
}

func TestDecodeEventShort(t *testing.T) {
	if _, ok := decodeEvent(make([]byte, 39)); ok {
		t.Error("payload corto accettato: rischio lettura oltre i dati")
	}
	if _, ok := decodeEvent(nil); ok {
		t.Error("payload nil accettato")
	}
}

func TestDecodeEventWithExeIdentity(t *testing.T) {
	raw := append(sampleRaw(), make([]byte, 16)...)
	binary.LittleEndian.PutUint64(raw[40:48], 1234567)
	binary.LittleEndian.PutUint64(raw[48:56], 0x10301)
	ev, ok := decodeEvent(raw)
	if !ok || ev.ExeIno != 1234567 || ev.ExeDev != 0x10301 || ev.Inode != 9740993 {
		t.Fatalf("identita' del binario non letta: %+v", ev)
	}
	// Il payload vecchio (40 byte) resta valido, senza identita'.
	old, ok := decodeEvent(sampleRaw())
	if !ok || old.ExeIno != 0 || old.ExeDev != 0 {
		t.Fatalf("payload a 40 byte: %+v", old)
	}
}

func TestResolveExeFallback(t *testing.T) {
	res := func(dev, ino uint64, comm string) (string, bool) {
		if dev == 7 && ino == 42 {
			return "/usr/bin/" + comm, true
		}
		return "", false
	}
	// /proc ha risposto: vale lui, l'indice non si consulta.
	if got := resolveExeFallback("/proc/risposta", Event{ExeIno: 42, ExeDev: 7}, "cat", res); got != "/proc/risposta" {
		t.Errorf("deve vincere /proc: %q", got)
	}
	// /proc vuoto (processo uscito): si usa l'identita' del kernel.
	if got := resolveExeFallback("", Event{ExeIno: 42, ExeDev: 7}, "cat", res); got != "/usr/bin/cat" {
		t.Errorf("fallback sull'indice: %q", got)
	}
	// Identita' sconosciuta o assente: vuoto, mai un percorso inventato.
	if got := resolveExeFallback("", Event{ExeIno: 99, ExeDev: 7}, "cat", res); got != "" {
		t.Errorf("inode sconosciuto: %q", got)
	}
	if got := resolveExeFallback("", Event{}, "cat", res); got != "" {
		t.Errorf("senza identita': %q", got)
	}
	if got := resolveExeFallback("", Event{ExeIno: 42, ExeDev: 7}, "cat", nil); got != "" {
		t.Errorf("senza resolver: %q", got)
	}
}
