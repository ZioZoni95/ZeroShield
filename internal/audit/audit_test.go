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
