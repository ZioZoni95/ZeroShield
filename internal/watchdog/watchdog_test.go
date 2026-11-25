// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package watchdog

import (
	"strings"
	"testing"
	"time"
)

func TestInterval(t *testing.T) {
	t.Setenv("WATCHDOG_USEC", "30000000")
	if got := Interval(); got != 15*time.Second {
		t.Fatalf("WatchdogSec=30 -> ping ogni %s, atteso 15s", got)
	}
	t.Setenv("WATCHDOG_USEC", "")
	if got := Interval(); got != 0 {
		t.Fatalf("senza watchdog atteso 0, ottenuto %s", got)
	}
}

// Un orologio finto che avanza solo quando glielo dici, come l'orologio monotono: una sospensione non lo fa avanzare.
type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func TestLivenessCountsOnlyElapsedTime(t *testing.T) {
	c := &fakeClock{t: time.Now()}
	l := newLiveness(c.now)
	if l.Since() != 0 {
		t.Fatalf("appena creato: atteso 0, trovato %v", l.Since())
	}
	c.advance(20 * time.Second)
	if got := l.Since(); got != 20*time.Second {
		t.Errorf("dopo 20s: %v", got)
	}
	l.Touch()
	if l.Since() != 0 {
		t.Errorf("dopo Touch: %v", l.Since())
	}
	c.advance(95 * time.Second)
	if l.Since() <= 90*time.Second {
		t.Errorf("un rescan davvero fermo da 95s deve superare i 90s: %v", l.Since())
	}
}

// Regressione 2026-11-23: l'ora di calendario salta di 10 minuti alla ripresa dalla sospensione, l'orologio monotono no.
// L'istante di riferimento deve portare la lettura monotona (String() la mostra come «m=+…»): se qualcuno lo
// riconverte da UnixNano o con Round(0) la perde e il demone torna a farsi uccidere dopo ogni sospensione.
func TestLivenessKeepsMonotonicReading(t *testing.T) {
	l := NewLiveness()
	if !strings.Contains(l.start.String(), "m=") {
		t.Fatalf("l'istante di riferimento non ha la lettura monotona: %s", l.start)
	}
	if l.Since() > time.Second {
		t.Errorf("appena creata non deve risultare ferma: %v", l.Since())
	}
}
