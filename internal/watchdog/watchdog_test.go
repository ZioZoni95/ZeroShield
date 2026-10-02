// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package watchdog

import (
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
