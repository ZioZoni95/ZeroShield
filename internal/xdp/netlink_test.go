// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package xdp

import (
	"context"
	"testing"
	"time"
)

// Senza privilegi non si puo' creare un'interfaccia per provocare un evento (lo si prova a mano in un network namespace,
// vedi docs/COLLAUDO_LSM_2026-11-05.md): qui si controlla che l'ascolto parta, non perda il controllo di ctx e si fermi
// chiudendo il canale.
func TestWatchLinksStartsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := WatchLinks(ctx)
	if err != nil {
		t.Skipf("netlink non disponibile qui: %v", err)
	}
	cancel()
	select {
	case _, open := <-ch:
		if open {
			// un evento di rete reale puo' arrivare: va bene, si aspetta la chiusura
			for range ch {
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("il canale non si e' chiuso dopo cancel (goroutine appesa)")
	}
}
