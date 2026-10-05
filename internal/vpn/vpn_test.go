// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"zt-shield/internal/config"
)

type fake struct {
	nftOK     bool
	handshake string
	calls     []string
}

func (f *fake) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+join(args))
	switch name {
	case "nft":
		if f.nftOK {
			return []byte("table inet zt-killswitch {}"), nil
		}
		return nil, errors.New("No such file or directory")
	case "wg":
		return []byte(f.handshake), nil
	}
	return nil, errors.New("comando inatteso")
}

func join(a []string) string {
	s := ""
	for i, x := range a {
		if i > 0 {
			s += " "
		}
		s += x
	}
	return s
}

func cfg() config.VpnConfig {
	return config.VpnConfig{Enabled: true, Endpoint: "203.0.113.7:51820", Tunnel: "wg0"}
}

func TestCheckDisabledRunsNothing(t *testing.T) {
	f := &fake{}
	st := Check(config.VpnConfig{}, f.run)
	if st.Enabled || st.Up || st.KillSwitch || st.HandshakeAge != -1 {
		t.Errorf("vpn spenta: stato inatteso %+v", st)
	}
	if len(f.calls) != 0 {
		t.Errorf("con la vpn spenta non si esegue niente: %v", f.calls)
	}
}

func TestCheckCombinations(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0)
	old, oldUp := now, ifaceUp
	now = func() time.Time { return fixed }
	defer func() { now, ifaceUp = old, oldUp }()

	cases := []struct {
		name      string
		up, ks    bool
		hs        string
		wantAge   int
		wantCalls int
	}{
		{"protetto: su + kill-switch + handshake recente", true, true, "KEY\t1699999950\n", 50, 2},
		{"su ma senza kill-switch", true, false, "KEY\t1699999950\n", 50, 2},
		{"giu' con kill-switch: offline ma non in chiaro", false, true, "", -1, 1},
		{"giu' senza kill-switch: in chiaro", false, false, "", -1, 1},
		{"su, mai un handshake", true, true, "KEY\t0\n", -1, 2},
	}
	for _, c := range cases {
		ifaceUp = func(string) bool { return c.up }
		f := &fake{nftOK: c.ks, handshake: c.hs}
		st := Check(cfg(), f.run)
		if st.Up != c.up || st.KillSwitch != c.ks || st.HandshakeAge != c.wantAge {
			t.Errorf("%s: %+v", c.name, st)
		}
		if len(f.calls) != c.wantCalls {
			t.Errorf("%s: %d comandi eseguiti (%v), attesi %d: wg non va interrogato a tunnel giu'", c.name, len(f.calls), f.calls, c.wantCalls)
		}
	}
}

func TestMissingToolsAreNeverGreen(t *testing.T) {
	old := ifaceUp
	ifaceUp = func(string) bool { return true }
	defer func() { ifaceUp = old }()
	st := Check(cfg(), func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("executable file not found")
	})
	if st.KillSwitch {
		t.Error("senza nft il kill-switch non puo' risultare attivo")
	}
	if st.HandshakeAge != -1 {
		t.Error("senza wg l'handshake e' sconosciuto, non recente")
	}
}

func TestHandshakeAge(t *testing.T) {
	now := time.Unix(1000, 0)
	cases := map[string]int{
		"A\t900\nB\t990\n": 10, // vince il piu' recente
		"A\t0\n":           -1,
		"":                 -1,
		"garbage\n":        -1,
		"A\tnotanumber\n":  -1,
		"A\t2000\n":        0, // orologio indietro: mai eta' negativa
		"A\t500\nB\t0\n":   500,
	}
	for in, want := range cases {
		if got := handshakeAge(in, now); got != want {
			t.Errorf("handshakeAge(%q) = %d, atteso %d", in, got, want)
		}
	}
}
