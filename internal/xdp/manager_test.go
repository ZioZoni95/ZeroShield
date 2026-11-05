// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package xdp

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"zt-shield/internal/netif"
)

type fakeLink struct{ closed bool }

func (f *fakeLink) Close() error { f.closed = true; return nil }

// world: un finto sistema di interfacce che i test modificano tra una Sync e l'altra.
type world struct {
	ifs      map[string]int // nome -> indice (assente = non esiste)
	kinds    map[string]string
	up       map[string]bool
	def      string
	links    map[int]*fakeLink
	attaches int
	failFor  map[int]bool
}

func newWorld() *world {
	return &world{ifs: map[string]int{}, kinds: map[string]string{}, up: map[string]bool{}, links: map[int]*fakeLink{}, failFor: map[int]bool{}}
}
func (w *world) add(name, kind string, idx int, up bool) {
	w.ifs[name], w.kinds[name], w.up[name] = idx, kind, up
}

func (w *world) manager(custom string) (*Manager, *[]string) {
	m := NewManager(nil, custom)
	var logs []string
	m.attachFn = func(_ *ebpf.Program, idx int) (io.Closer, error) {
		w.attaches++
		if w.failFor[idx] {
			return nil, errors.New("device or resource busy")
		}
		l := &fakeLink{}
		w.links[idx] = l
		return l, nil
	}
	m.ifaceFn = func(n string) (*net.Interface, error) {
		if idx, ok := w.ifs[n]; ok {
			return &net.Interface{Name: n, Index: idx}, nil
		}
		return nil, errors.New("no such interface")
	}
	m.listFn = func() []netif.Info {
		var out []netif.Info
		for n := range w.ifs {
			out = append(out, netif.Info{Name: n, Kind: w.kinds[n], Up: w.up[n]})
		}
		return out
	}
	m.defaultFn = func() (string, error) {
		if w.def == "" {
			return "", errors.New("nessuna rotta")
		}
		return w.def, nil
	}
	m.logf = func(f string, a ...any) { logs = append(logs, strings.TrimSpace(f)) }
	return m, &logs
}

func eq(got []string, want ...string) bool { return strings.Join(got, ",") == strings.Join(want, ",") }

func TestAutoFollowsHotplugAndRouteChanges(t *testing.T) {
	w := newWorld()
	w.add("enx1", netif.KindUSB, 3, true)
	w.add("wlp1s0", netif.KindWifi, 4, false) // spento: non va agganciato in automatico
	w.add("docker0", netif.KindBridge, 5, true)
	w.add("veth1", netif.KindVirtual, 6, true)
	w.def = "enx1"
	m, _ := w.manager("")
	added, removed := m.Sync()
	if !eq(added, "enx1") || len(removed) != 0 || !eq(m.Names(), "enx1") {
		t.Fatalf("avvio: +%v -%v nomi=%v (solo la fisica accesa, mai bridge/veth)", added, removed, m.Names())
	}
	// Idempotente: nessun nuovo aggancio se non cambia nulla.
	n := w.attaches
	if a, r := m.Sync(); len(a)+len(r) != 0 || w.attaches != n {
		t.Fatal("Sync senza cambiamenti non deve riagganciare")
	}
	// Si accende il Wi-Fi: deve agganciarsi da solo.
	w.up["wlp1s0"] = true
	if a, _ := m.Sync(); !eq(a, "wlp1s0") || !eq(m.Names(), "enx1", "wlp1s0") {
		t.Fatalf("Wi-Fi acceso a caldo: %v", m.Names())
	}
	// Si collega un secondo adattatore USB.
	w.add("enx2", netif.KindUSB, 9, true)
	if a, _ := m.Sync(); !eq(a, "enx2") {
		t.Fatalf("USB collegato a caldo: %v", a)
	}
	// Si scollega: il link va chiuso e tolto.
	delete(w.ifs, "enx2")
	if _, r := m.Sync(); !eq(r, "enx2") || !w.links[9].closed || !eq(m.Names(), "enx1", "wlp1s0") {
		t.Fatalf("USB scollegato: -%v nomi=%v", r, m.Names())
	}
	// Ricollegato con un altro indice: nuovo aggancio.
	w.add("enx2", netif.KindUSB, 11, true)
	if a, _ := m.Sync(); !eq(a, "enx2") || w.links[11] == nil {
		t.Fatalf("USB ricollegato con indice nuovo: %v", a)
	}
	// Stesso nome, indice cambiato senza sparire dall'elenco (scollegato e ricollegato tra due Sync).
	w.add("enx1", netif.KindUSB, 33, true)
	a, r := m.Sync()
	if !eq(a, "enx1") || !eq(r, "enx1") || !w.links[3].closed {
		t.Fatalf("indice cambiato: +%v -%v", a, r)
	}
	// Una rotta predefinita su un tunnel viene coperta anche se il tunnel non e' "fisico".
	w.add("wg0", netif.KindVPN, 20, true)
	w.def = "wg0"
	if a, _ := m.Sync(); !eq(a, "wg0") {
		t.Fatalf("rotta su tunnel: %v", a)
	}
	// Le interfacce di container non si agganciano mai in automatico.
	for _, n := range m.Names() {
		if n == "docker0" || n == "veth1" {
			t.Errorf("%s agganciata in automatico", n)
		}
	}
	m.Close()
	if len(m.Names()) != 0 || !w.links[4].closed {
		t.Error("Close deve staccare tutto")
	}
}

func TestManualAttachesWhenItAppearsAndNeverElse(t *testing.T) {
	w := newWorld()
	w.add("enx1", netif.KindUSB, 3, true)
	w.add("wlp1s0", netif.KindWifi, 4, true)
	w.def = "enx1"
	m, _ := w.manager("enx1, usb9 ,lo")
	if m.Auto() {
		t.Fatal("con una lista non e' automatico")
	}
	a, _ := m.Sync()
	if !eq(a, "enx1") || !eq(m.Names(), "enx1") {
		t.Fatalf("solo quelle che esistono: %v", a)
	}
	for _, n := range m.Names() {
		if n == "wlp1s0" {
			t.Fatal("wlp1s0 non e' nell'elenco: non va agganciata")
		}
	}
	if u := m.Uncovered(); !eq(u, "wlp1s0") {
		t.Fatalf("la Wi-Fi accesa non filtrata va segnalata: %v", u)
	}
	// usb9 compare dopo: si aggancia da sola. lo idem (esiste anche se spenta/virtuale).
	w.add("usb9", netif.KindUSB, 7, true)
	w.add("lo", netif.KindLoopback, 1, true)
	if a, _ := m.Sync(); !eq(a, "lo", "usb9") {
		t.Fatalf("comparse a caldo: %v", a)
	}
}

func TestAttachFailureWarnsOnceAndRetries(t *testing.T) {
	w := newWorld()
	w.add("enx1", netif.KindUSB, 3, true)
	w.def = "enx1"
	w.failFor[3] = true
	m, logs := w.manager("")
	for i := 0; i < 5; i++ {
		m.Sync()
	}
	warns := 0
	for _, l := range *logs {
		if strings.Contains(l, "XDP non attivo") {
			warns++
		}
	}
	if warns != 1 || len(m.Names()) != 0 || w.attaches != 5 {
		t.Fatalf("avviso una volta, ritenta ogni giro: avvisi=%d nomi=%v tentativi=%d", warns, m.Names(), w.attaches)
	}
	// Quando l'altro programma XDP se ne va, al giro dopo si aggancia.
	w.failFor[3] = false
	if a, _ := m.Sync(); !eq(a, "enx1") {
		t.Fatalf("dopo il fallimento: %v", a)
	}
}
