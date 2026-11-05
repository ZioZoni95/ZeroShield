// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package xdp

import (
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"zt-shield/internal/netif"
)

// Manager tiene agganciato il filtro XDP alle interfacce giuste ANCHE quando cambiano mentre il servizio gira:
// un adattatore USB collegato dopo l'avvio, il Wi-Fi acceso in un secondo momento, l'interfaccia che cambia indice
// perche' l'hai scollegata e ricollegata. Prima l'elenco si fissava all'avvio e la rete nuova restava scoperta.
//
// Due modi, come nel config:
//   - automatico (`interface` vuota): ogni interfaccia FISICA (cavo, USB, Wi-Fi) piu' quella della rotta predefinita
//     (che puo' essere un tunnel). Scegliere "la rete in uso" non basta: se la rotta cambia si resta scoperti.
//   - manuale (`interface: a,b`): solo quelle nominate, agganciate appena esistono.
//
// Sync va chiamata di tanto in tanto (il demone la chiama ogni pochi secondi): e' economica, legge /sys e la tabella
// di routing, e non tocca nulla se non e' cambiato niente. Non e' thread-safe per le modifiche concorrenti allo stato
// del chiamante, ma ha un mutex interno cosi' Names() si puo' leggere da altre goroutine.
type Manager struct {
	mu     sync.Mutex
	prog   *ebpf.Program
	names  []string // da config; vuoto = automatico
	cur    map[string]*attached
	warned map[string]bool

	// iniettabili per i test
	attachFn  func(prog *ebpf.Program, ifindex int) (io.Closer, error)
	ifaceFn   func(name string) (*net.Interface, error)
	listFn    func() []netif.Info
	defaultFn func() (string, error)
	logf      func(format string, args ...any)
}

type attached struct {
	index int
	l     io.Closer // il link XDP (nei test un finto)
}

// NewManager legge `custom` (lista csv, come `interface` nel config).
func NewManager(prog *ebpf.Program, custom string) *Manager {
	return &Manager{
		prog: prog, names: splitList(custom), cur: map[string]*attached{}, warned: map[string]bool{},
		attachFn: func(p *ebpf.Program, idx int) (io.Closer, error) {
			return link.AttachXDP(link.XDPOptions{Program: p, Interface: idx, Flags: link.XDPGenericMode})
		},
		ifaceFn: net.InterfaceByName,
		listFn:  func() []netif.Info { return netif.List(netif.Sys, netif.Up) },
		defaultFn: func() (string, error) {
			i, err := defaultInterface("")
			if err != nil {
				return "", err
			}
			return i.Name, nil
		},
		logf: log.Printf,
	}
}

// Auto dice se si e' in modalita' automatica.
func (m *Manager) Auto() bool { return len(m.names) == 0 }

// desired: i nomi che dovrebbero essere agganciati adesso.
func (m *Manager) desired() []string {
	if !m.Auto() {
		return m.names
	}
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if d, err := m.defaultFn(); err == nil {
		add(d)
	}
	for _, i := range m.listFn() {
		if i.Physical() && i.Up {
			add(i.Name)
		}
	}
	return out
}

// Sync riallinea gli aggancio a quello che serve e restituisce cosa e' cambiato (per il log e per ripubblicare lo stato).
func (m *Manager) Sync() (added, removed []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// 1. via quelli che non esistono piu' o hanno cambiato indice (scollegato e ricollegato): il link del kernel e' morto.
	for name, a := range m.cur {
		ifc, err := m.ifaceFn(name)
		if err != nil || ifc.Index != a.index {
			_ = a.l.Close()
			delete(m.cur, name)
			removed = append(removed, name)
			delete(m.warned, "attach:"+name) // se ricompare si riprova e si puo' avvisare di nuovo
		}
	}
	// 2. agganciare quelli che servono e non ci sono.
	for _, name := range m.desired() {
		if _, ok := m.cur[name]; ok {
			continue
		}
		ifc, err := m.ifaceFn(name)
		if err != nil {
			continue // non esiste (ancora): si riprova al prossimo giro
		}
		l, err := m.attachFn(m.prog, ifc.Index)
		if err != nil {
			// Tipico: un altro programma XDP e' gia' agganciato (XDP e' esclusivo per interfaccia). Si avvisa una volta.
			if k := "attach:" + name; !m.warned[k] {
				m.warned[k] = true
				m.logf("⚠️ XDP non attivo su %s: %v", name, fmt.Errorf("attach XDP su %s: %w", name, err))
			}
			continue
		}
		m.cur[name] = &attached{index: ifc.Index, l: l}
		added = append(added, name)
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// Names: le interfacce su cui il filtro e' agganciato adesso, in ordine.
func (m *Manager) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.cur))
	for n := range m.cur {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Uncovered: interfacce fisiche o tunnel accese su cui il filtro NON e' agganciato (di norma solo in modalita' manuale).
func (m *Manager) Uncovered() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, i := range m.listFn() {
		if !i.Up || (!i.Physical() && i.Kind != netif.KindVPN) {
			continue
		}
		if _, ok := m.cur[i.Name]; !ok {
			out = append(out, i.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Close stacca il filtro da tutte le interfacce.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for n, a := range m.cur {
		_ = a.l.Close()
		delete(m.cur, n)
	}
}
