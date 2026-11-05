// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package lsm

import (
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ExeIndex associa l'identita' di un file (dev, inode, nella codifica del kernel) al suo percorso, per i binari nelle
// cartelle dove vivono i programmi. Serve a dare un nome al programma di un evento quando il processo e' gia' uscito:
// il kernel porta nell'evento (dev, inode) del binario, non il percorso.
//
// Non e' un controllo di sicurezza (decide sempre il kernel): e' solo un'etichetta per il log e la GUI, quindi un
// percorso mancante o un hard link che compare con un altro nome non cambiano nessuna decisione. L'indice si ricostruisce
// solo quando serve (una ricerca fallita e piu' di 10 secondi dall'ultimo giro), non a ogni evento.
type ExeIndex struct {
	mu      sync.Mutex
	m       map[key]string
	dirs    []indexDir
	built   time.Time
	maxWalk int
}

type indexDir struct {
	path  string
	depth int
}

// NewExeIndex: cartelle dei programmi di sistema e dell'utente. Profondita' limitata per non scandire mezzo disco.
func NewExeIndex(home string) *ExeIndex {
	return &ExeIndex{m: map[key]string{}, maxWalk: 60000, dirs: []indexDir{
		{"/usr/bin", 1}, {"/usr/sbin", 1}, {"/bin", 1}, {"/sbin", 1}, {"/usr/local/bin", 1}, {"/usr/local/sbin", 1},
		{"/snap/bin", 1}, {"/usr/libexec", 3}, {"/usr/lib/cargo/bin", 3}, {"/opt", 4},
		{filepath.Join(home, ".local/bin"), 1}, {filepath.Join(home, "bin"), 1},
	}}
}

func (x *ExeIndex) rebuild() {
	idx := map[key]string{}
	n := 0
	for _, d := range x.dirs {
		root := d.path
		_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if n >= x.maxWalk {
				return fs.SkipAll
			}
			if e.IsDir() {
				if depth(root, p) >= d.depth {
					return fs.SkipDir
				}
				return nil
			}
			n++
			var st syscall.Stat_t
			if syscall.Stat(p, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0o111 == 0 {
				return nil // symlink: Stat segue; interessano solo i file eseguibili veri
			}
			k := key{Ino: st.Ino, Dev: unix.Major(uint64(st.Dev))<<20 | unix.Minor(uint64(st.Dev))}
			real := p
			if r, err := filepath.EvalSymlinks(p); err == nil {
				real = r
			}
			if _, dup := idx[k]; !dup {
				idx[k] = real
			}
			return nil
		})
	}
	x.m, x.built = idx, time.Now()
}

func depth(root, p string) int {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == "." {
		return 0
	}
	d := 1
	for _, c := range rel {
		if c == os.PathSeparator {
			d++
		}
	}
	return d
}

// Resolve restituisce il percorso del binario con quella identita'. Al primo uso (o dopo una ricerca fallita, al massimo
// ogni 10 secondi) rilegge le cartelle.
func (x *ExeIndex) Resolve(dev, ino uint64) (string, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	k := key{Ino: ino, Dev: uint32(dev)}
	if p, ok := x.m[k]; ok {
		return p, true
	}
	if x.built.IsZero() || time.Since(x.built) > 10*time.Second {
		x.rebuild()
		if p, ok := x.m[k]; ok {
			return p, true
		}
	}
	return "", false
}
