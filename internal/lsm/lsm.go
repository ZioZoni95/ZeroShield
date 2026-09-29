// Package lsm sincronizza le mappe eBPF (file protetti, binari autorizzati) e gestisce l'hook file_open.
package lsm

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"zt-shield/bpf"
	"zt-shield/internal/config"
)

const maxFilesPerPath = 5000

// key ha lo stesso layout di file_key / allow_key in zerotrust.c.
// Extra: padding (0) per i file protetti, id regola per i binari autorizzati.
type key struct {
	Ino   uint64
	Dev   uint32
	Extra uint32
}

type Manager struct {
	objs  *bpf.ShieldObjects
	home  string
	rules []config.Rule
	link  link.Link
}

func New(objs *bpf.ShieldObjects, home string, rules []config.Rule) *Manager {
	return &Manager{objs: objs, home: home, rules: rules}
}

// Attach aggancia l'hook LSM file_open.
func (m *Manager) Attach() error {
	l, err := link.AttachLSM(link.LSMOptions{Program: m.objs.ZtFileOpen})
	if err != nil {
		return fmt.Errorf("attach LSM: %w (verifica che 'bpf' sia in /sys/kernel/security/lsm)", err)
	}
	m.link = l
	return nil
}

func (m *Manager) Close() {
	if m.link != nil {
		m.link.Close()
	}
}

// RuleName: nome della regola dall'id (indice + 1) riportato negli eventi.
func (m *Manager) RuleName(id uint32) string {
	if id >= 1 && int(id) <= len(m.rules) {
		return m.rules[id-1].Name
	}
	return fmt.Sprintf("rule-%d", id)
}

// Sync riallinea le mappe allo stato attuale del filesystem: aggiunge i nuovi file/binari
// e rimuove le voci non più presenti.
func (m *Manager) Sync() (protected, allowed int) {
	wantFiles := map[key]uint32{}
	wantExes := map[key]uint32{}

	for i, r := range m.rules {
		id := uint32(i + 1)
		for _, p := range r.Paths {
			for _, f := range expand(m.home, p) {
				if k, ok := fileKey(f); ok {
					wantFiles[k] = id
				}
			}
		}
		for _, a := range r.Allow {
			if exe, ok := resolveExe(a); ok {
				if k, ok := fileKey(exe); ok {
					k.Extra = id
					wantExes[k] = 1
				}
			}
		}
	}

	m.reconcile(m.objs.ProtectedFiles, wantFiles)
	m.reconcile(m.objs.AllowedExes, wantExes)
	return len(wantFiles), len(wantExes)
}

func (m *Manager) reconcile(mp *ebpf.Map, want map[key]uint32) {
	var stale []key
	var k key
	var v uint32
	it := mp.Iterate()
	for it.Next(&k, &v) {
		if _, ok := want[k]; !ok {
			stale = append(stale, k)
		}
	}
	for _, s := range stale {
		if err := mp.Delete(s); err != nil {
			log.Printf("⚠️ rimozione voce obsoleta: %v", err)
		}
	}
	for k, v := range want {
		if err := mp.Put(k, v); err != nil {
			log.Printf("⚠️ aggiornamento mappa: %v", err)
		}
	}
}

// expand espande home-relative, glob e directory (ricorsive) in file regolari.
func expand(home, pattern string) []string {
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(home, pattern)
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	var out []string
	for _, match := range matches {
		fi, err := os.Stat(match) // segue i symlink: l'inode che conta è quello del target
		if err != nil {
			continue
		}
		if fi.Mode().IsRegular() {
			out = append(out, match)
			continue
		}
		if fi.IsDir() {
			n := 0
			filepath.WalkDir(match, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.Type().IsRegular() {
					out = append(out, p)
					if n++; n >= maxFilesPerPath {
						return fs.SkipAll
					}
				}
				return nil
			})
		}
	}
	return out
}

func resolveExe(name string) (string, bool) {
	path := name
	if !filepath.IsAbs(name) {
		p, err := exec.LookPath(name)
		if err != nil {
			return "", false
		}
		path = p
	}
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	return path, true
}

// fileKey: dev nel formato kernel (major<<20 | minor), diverso da st_dev userspace.
func fileKey(path string) (key, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return key{}, false
	}
	dev := uint64(st.Dev)
	return key{Ino: st.Ino, Dev: unix.Major(dev)<<20 | unix.Minor(dev)}, true
}
