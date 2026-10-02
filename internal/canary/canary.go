// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Package canary: esche anti-ransomware via fanotify (vedi docs/CANARY.md).
//
// Due trigger, stessa filosofia audit/enforce del resto dello scudo:
//   - tocco canary (open/write/close di un file esca) -> kill in enforce, alert in audit.
//   - massa di rename/delete/close-write per PID oltre soglia -> solo alert
//     (mai kill: troppi falsi positivi da compilazioni e backup).
//
// Il kill e' l'unico punto dove il demone agisce invece di osservare: per questo
// non killa mai pid<=1, se stesso, né in audit. fanotify richiede CAP_SYS_ADMIN:
// senza privilegi Start fallisce e il resto dello scudo continua.
package canary

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Kind di evento osservato (nomi stabili per log e IPC).
type Kind string

const (
	KindOpen   Kind = "open"
	KindWrite  Kind = "write"
	KindDelete Kind = "delete"
	KindRename Kind = "rename"
)

// Verdict del detector: osserva, avvisa, o neutralizza.
type Verdict int

const (
	VerdictIgnore Verdict = iota
	VerdictAlert
	VerdictKill
)

// Hit: un fatto attribuito a un PID.
type Hit struct {
	PID     int
	Exe     string
	Path    string
	Kind    Kind
	Canary  bool
	Verdict Verdict
	Enforce bool
	At      time.Time
	Reason  string
	KillErr error
	Killed  bool
}

// Detector: logica pura e testabile senza fd fanotify né root.
// canaries = set di path esca (assoluti, puliti). exclude = sottostringhe exe
// saltate dal conteggio massa (mai dal trip canary: le esche non si toccano).
type Detector struct {
	burstCount int
	window     time.Duration
	exclude    []string
	canaries   map[string]bool

	mu       sync.Mutex
	hits     map[int][]time.Time
	cooldown map[int]time.Time
}

func NewDetector(burstCount int, burstSecs int, exclude []string, canaries []string) *Detector {
	set := map[string]bool{}
	for _, c := range canaries {
		set[filepath.Clean(c)] = true
	}
	return &Detector{
		burstCount: burstCount,
		window:     time.Duration(burstSecs) * time.Second,
		exclude:    exclude,
		canaries:   set,
		hits:       map[int][]time.Time{},
		cooldown:   map[int]time.Time{},
	}
}

func (d *Detector) excluded(exe string) bool {
	for _, e := range d.exclude {
		if e != "" && strings.Contains(exe, e) {
			return true
		}
	}
	return false
}

// Record valuta un evento. isCanary = path risolto dentro il set esche.
// Ritorna il verdetto; l'azione (kill/log) sta al chiamante.
func (d *Detector) Record(pid int, exe, path string, kind Kind, enforce bool, now time.Time) Verdict {
	if pid <= 1 {
		return VerdictIgnore // mai pid 1/init: fail-safe contro kill catastrofici
	}
	if d.canaries[filepath.Clean(path)] {
		if enforce {
			return VerdictKill
		}
		return VerdictAlert
	}
	if kind != KindRename && kind != KindDelete && kind != KindWrite {
		return VerdictIgnore // open/letture non contano per la massa
	}
	if d.excluded(exe) {
		return VerdictIgnore
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.Sub(d.cooldown[pid]) < d.window {
		return VerdictIgnore // un allarme per finestra basta, niente spam
	}
	h := d.hits[pid]
	// Tieni solo la finestra: slice senza riallocazioni selvagge.
	kept := h[:0]
	for _, t := range h {
		if now.Sub(t) < d.window {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	d.hits[pid] = kept
	if len(kept) >= d.burstCount {
		d.cooldown[pid] = now
		delete(d.hits, pid)
		return VerdictAlert
	}
	return VerdictIgnore
}

// DeployCanaries crea dir ed esche mancanti (4KB casuali, 0644 come file normali).
// Mai sovrascritte: un'esca esistente potrebbe essere un tuo file vero.
func DeployCanaries(home string, dirs, names []string) ([]string, error) {
	var out []string
	for _, dir := range dirs {
		d := dir
		if !filepath.IsAbs(d) {
			d = filepath.Join(home, d)
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			return out, fmt.Errorf("canary mkdir %s: %w", d, err)
		}
		for _, n := range names {
			p := filepath.Join(d, n)
			out = append(out, p)
			if _, err := os.Stat(p); err == nil {
				continue
			}
			buf := make([]byte, 4096)
			if _, err := rand.Read(buf); err != nil {
				return out, err
			}
			if err := os.WriteFile(p, buf, 0o644); err != nil {
				return out, fmt.Errorf("canary write %s: %w", p, err)
			}
			log.Printf("🐤 esca creata: %s (non aprirla mai: ogni tocco e' allarme)", p)
		}
	}
	return out, nil
}

// Watcher: fd fanotify + loop eventi. Chiudere con Close.
type Watcher struct {
	fd  int
	det *Detector
}

// Start arma dir (eventi figli) ed esche (open/write/close). enforce decide kill/alert.
// onHit chiamato per ogni Alert/Kill: log + IPC nel demone.
func Start(home string, dirs, names []string, exclude []string, burstCount, burstSecs int, enforce bool, onHit func(Hit)) (*Watcher, error) {
	paths, err := DeployCanaries(home, dirs, names)
	if err != nil {
		return nil, err
	}
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init (serve CAP_SYS_ADMIN/root): %w", err)
	}
	w := &Watcher{fd: fd, det: NewDetector(burstCount, burstSecs, exclude, paths)}
	// Dir: conta massa sui figli. OPEN escluso qui (troppo rumore: ogni ls).
	for _, dir := range dirs {
		d := dir
		if !filepath.IsAbs(d) {
			d = filepath.Join(home, d)
		}
		mask := uint64(unix.FAN_CLOSE_WRITE | unix.FAN_DELETE | unix.FAN_MOVED_FROM | unix.FAN_MOVED_TO | unix.FAN_EVENT_ON_CHILD)
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, d); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("fanotify_mark dir %s: %w", d, err)
		}
	}
	// Esche: trip diretto su open/write/close (path noto via fd evento).
	for _, p := range paths {
		mask := uint64(unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE)
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, p); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("fanotify_mark esca %s: %w", p, err)
		}
	}
	go w.loop(enforce, onHit)
	return w, nil
}

func (w *Watcher) Close() error { return unix.Close(w.fd) }

// metadata fanotify: event_len u32, vers u8, res u8, metadata_len u16,
// mask u64, fd i32, pid i32 = 24 byte little-endian (layout kernel stabile).
func (w *Watcher) loop(enforce bool, onHit func(Hit)) {
	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if err == unix.EAGAIN {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return // fd chiuso: stop
		}
		off := 0
		for off+24 <= n {
			mask := u64le(buf[off+8:])
			efd := int(i32le(buf[off+16:]))
			pid := int(i32le(buf[off+20:]))
			elen := int(u32le(buf[off:]))
			if elen <= 0 {
				break
			}
			w.handle(mask, efd, pid, enforce, onHit)
			if efd >= 0 {
				unix.Close(efd)
			}
			off += elen
		}
	}
}

func (w *Watcher) handle(mask uint64, efd int, pid int, enforce bool, onHit func(Hit)) {
	var kind Kind
	var needPath bool
	switch {
	case mask&uint64(unix.FAN_DELETE) != 0:
		kind, needPath = KindDelete, false // path ignoto senza DFID: conta per massa
	case mask&uint64(unix.FAN_MOVED_FROM|unix.FAN_MOVED_TO) != 0:
		kind, needPath = KindRename, false
	case mask&uint64(unix.FAN_CLOSE_WRITE|unix.FAN_MODIFY) != 0:
		kind, needPath = KindWrite, true
	case mask&uint64(unix.FAN_OPEN) != 0:
		kind, needPath = KindOpen, true
	default:
		return
	}
	path := ""
	if needPath && efd >= 0 {
		if link, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", efd)); err == nil {
			path = link
		}
	}
	now := time.Now()
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	// Per eventi senza path (delete/move su dir) il trip canary non e'
	// attribuibile: valgono solo per la massa (documentato in CANARY.md).
	v := w.det.Record(pid, exe, path, kind, enforce, now)
	if v == VerdictIgnore {
		return
	}
	hit := Hit{PID: pid, Exe: exe, Path: path, Kind: kind, At: now, Enforce: enforce,
		Canary: w.det.canaries[filepath.Clean(path)]}
	if v == VerdictKill {
		hit.Verdict = VerdictKill
		hit.Reason = "tocco esca canary"
		if pid != os.Getpid() {
			if err := unix.Kill(pid, unix.SIGKILL); err != nil {
				hit.KillErr = err
			} else {
				hit.Killed = true
			}
		}
	} else {
		hit.Verdict = VerdictAlert
		if w.det.canaries[filepath.Clean(path)] {
			hit.Canary = true
			hit.Reason = "tocco esca canary (audit: solo log)"
		} else {
			hit.Reason = "massa rename/delete oltre soglia"
		}
	}
	onHit(hit)
}

func u32le(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func u64le(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
func i32le(b []byte) int32 { return int32(u32le(b)) }
