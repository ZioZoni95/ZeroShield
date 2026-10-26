// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package lsm

import (
	"log"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Watcher osserva con inotify le directory dei segreti e chiama onChange quando ci
// compare, sparisce o viene rinominato qualcosa.
//
// Perche': la chiave in mappa e' l'inode. Un segreto riscritto con "scrivi un file nuovo
// e rinominalo sopra" (editor, `ssh-keygen`, gestori di credenziali) cambia inode: fino al
// rescan successivo (rescan_seconds, 30 s) il file nuovo e' LIBERO. Con inotify il rescan
// parte entro pochi centinaia di millisecondi. Il rescan periodico resta: inotify non vede
// i mount, i file creati prima dell'osservazione e le directory oltre il tetto.
//
// onChange e' chiamato con un debounce: raffiche di eventi (una compilazione in una dir
// osservata) producono al massimo un rescan ogni minGap.
type Watcher struct {
	fd       int
	stopR    int
	stopW    int
	onChange func()

	mu    sync.Mutex
	paths map[string]int // directory -> watch descriptor
	byWD  map[int]string

	wg        sync.WaitGroup
	closeOnce sync.Once
}

const (
	watchDebounce = 400 * time.Millisecond
	watchMinGap   = 3 * time.Second
	watchMask     = unix.IN_CREATE | unix.IN_MOVED_TO | unix.IN_MOVED_FROM |
		unix.IN_DELETE | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_ONLYDIR
)

// NewWatcher avvia il loop. onChange non deve bloccare (nel demone: invio non bloccante
// su un canale con capienza 1).
func NewWatcher(onChange func()) (*Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		unix.Close(fd)
		return nil, err
	}
	w := &Watcher{fd: fd, stopR: pipe[0], stopW: pipe[1], onChange: onChange,
		paths: map[string]int{}, byWD: map[int]string{}}
	w.wg.Add(1)
	go w.loop()
	return w, nil
}

// Set riallinea le directory osservate a `dirs`: aggiunge le nuove, toglie le altre.
// Una directory che non si puo' osservare (sparita, limite inotify) e' saltata con un
// avviso una sola volta: il rescan periodico resta la rete di sicurezza.
func (w *Watcher) Set(dirs []string) {
	want := make(map[string]bool, len(dirs))
	for _, d := range dirs {
		want[d] = true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for d, wd := range w.paths {
		if !want[d] {
			unix.InotifyRmWatch(w.fd, uint32(wd))
			delete(w.paths, d)
			delete(w.byWD, wd)
		}
	}
	for d := range want {
		if _, ok := w.paths[d]; ok {
			continue
		}
		wd, err := unix.InotifyAddWatch(w.fd, d, watchMask)
		if err != nil {
			if err == unix.ENOSPC {
				log.Printf("⚠️ inotify: limite fs.inotify.max_user_watches raggiunto, %s non osservata (resta il rescan periodico)", d)
			}
			continue
		}
		w.paths[d] = wd
		w.byWD[wd] = d
	}
}

// Watched: numero di directory osservate (per i test).
func (w *Watcher) Watched() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.paths)
}

// Close ferma il loop e chiude gli fd. Idempotente.
func (w *Watcher) Close() {
	w.closeOnce.Do(func() {
		_, _ = unix.Write(w.stopW, []byte{1})
		w.wg.Wait()
		for _, fd := range []int{w.fd, w.stopR, w.stopW} {
			unix.Close(fd)
		}
	})
}

func (w *Watcher) loop() {
	defer w.wg.Done()
	buf := make([]byte, 16*1024)
	fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}, {Fd: int32(w.stopR), Events: unix.POLLIN}}
	var (
		timer   *time.Timer
		timerC  <-chan time.Time
		lastRun time.Time
	)
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		// Con un timer pendente si sveglia anche per lui: poll con timeout breve.
		timeout := -1
		if timerC != nil {
			timeout = 50
		}
		if _, err := unix.Poll(fds, timeout); err != nil && err != unix.EINTR {
			return
		}
		if fds[1].Revents != 0 {
			return
		}
		if fds[0].Revents&unix.POLLIN != 0 {
			n, err := unix.Read(w.fd, buf)
			if err == nil && n > 0 && timerC == nil {
				delay := watchDebounce
				if gap := watchMinGap - time.Since(lastRun); gap > delay {
					delay = gap
				}
				timer = time.NewTimer(delay)
				timerC = timer.C
			}
		}
		if timerC != nil {
			select {
			case <-timerC:
				timerC, lastRun = nil, time.Now()
				w.onChange()
			default:
			}
		}
	}
}
