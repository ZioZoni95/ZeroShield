// Package lsm sincronizza le mappe eBPF (file protetti, binari autorizzati) e gestisce l'hook file_open.
//
// Il confine userspace/kernel e' fatto di numeri, non di stringhe: per ogni file
// si mette in mappa (device, inode) e il kernel confronta i propri numeri con
// l'oggetto che sta per essere aperto. Nessun path attraversa mai il confine, e
// questo e' il motivo per cui la whitelist non puo' essere aggirata con symlink:
// conta l'identita' del file, non il nome con cui lo chiami.
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

// Tetto di file per singolo path espanso, per non saturare la mappa (16384 entry)
// su un path che punta a una directory enorme. superato il tetto si smette di
// camminare con fs.SkipAll e i file restanti NON sono protetti: un limite noto e
// deliberato, perche' il fallimento silenzioso di un'intera regola sarebbe peggio.
const maxFilesPerPath = 5000

// key ha lo stesso layout di file_key / allow_key in zerotrust.c.
//
//	ino@0 (8) | dev@8 (4) | extra@12 (4)  = 16 byte
//
// `Extra` ha due significati a seconda della mappa: 0 (padding) per i file protetti,
// l'id della regola per i binari autorizzati. Un'unica struct per entrambe evita
// di duplicare la codifica e il rischio di disallineamento con il C.
type key struct {
	Ino   uint64
	Dev   uint32
	Extra uint32
}

// Manager: stato del lato userspace dell'hook LSM.
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
//
// Restituisce un errore invece di loggare: main lo tratta come fatale. Un hook
// non agganciato mentre il demone dichiara "scudo attivo" e' il peggior caso
// possibile, perche' l'utente si crede protetto.
//
// Nota: il programma va agganciato una volta sola. Un secondo aggancio sullo stesso
// hook crea una seconda istanza attiva, non sostituisce la prima.
func (m *Manager) Attach() error {
	l, err := link.AttachLSM(link.LSMOptions{Program: m.objs.ZtFileOpen})
	if err != nil {
		return fmt.Errorf("attach LSM: %w (verifica che 'bpf' sia in /sys/kernel/security/lsm)", err)
	}
	m.link = l
	return nil
}

// Close stacca l'hook. Da qui in poi la protezione non e' piu' attiva: e' il punto
// in cui il servizio e' fermo. Nessun pinning in bpffs, quindi non c'e' persistenza
// oltre la vita del processo.
func (m *Manager) Close() {
	if m.link != nil {
		m.link.Close()
	}
}

// RuleName: nome della regola dall'id (indice + 1) riportato negli eventi.
// Gli id arrivano dal kernel come interi, la traduzione in nome e' qui: cosi' il
// log e' leggibile e il kernel non deve trasportare stringhe.
func (m *Manager) RuleName(id uint32) string {
	if id >= 1 && int(id) <= len(m.rules) {
		return m.rules[id-1].Name
	}
	return fmt.Sprintf("rule-%d", id)
}

// Sync riallinea le mappe allo stato attuale del filesystem: aggiunge i nuovi
// file/binari e rimuove le voci non piu' presenti.
//
// Il rimuovere conta quanto l'aggiungere. Senza, un binario sostituito da apt
// lascerebbe in mappa l'inode vecchio, e un file cancellato lascerebbe un
// inode che il filesystem puo' riassegnare a qualcos'altro: in entrambi i casi
// l'autorizzazione sopravvive a cose diverse da quella che autorizzavi.
func (m *Manager) Sync() (protected, allowed int) {
	// Stato desiderato, calcolato da zero a ogni sync. Non un delta: piu' semplice
	// da ragionare e il costo e' dominato dai walk su filesystem, non dalle Put.
	wantFiles := map[key]uint32{}
	wantExes := map[key]uint32{}

	for i, r := range m.rules {
		id := uint32(i + 1) // id 0 è riservato: in una map, 0 come valore significa "non protetto"
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

// reconcile rende la mappa uguale a `want`: cancella le voci in piu', scrive quelle mancanti.
//
// Gli errori individuali vengono loggati e il sync prosegue. Un path che non si
// risolve (binario non installato, profilo browser inesistente) non deve impedire
// la protezione delle altre regole. Il caso peggiore resta quello in cui un tool
// LEGITTIMO non entra in whitelist: l'utente riceve EACCES su un file suo e la
// causa non e' nel log, solo nel conteggio "binari autorizzati: N".
func (m *Manager) reconcile(mp *ebpf.Map, want map[key]uint32) {
	// Fase 1: identificare le voci obsolete iterando la mappa.
	// Nota: non si puo' cancellare durante l'iterazione, quindi si raccoglie prima.
	var stale []key
	var k key
	var v uint32
	it := mp.Iterate()
	for it.Next(&k, &v) {
		if _, ok := want[k]; !ok {
			stale = append(stale, k)
		}
	}
	// Fase 2: cancellare.
	for _, s := range stale {
		if err := mp.Delete(s); err != nil {
			log.Printf("⚠️ rimozione voce obsoleta: %v", err)
		}
	}
	// Fase 3: scrivere tutto lo stato desiderato. Put e' idempotente, quindi
	// riscrive anche le voci invariate: costa qualche syscall in piu' a ogni sync
	// e rende il codice immune a qualsiasi errore di allineamento precedente.
	for k, v := range want {
		if err := mp.Put(k, v); err != nil {
			log.Printf("⚠️ aggiornamento mappa: %v", err)
		}
	}
}

// expand espande un pattern in file regolari: relativo alla home o assoluto,
// con glob, e ricorsivo se il match e' una directory.
//
// os.Stat e non Lstat, quindi segue i symlink: conta l'inode del TARGET, che e'
// quello che il kernel vede all'apertura. Coerente con il fatto che la chiave e'
// (dev, ino) del file effettivamente aperto.
func expand(home, pattern string) []string {
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(home, pattern)
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil // pattern malformato: silenzioso, la validazione del glob non e' fatta
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
					return nil // file sparito durante il walk: normale
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

// resolveExe trasforma una voce di `allow` nel path assoluto del binario.
//
// EvalSymlinks e' obbligatorio, non decorativo: su Ubuntu /bin e /usr/bin sono la
// stessa directory, quindi senza resolve metteresti in mappa l'inode del symlink
// e non quello dell'ELF, che non corrisponderebbe mai.
//
// BUG: per i nomi non assoluti si usa exec.LookPath, che risolve con il PATH di
// QUESTO processo. Sotto systemd il PATH e' minimale
// (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin), quindi un tool
// come kubectl installato come snap (/snap/bin/kubectl) o aws in ~/.local/bin non
// viene trovato, l'errore viene scartato in silenzio da `continue`, e il binario
// LEGITTIMO non finisce in whitelist: l'utente prende EACCES sul proprio kubeconfig.
// Il rimedio e' risolvere con il PATH dell'utente target (config.HomeDir) o usare
// path assoluti nelle regole.
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

// fileKey: (dev, ino) del file, con dev nel formato del kernel.
//
// unix.Major(dev)<<20 | unix.Minor(dev) replica new_encode_dev, la codifica con cui
// il kernel scrive s_dev. Non e' cosmetico: userspace e kernelspace usano due
// encoding diversi e senza questa conversione le chiavi non matcherebbero MAI,
// cioe' la protezione sarebbe silenziosamente inerte.
//
// Limite: vale per ext4/xfs. Su btrfs (subvolume) e overlayfs (Docker) st_dev in
// userspace e s_dev nel kernel divergono, e la chiave non matcha. Un file su un
// overlay non e' protetto senza che nulla lo segnali. Se il tuo ~/.kube/config
// vive su un mount overlay, il test 1 di TESTING.md e' il modo per accorgertene.
func fileKey(path string) (key, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return key{}, false
	}
	dev := uint64(st.Dev)
	return key{Ino: st.Ino, Dev: unix.Major(dev)<<20 | unix.Minor(dev)}, true
}
