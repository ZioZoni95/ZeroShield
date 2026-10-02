// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

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

// Manager: stato del lato userspace degli hook LSM.
//
// I tipi eBPF sono quelli generici di cilium/ebpf, NON gli stub generati da
// bpf2go: cosi' il package compila e si testa senza toolchain eBPF né kernel
// (gli stub vivono solo nel demone e sono gitignored). Il demone passa
// objs.ProtectedFiles / objs.AllowedExes e i programmi
// (ZtFileOpen, ZtFileUnlink, ZtFileRename).
type Manager struct {
	protected *ebpf.Map
	allowed   *ebpf.Map
	progs     []*ebpf.Program
	home      string
	rules     []config.Rule
	links     []link.Link
}

func New(protected, allowed *ebpf.Map, progs []*ebpf.Program, home string, rules []config.Rule) *Manager {
	return &Manager{protected: protected, allowed: allowed, progs: progs, home: home, rules: rules}
}

// Attach aggancia gli hook LSM (file_open + unlink + rename).
//
// Restituisce un errore invece di loggare: main lo tratta come fatale. Un hook
// non agganciato mentre il demone dichiara "scudo attivo" e' il peggior caso
// possibile, perche' l'utente si crede protetto. Se uno qualsiasi fallisce,
// quelli già agganciati vengono staccati e si esce: mai protezione a metà.
//
// Nota: ogni programma va agganciato una volta sola. Un secondo aggancio sullo
// stesso hook crea una seconda istanza attiva, non sostituisce la prima.
func (m *Manager) Attach() error {
	for _, p := range m.progs {
		l, err := link.AttachLSM(link.LSMOptions{Program: p})
		if err != nil {
			m.Close()
			return fmt.Errorf("attach LSM: %w (verifica che 'bpf' sia in /sys/kernel/security/lsm)", err)
		}
		m.links = append(m.links, l)
	}
	return nil
}

// Close stacca gli hook. Da qui in poi la protezione non e' piu' attiva: e' il punto
// in cui il servizio e' fermo. Nessun pinning in bpffs, quindi non c'e' persistenza
// oltre la vita del processo.
func (m *Manager) Close() {
	for _, l := range m.links {
		if l != nil {
			l.Close()
		}
	}
	m.links = nil
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
		// deny_write viaggia nel bit31 del valore (il kernel lo separa dall'id).
		// Stessa mappa, stessa lookup: zero costo aggiuntivo nel percorso caldo.
		val := id
		if r.DenyWrite {
			val |= 1 << 31
			log.Printf("⛔ regola %q: deny_write attivo, scrittura negata anche a root", r.Name)
		}
		for _, p := range r.Paths {
			for _, f := range expand(m.home, p) {
				if k, ok := fileKey(f); ok {
					wantFiles[k] = val
				}
			}
		}
		for _, a := range r.Allow {
			// FIX: prima l'errore di risoluzione era scartato in silenzio da `continue`:
			// binario legittimo fuori whitelist -> EACCES inspiegabile. Ora log esplicito
			// con nome regola, cosi' l'utente sa cosa allargare o dove mettere path assoluto.
			exe, ok := resolveExe(m.home, a)
			if !ok {
				log.Printf("⚠️ regola %q: binario %q non risolto (PATH demone: %q + /snap/bin + ~/.local/bin), NON in whitelist", r.Name, a, os.Getenv("PATH"))
				continue
			}
			// FIX: un binario modificabile dall'utente in whitelist e' un bypass:
			// `cat evil > ~/.local/bin/aws` conserva l'inode e il codice malevolo
			// legge i segreti come "aws". Si accettano solo binari (e directory
			// padri) di root e non scrivibili da altri.
			if err := trustedExe(exe); err != nil {
				log.Printf("⛔ regola %q: binario %q (%s) NON in whitelist: %v. Installalo in un percorso di root (es. /usr/local/bin)", r.Name, a, exe, err)
				continue
			}
			if k, ok := fileKey(exe); ok {
				k.Extra = id
				wantExes[k] = 1
			}
		}
	}

	// FIX: allarme capienza mappe. Oltre 16384 file / 1024 exe i Put falliscono con
	// E2BIG e la protezione resta incompleta in silenzio. Ora avviso prima che accada.
	const (
		maxProtectedFiles = 16384
		maxAllowedExes    = 1024
	)
	if len(wantFiles) > maxProtectedFiles {
		log.Printf("⚠️ file protetti %d > capienza mappa %d: parte NON protetta, restringi le regole", len(wantFiles), maxProtectedFiles)
	}
	if len(wantExes) > maxAllowedExes {
		log.Printf("⚠️ binari autorizzati %d > capienza mappa %d: parte NON in whitelist", len(wantExes), maxAllowedExes)
	}

	m.reconcile(m.protected, wantFiles)
	m.reconcile(m.allowed, wantExes)
	return len(wantFiles), len(wantExes)
}

// reconcile rende la mappa uguale a `want`: cancella le voci in piu', scrive quelle mancanti.
//
// Gli errori individuali vengono loggati e il sync prosegue. Un path che non si
// risolve (binario non installato, profilo browser inesistente) non deve impedire
// la protezione delle altre regole. Il caso peggiore resta quello in cui un tool
// LEGITTIMO non entra in whitelist: per questo Sync logga esplicitamente ogni
// `allow` non risolto con il nome della regola (prima era silenzio).
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
	// FIX: l'errore di iterazione non veniva mai controllato. Con una mappa
	// corrotta o sotto pressione memoria, un'iterazione parziale cancellava solo
	// parte delle voci obsolete: inode riassegnati restavano protetti per errore.
	if err := it.Err(); err != nil {
		log.Printf("⚠️ iterazione mappa incompleta, obsolete non rimosse: %v", err)
		return
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
		// FIX: prima il glob malformato (refuso in extra_rules) era silenzioso:
		// regola non protetta senza segnale. Ora log con pattern.
		log.Printf("⚠️ glob malformato %q: regola non applicata", pattern)
		return nil
	}
	if len(matches) == 0 {
		// Non un errore: profilo browser su macchina senza quel browser.
		// Debug-level: lo vede chi cerca, non sporca il log a ogni rescan.
		// (Si logga una volta per Sync? No: ogni rescan spammerebbe. Resta silenzio
		// voluto qui; gli `allow` non risolti invece si loggano in Sync.)
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
			// FIX: prima si usava d.Type().IsRegular() dentro il walk, che NON segue
			// i symlink (DT_LNK != regolare): un segreto linkato dentro una directory
			// ricorsiva restava non protetto. Ora si fa Stat sul path (segue symlink,
			// coerente con os.Stat sul match e con l'inode visto dal kernel).
			n := 0
			truncated := false
			filepath.WalkDir(match, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil // file sparito durante il walk: normale
				}
				st, err := os.Stat(p) // segue symlink: l'inode che conta e' del target
				if err != nil {
					return nil
				}
				if st.Mode().IsRegular() {
					out = append(out, p)
					if n++; n >= maxFilesPerPath {
						truncated = true
						return fs.SkipAll
					}
				}
				return nil
			})
			// FIX: prima il troncamento a maxFilesPerPath era silenzioso: i file oltre
			// il tetto restavano NON protetti senza alcun segnale. Ora log esplicito.
			if truncated {
				log.Printf("⚠️ path %q: oltre %d file, resto NON protetto (restringi la regola)", match, maxFilesPerPath)
			}
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
// Nota: i fallback in home (~/.local/bin, ~/bin) servono solo a risolvere il nome
// e a dare un log chiaro: trustedExe li scarta perche' scrivibili dall'utente.
//
// FIX: per i nomi non assoluti si cercava solo con exec.LookPath (PATH di QUESTO
// processo). Sotto systemd il PATH e' minimale, quindi kubectl snap (/snap/bin)
// o aws in ~/.local/bin non venivano trovati e restavano fuori whitelist in
// silenzio. Ora si cerca anche in /snap/bin, ~/.local/bin e ~/bin prima di
// arrendersi. Resta il rimedio migliore: path assoluti nelle regole.
func resolveExe(home, name string) (string, bool) {
	path := name
	if !filepath.IsAbs(name) {
		if p, err := exec.LookPath(name); err == nil {
			path = p
		} else {
			// Fallback: directory tipiche fuori dal PATH minimale di systemd.
			fallback := []string{"/snap/bin", filepath.Join(home, ".local/bin"), filepath.Join(home, "bin")}
			found := ""
			for _, d := range fallback {
				cand := filepath.Join(d, name)
				if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
					found = cand
					break
				}
			}
			if found == "" {
				return "", false
			}
			path = found
		}
	}
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false
	}
	return path, true
}

// trustedExe verifica che un utente non root non possa sostituire o modificare
// il binario: il file e ogni directory padre devono essere di root, non
// scrivibili da "others" e scrivibili dal gruppo solo se il gruppo e' root.
// Basta un anello debole (es. una dir padre dell'utente) per rinominare o
// riscrivere il binario e ereditarne l'autorizzazione.
func trustedExe(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			return fmt.Errorf("stat %s: %w", p, err)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s appartiene a uid %d, non a root", p, st.Uid)
		}
		if st.Mode&0o002 != 0 {
			return fmt.Errorf("%s scrivibile da chiunque", p)
		}
		if st.Mode&0o020 != 0 && st.Gid != 0 {
			return fmt.Errorf("%s scrivibile dal gruppo %d", p, st.Gid)
		}
		if p == "/" || p == "." {
			return nil
		}
	}
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

// CheckFilesystem avvisa se la home vive su un fs dove la chiave dev+inode non
// matcha tra userspace e kernel (btrfs subvolume, overlayfs Docker).
// FIX: prima la protezione era silenziosamente inerte su questi fs: nessun log,
// nessun errore, solo test manuale in TESTING.md a rivelarlo. Ora il demone lo
// dice a avvio. Chiamato una volta da main, non a ogni Sync.
func CheckFilesystem(home string) {
	var st unix.Statfs_t
	if err := unix.Statfs(home, &st); err != nil {
		return // non bloccante: se non si puo' leggere, non si puo' dire nulla
	}
	const (
		btrfsSuperMagic   = 0x9123683E
		overlaySuperMagic = 0x794C7630
	)
	switch st.Type {
	case btrfsSuperMagic:
		log.Printf("⚠️ home su btrfs: st_dev userspace != s_dev kernel, la chiave dev+inode NON matcha. Protezione LSM inerte: verifica con TESTING.md Test 1")
	case overlaySuperMagic:
		log.Printf("⚠️ home su overlayfs: st_dev userspace != s_dev kernel, la chiave dev+inode NON matcha. Protezione LSM inerte")
	}
}
