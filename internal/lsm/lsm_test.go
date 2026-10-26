// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package lsm

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"zt-shield/internal/config"
)

func TestTrustedExeSystemBinary(t *testing.T) {
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("niente /bin/sh")
	}
	if err := trustedExe(sh); err != nil {
		t.Fatalf("binario di sistema rifiutato: %v", err)
	}
}

func TestTrustedExeRejectsWritable(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "aws")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Non root: la tempdir e' dell'utente, va rifiutata.
	// Root: la tempdir e' di root ma /tmp e' scrivibile da tutti, idem.
	if err := trustedExe(exe); err == nil {
		t.Fatal("binario in directory utente/temp accettato")
	}
	if os.Geteuid() == 0 {
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := trustedExe(exe); err == nil {
			t.Fatal("binario in directory world-writable accettato")
		}
	}
}

func TestExpandSkipsForeignSymlink(t *testing.T) {
	home := t.TempDir()
	own := filepath.Join(home, ".ssh", "id_ok")
	if err := os.MkdirAll(filepath.Dir(own), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Symlink dell'utente verso un file di sistema: non deve diventare "segreto".
	if err := os.Symlink("/etc/hostname", filepath.Join(home, ".ssh", "id_evil")); err != nil {
		t.Fatal(err)
	}
	uid := int64(os.Getuid())
	if uid == 0 {
		// Da root /etc/hostname e' dello stesso uid: simula un utente diverso.
		uid = 4242
		if err := os.Chown(own, 4242, 4242); err != nil {
			t.Fatal(err)
		}
	}
	got := expand(home, ".ssh/id_*", uid)
	if len(got) != 1 || got[0] != own {
		t.Fatalf("expand = %v, atteso solo %s", got, own)
	}
	// Pattern assoluto (admin): nessun filtro proprietario.
	if got := expand(home, "/etc/hostname", uid); len(got) != 1 {
		t.Fatalf("pattern assoluto filtrato: %v", got)
	}
}

func writeFiles(t *testing.T, dir string, n int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func hasKey(t *testing.T, sel selection, path string) bool {
	t.Helper()
	k, ok := fileKey(path)
	if !ok {
		t.Fatalf("stat %s", path)
	}
	_, in := sel.want[k]
	return in
}

// Un processo che inonda una directory protetta non deve spingere fuori le chiavi vere
// di un'altra regola, ne' quelle nominate esplicitamente nella stessa.
func TestSelectFilesFloodDoesNotEvictRealSecrets(t *testing.T) {
	home := t.TempDir()
	// Regola "browser": directory enorme riempita da un processo ostile.
	writeFiles(t, filepath.Join(home, "flood"), 4500)
	// Regola "ssh": una chiave vera, nominata.
	key := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	rules := []config.Rule{
		{Name: "browser", Paths: []string{"flood"}, Allow: []string{"x"}},
		{Name: "ssh", Paths: []string{".ssh/id_*"}, Allow: []string{"ssh"}},
	}
	sel := selectFiles(home, rules, -1)
	if !hasKey(t, sel, key) {
		t.Fatal("la chiave vera e' stata sfrattata dal diluvio")
	}
	walked := len(sel.want) - 1
	if walked != maxWalkedPerRule {
		t.Errorf("file della regola inondata = %d, atteso il tetto %d", walked, maxWalkedPerRule)
	}
	if sel.dropped["browser"] != 4500-maxWalkedPerRule {
		t.Errorf("scartati dichiarati = %d, attesi %d", sel.dropped["browser"], 4500-maxWalkedPerRule)
	}
	if _, bad := sel.dropped["ssh"]; bad {
		t.Error("la regola ssh non ha perso nulla")
	}
}

// Anche con la mappa piena di file "camminati", i file nominati dell'ultima regola
// entrano comunque, e il totale non supera mai la capienza.
func TestSelectFilesNamedFilesWinWhenMapIsFull(t *testing.T) {
	if testing.Short() {
		t.Skip("crea ~20000 file")
	}
	home := t.TempDir()
	var rules []config.Rule
	for i := 0; i < 5; i++ {
		d := fmt.Sprintf("dir%d", i)
		writeFiles(t, filepath.Join(home, d), 4200)
		rules = append(rules, config.Rule{Name: d, Paths: []string{d}, Allow: []string{"x"}})
	}
	secret := filepath.Join(home, "secret.key")
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	rules = append(rules, config.Rule{Name: "named", Paths: []string{"secret.key"}, Allow: []string{"x"}})
	sel := selectFiles(home, rules, -1)
	if !hasKey(t, sel, secret) {
		t.Fatal("file nominato escluso da una mappa piena")
	}
	if len(sel.want) > maxProtectedFiles {
		t.Errorf("selezione %d > capienza %d", len(sel.want), maxProtectedFiles)
	}
	if len(sel.want) < maxProtectedFiles-1 {
		t.Errorf("la mappa doveva riempirsi: %d", len(sel.want))
	}
}

func TestSelectFilesDeterministic(t *testing.T) {
	home := t.TempDir()
	writeFiles(t, filepath.Join(home, "d"), 50)
	rules := []config.Rule{{Name: "r", Paths: []string{"d"}, Allow: []string{"x"}, DenyWrite: true}}
	a, b := selectFiles(home, rules, -1), selectFiles(home, rules, -1)
	if len(a.want) != 50 || len(b.want) != 50 {
		t.Fatalf("attesi 50 file, avuti %d/%d", len(a.want), len(b.want))
	}
	for k, v := range a.want {
		if b.want[k] != v {
			t.Fatal("selezione non deterministica")
		}
		if v&(1<<31) == 0 || v&^(1<<31) != 1 {
			t.Fatalf("valore %#x: attesi id=1 e bit deny_write", v)
		}
	}
}

func TestWatchBase(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		".ssh/id_*":              filepath.Join(home, ".ssh"),
		".ssh/id_ed25519":        filepath.Join(home, ".ssh"),
		".ssh":                   home,
		".aws/credentials":       home, // ~/.aws non esiste ancora: si guarda la home
		".mozilla/firefox/*/key": home,
	}
	for pat, want := range cases {
		if got := watchBase(home, pat); got != want {
			t.Errorf("watchBase(%q) = %q, atteso %q", pat, got, want)
		}
	}
}

// La finestra di rescan: un file creato o rinominato in una directory osservata fa
// scattare onChange subito, senza aspettare il rescan periodico.
func TestWatcherFiresOnRenameIntoPlace(t *testing.T) {
	dir := t.TempDir()
	fired := make(chan struct{}, 4)
	w, err := NewWatcher(func() { fired <- struct{}{} })
	if err != nil {
		t.Skipf("inotify non disponibile: %v", err)
	}
	defer w.Close()
	w.Set([]string{dir})
	if w.Watched() != 1 {
		t.Fatalf("directory osservate = %d", w.Watched())
	}
	tmp, final := filepath.Join(dir, ".id.tmp"), filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(tmp, []byte("nuova chiave"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, final); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fired:
	case <-time.After(5 * time.Second):
		t.Fatal("nessun rescan dopo il rename")
	}
	// Raffica di eventi: debounce, non un rescan per file.
	for len(fired) > 0 {
		<-fired
	}
	for i := 0; i < 200; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("n%d", i)), nil, 0o600)
	}
	time.Sleep(watchMinGap + time.Second)
	if n := len(fired); n < 1 || n > 2 {
		t.Errorf("raffica di 200 file: %d rescan, attesi 1 (max 2)", n)
	}
	// Set vuoto = niente piu' osservazione.
	w.Set(nil)
	if w.Watched() != 0 {
		t.Error("Set(nil) deve togliere le watch")
	}
}
