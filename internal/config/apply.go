// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// maxConfigBytes: un config reale sta in poche KiB; il tetto evita di caricare file enormi
// passati per errore (o apposta) a un comando che gira da root.
const maxConfigBytes = 256 << 10

// Install sostituisce dst con il contenuto di src dopo averlo validato con lo stesso parser
// del demone, e lascia una copia di sicurezza accanto a dst. Pensato per girare da root
// (`zt-shield config-apply`), chiamato dalla GUI via pkexec con un file scritto dall'utente:
//
//   - src non puo' essere un symlink (O_NOFOLLOW) ne' un file speciale: root non deve
//     leggere cio' che un utente ha puntato altrove;
//   - il contenuto e' validato PRIMA di toccare dst, e la scrittura e' atomica (temp + rename):
//     un config rotto non sostituisce mai quello buono;
//   - l'utente da proteggere deve risolvere, o il demone morirebbe al riavvio.
//
// Restituisce il percorso del backup ("" se dst non esisteva).
func Install(src, dst string, now time.Time) (string, error) {
	f, err := os.OpenFile(src, os.O_RDONLY|syscallNoFollow, 0)
	if err != nil {
		return "", fmt.Errorf("apertura %s: %w", src, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s non e' un file normale", src)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxConfigBytes {
		return "", fmt.Errorf("%s troppo grande (> %d KiB)", src, maxConfigBytes>>10)
	}

	// Validazione su un file temporaneo privato: Load legge da percorso.
	tmpDir, err := os.MkdirTemp("", "zt-cfg-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)
	probe := filepath.Join(tmpDir, "shield.yaml")
	if err := os.WriteFile(probe, data, 0o600); err != nil {
		return "", err
	}
	cfg, err := Load(probe)
	if err != nil {
		return "", fmt.Errorf("configurazione non valida: %w", err)
	}
	if _, err := cfg.Account(); err != nil {
		return "", fmt.Errorf("configurazione non valida: %w", err)
	}

	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	backup := ""
	if old, err := os.ReadFile(dst); err == nil {
		backup = fmt.Sprintf("%s.bak-%s", dst, now.Format("20060102-150405"))
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			return "", fmt.Errorf("backup: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".shield-new-")
	if err != nil {
		return backup, err
	}
	defer os.Remove(tmp.Name()) // no-op dopo il rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return backup, err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return backup, err
	}
	if err := tmp.Close(); err != nil {
		return backup, err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return backup, err
	}
	return backup, nil
}
