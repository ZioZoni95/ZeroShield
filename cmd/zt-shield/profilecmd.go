// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"zt-shield/internal/config"
	"zt-shield/pkg/rules"
	"zt-shield/pkg/svc"
)

// runProfile: `zt-shield profile export|import ...` (senza privilegi per l'anteprima; l'applicazione passa da
// svc.ApplyConfig, cioe' pkexec + config-apply con backup e ripristino, come la GUI).
func runProfile(args []string) int {
	return profileMain(args, os.Stdout, os.Stderr, readSystemConfig, svc.ApplyConfig, time.Now)
}

func readSystemConfig() (string, error) {
	b, err := os.ReadFile(config.DefaultPath)
	if err != nil {
		return "", fmt.Errorf("config di sistema non leggibile (%s): installa prima il servizio", config.DefaultPath)
	}
	return string(b), nil
}

const profileUsage = `uso:
  zt-shield profile export [-name NOME] [-note TESTO] [-o FILE] [-f]
      scrive le tue scelte (programmi autorizzati, protezioni, modalità, regole personali, filtro di rete, canary)
      in un file da portare su un'altra macchina. Non contiene utente, interfaccia, VPN né percorsi nella home.
  zt-shield profile import [-replace] [-keep-modes] [-yes] FILE
      mostra cosa cambierebbe. Senza -yes non scrive nulla. Con -yes applica (password di sistema).
      -replace      sostituisce le scelte attuali invece di unirle
      -keep-modes   conserva le modalità del profilo (di norma si importa in sola osservazione)
`

func profileMain(args []string, stdout, stderr io.Writer, readCfg func() (string, error), apply func(string) error, now func() time.Time) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, profileUsage)
		return 2
	}
	switch args[0] {
	case "export":
		return profileExport(args[1:], stdout, stderr, readCfg, now)
	case "import":
		return profileImport(args[1:], stdout, stderr, readCfg, apply)
	}
	fmt.Fprint(stderr, profileUsage)
	return 2
}

func profileExport(args []string, stdout, stderr io.Writer, readCfg func() (string, error), now func() time.Time) int {
	fs := flag.NewFlagSet("profile export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "nome del profilo (es. Ufficio)")
	note := fs.String("note", "", "nota libera")
	out := fs.String("o", "", "file di destinazione (default: standard output)")
	force := fs.Bool("f", false, "sovrascrive il file se esiste")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := readCfg()
	if err != nil {
		fmt.Fprintln(stderr, "profile export:", err)
		return 1
	}
	data, left, err := rules.Export(cfg, rules.ExportOptions{Name: *name, Note: *note, Version: version, Now: now()})
	if err != nil {
		fmt.Fprintln(stderr, "profile export:", err)
		return 1
	}
	for _, l := range left {
		fmt.Fprintln(stderr, "non esportato:", l)
	}
	if *out == "" {
		_, _ = stdout.Write(data)
		return 0
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if *force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(*out, flags, 0o644)
	if err != nil {
		if os.IsExist(err) {
			fmt.Fprintf(stderr, "profile export: %s esiste già (usa -f per sovrascrivere)\n", *out)
		} else {
			fmt.Fprintln(stderr, "profile export:", err)
		}
		return 1
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		fmt.Fprintln(stderr, "profile export:", werr)
		return 1
	}
	fmt.Fprintf(stdout, "profilo scritto in %s\n", *out)
	return 0
}

func profileImport(args []string, stdout, stderr io.Writer, readCfg func() (string, error), apply func(string) error) int {
	fs := flag.NewFlagSet("profile import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	replace := fs.Bool("replace", false, "sostituisce le scelte attuali")
	keep := fs.Bool("keep-modes", false, "conserva le modalità del profilo (default: sola osservazione)")
	yes := fs.Bool("yes", false, "applica davvero")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, profileUsage)
		return 2
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "profile import:", err)
		return 1
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, rules.ProfileMaxBytes+1))
	if err != nil {
		fmt.Fprintln(stderr, "profile import:", err)
		return 1
	}
	cfg, err := readCfg()
	if err != nil {
		fmt.Fprintln(stderr, "profile import:", err)
		return 1
	}
	res, err := rules.PreviewImport(cfg, data, rules.ImportOptions{Replace: *replace, AsAudit: !*keep})
	if err != nil {
		fmt.Fprintln(stderr, "profile import:", err)
		return 1
	}
	printPreview(stdout, res, *replace)
	if res.Unchanged {
		return 0
	}
	if !*yes {
		fmt.Fprintln(stdout, "\nNon è stato scritto nulla. Per applicare: aggiungi -yes (chiede la password di sistema).")
		return 0
	}
	if err := apply(res.NewText); err != nil {
		fmt.Fprintln(stderr, "profile import: applicazione non riuscita:", err)
		return 1
	}
	fmt.Fprintln(stdout, "\nApplicato. Il servizio è stato riavviato.")
	return 0
}

func printPreview(w io.Writer, r rules.ImportResult, replace bool) {
	title := r.Name
	if title == "" {
		title = "(senza nome)"
	}
	fmt.Fprintf(w, "Profilo: %s", title)
	if r.ExportedBy != "" {
		fmt.Fprintf(w, "  · creato con ZeroShield %s", r.ExportedBy)
	}
	fmt.Fprintf(w, "\nImpronta SHA-256: %s\n", r.SHA256)
	if r.Note != "" {
		fmt.Fprintf(w, "Nota: %s\n", r.Note)
	}
	if replace {
		fmt.Fprintln(w, "Modo: SOSTITUISCE le scelte attuali.")
	} else {
		fmt.Fprintln(w, "Modo: unisce alle scelte attuali.")
	}
	if r.Unchanged {
		fmt.Fprintln(w, "\nNessuna differenza: questa macchina ha già queste scelte.")
	} else {
		fmt.Fprintln(w, "\nCosa cambierebbe:")
		for _, c := range r.Changes {
			sign := map[string]string{"add": "+", "remove": "-"}[c.Kind]
			if sign == "" {
				sign = "~"
			}
			fmt.Fprintf(w, "  %s %s\n", sign, c.Text)
		}
	}
	if len(r.Skipped) > 0 {
		fmt.Fprintln(w, "\nNon importato:")
		for _, s := range r.Skipped {
			fmt.Fprintln(w, "  ✗", s)
		}
	}
	if len(r.Warnings) > 0 {
		fmt.Fprintln(w, "\nDa sapere:")
		for _, s := range r.Warnings {
			fmt.Fprintln(w, "  !", s)
		}
	}
}
