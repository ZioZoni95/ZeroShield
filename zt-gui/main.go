// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

// version: impostata al build con -ldflags "-X main.version=..." (Makefile: gui-bin).
// La GUI la mostra nel sottotitolo di Stato; senza ldflags resta "dev".
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println("zt-gui", version)
		return
	}
	// Create an instance of the app structure
	app := NewApp()

	// Create application with options
	err := wails.Run(&options.App{
		Title:  "ZeroShield",
		Width:  1024,
		Height: 768,
		// Minimo: sotto questa larghezza la barra laterale e' gia' a sole icone e il contenuto a una colonna.
		MinWidth:  480,
		MinHeight: 420,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
