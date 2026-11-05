// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"strconv"
	"strings"

	"zt-shield/pkg/ipc"
)

// Stato mostrato dall'icona. L'ordine non conta, il significato si'.
type state int

const (
	stDown     state = iota // demone non raggiungibile: rosso
	stDegraded              // enforce ma senza hook LSM: giallo
	stAudit                 // solo registra, non blocca: giallo
	stOK                    // enforce con hook attivo: blu
)

// classify traduce lo stato del demone in uno stato d'icona. Un errore e'
// sempre "down": se non riusciamo a leggere il socket non possiamo dire altro.
func classify(st ipc.Status, err error) state {
	switch {
	case err != nil:
		return stDown
	case st.Mode == "audit":
		return stAudit
	case !st.HookLSM:
		return stDegraded
	default:
		return stOK
	}
}

func (s state) label() string {
	switch s {
	case stOK:
		return "Protezione attiva"
	case stAudit:
		return "Attivo in modalità audit (registra, non blocca)"
	case stDegraded:
		return "Attivo ma senza blocco dei file (hook LSM non agganciato)"
	default:
		return "Demone spento o non raggiungibile"
	}
}

func (s state) rgb() color.RGBA {
	switch s {
	case stOK:
		return color.RGBA{0x1f, 0x6f, 0xeb, 0xff}
	case stAudit, stDegraded:
		return color.RGBA{0xd9, 0x9a, 0x06, 0xff}
	default:
		return color.RGBA{0xd7, 0x3a, 0x49, 0xff}
	}
}

// iconPNG disegna uno scudo colorato con una spunta (o una croce se spento).
// Generato a runtime: niente asset binari da versionare, un colore per stato.
func iconPNG(s state) []byte {
	const n = 64
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	fill := s.rgb()
	white := color.RGBA{255, 255, 255, 255}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if inShield(float64(x)+0.5, float64(y)+0.5, n) {
				img.SetRGBA(x, y, fill)
			}
		}
	}
	line := func(x0, y0, x1, y1 float64) {
		for t := 0.0; t <= 1; t += 0.005 {
			cx, cy := x0+(x1-x0)*t, y0+(y1-y0)*t
			for dy := -3; dy <= 3; dy++ {
				for dx := -3; dx <= 3; dx++ {
					if dx*dx+dy*dy <= 9 {
						px, py := int(cx)+dx, int(cy)+dy
						if px >= 0 && py >= 0 && px < n && py < n && img.RGBAAt(px, py).A != 0 {
							img.SetRGBA(px, py, white)
						}
					}
				}
			}
		}
	}
	if s == stDown {
		line(22, 22, 42, 42)
		line(42, 22, 22, 42)
	} else {
		line(21, 33, 29, 41)
		line(29, 41, 44, 24)
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}

// inShield: lati dritti in alto, poi la punta si stringe verso il basso.
func inShield(x, y, n float64) bool {
	top, bottom, half := n*0.08, n*0.95, n*0.40
	if y < top || y > bottom {
		return false
	}
	mid := n * 0.5
	w := half
	if y > n*0.5 {
		f := (y - n*0.5) / (bottom - n*0.5)
		w = half * math.Sqrt(1-f*f)
	}
	return math.Abs(x-mid) <= w
}

// guiRunning dice se esiste un processo "zt-gui". Serve a non duplicare le
// notifiche: con la GUI aperta le manda lei, a GUI chiusa le manda l'icona.
func guiRunning(procRoot string) bool {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(procRoot + "/" + e.Name() + "/comm")
		if err == nil && strings.TrimSpace(string(b)) == "zt-gui" {
			return true
		}
	}
	return false
}
