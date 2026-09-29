// Package audit consuma gli eventi del ring buffer e li stampa in formato text o JSON.
package audit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

// Event ha lo stesso layout di audit_event in zerotrust.c (40 byte, padding esplicito).
type Event struct {
	PID    uint32
	Comm   [16]byte
	Rule   uint32
	Inode  uint64
	Action uint32
	Pad    uint32
}

type jsonEntry struct {
	Time   string `json:"time"`
	Action string `json:"action"`
	PID    uint32 `json:"pid"`
	Comm   string `json:"comm"`
	Exe    string `json:"exe,omitempty"`
	Rule   string `json:"rule"`
	Inode  uint64 `json:"inode"`
}

// Run legge finché il reader non viene chiuso. ruleName traduce l'id regola in nome.
func Run(rd *ringbuf.Reader, format string, ruleName func(uint32) string) {
	enc := json.NewEncoder(os.Stdout)
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var ev Event
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		comm := string(bytes.TrimRight(ev.Comm[:], "\x00"))
		// Best effort: il processo potrebbe essere già terminato. Utile per sapere quale binario autorizzare.
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", ev.PID))
		action := "audit"
		if ev.Action == 1 {
			action = "blocked"
		}

		if format == "json" {
			enc.Encode(jsonEntry{
				Time: time.Now().UTC().Format(time.RFC3339), Action: action, PID: ev.PID,
				Comm: comm, Exe: exe, Rule: ruleName(ev.Rule), Inode: ev.Inode,
			})
			continue
		}
		icon := "👁️ [AUDIT]"
		if ev.Action == 1 {
			icon = "🚨 [BLOCCATO]"
		}
		log.Printf("%s regola=%s PID=%d comm='%s' exe=%s inode=%d", icon, ruleName(ev.Rule), ev.PID, comm, exe, ev.Inode)
	}
}
