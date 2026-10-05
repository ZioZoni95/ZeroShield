// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

package netstat

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestSplitAddr(t *testing.T) {
	cases := []struct {
		in   string
		v6   bool
		addr string
		port uint16
		ok   bool
	}{
		{"0100007F:0277", false, "127.0.0.1", 631, true},
		{"00000000:0016", false, "0.0.0.0", 22, true},
		{"00000000000000000000000001000000:0016", true, "::1", 22, true},
		{"0000000000000000FFFF00000100007F:0050", true, "127.0.0.1", 80, true}, // v4-mapped
		{"B80D0120000000000000000001000000:01BB", true, "2001:db8::1", 443, true},
		{"0100007F", false, "", 0, false},       // senza porta
		{"0100:0050", false, "", 0, false},      // IP troppo corto
		{"ZZ00007F:0050", false, "", 0, false},  // non esadecimale
		{"0100007F:FFFFF", false, "", 0, false}, // porta oltre 16 bit
		{"00000000:0016", true, "", 0, false},   // v6 atteso, v4 trovato
	}
	for _, c := range cases {
		addr, port, ok := splitAddr(c.in, c.v6)
		if ok != c.ok || addr != c.addr || port != c.port {
			t.Errorf("splitAddr(%q,%v) = %q,%d,%v; atteso %q,%d,%v", c.in, c.v6, addr, port, ok, c.addr, c.port, c.ok)
		}
	}
}

// fakeProc costruisce un /proc minimo: tabelle di rete + processi con fd socket.
type fakeProc struct {
	t    *testing.T
	root string
}

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &fakeProc{t: t, root: root}
}

func (f *fakeProc) table(name string, lines ...string) {
	f.t.Helper()
	body := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(f.root, "net", name), []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeProc) proc(pid int, exe string, inodes ...string) {
	f.t.Helper()
	dir := filepath.Join(f.root, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		f.t.Fatal(err)
	}
	for i, ino := range inodes {
		if err := os.Symlink("socket:["+ino+"]", filepath.Join(dir, "fd", strconv.Itoa(i+3))); err != nil {
			f.t.Fatal(err)
		}
	}
}

const (
	tcpListen22  = "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 100 0 0 10 0"
	tcpEstab     = "   1: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 1002 1 0 100 0 0 10 0"
	udpMdns      = "   2: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   108        0 2001 2 0 0"
	udpConnected = "   3: 0100007F:9C41 0100007F:0035 01 00000000:00000000 00:00000000 00000000  1000        0 2002 2 0 0"
	udp6Llmnr    = "   4: 00000000000000000000000000000000:14EB 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 2003 2 0 0"
)

func TestListeningFiltersTCPAndUDP(t *testing.T) {
	f := newFakeProc(t)
	f.table("tcp", tcpListen22, tcpEstab)
	f.table("udp", udpMdns, udpConnected)
	f.table("udp6", udp6Llmnr)
	f.proc(500, "/usr/sbin/sshd", "1001")
	f.proc(77, "/usr/sbin/avahi-daemon", "2001")

	got, total := listening(f.root, 100)
	if total != 3 || len(got) != 3 {
		t.Fatalf("attese 3 voci (tcp LISTEN, udp bound, udp6 bound), trovate %d: %+v", total, got)
	}
	want := map[string]string{"tcp/22": "/usr/sbin/sshd", "udp/5353": "/usr/sbin/avahi-daemon", "udp6/5355": ""}
	for _, e := range got {
		key := e.Proto + "/" + strconv.Itoa(int(e.Port))
		exe, ok := want[key]
		if !ok {
			t.Errorf("voce inattesa %+v (TCP stabilito o UDP connesso non sono 'in ascolto')", e)
			continue
		}
		if e.Exe != exe {
			t.Errorf("%s: exe %q, atteso %q", key, e.Exe, exe)
		}
	}
}

func TestListeningOrderIsStableAndCapped(t *testing.T) {
	f := newFakeProc(t)
	var lines []string
	for i := 0; i < 10; i++ {
		// porte discendenti 0x0050+... in ordine sparso
		port := []string{"0050", "0016", "01BB", "1F90", "0035", "0019", "006E", "0143", "03E1", "00A1"}[i]
		lines = append(lines, "   "+strconv.Itoa(i)+": 00000000:"+port+" 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 "+strconv.Itoa(3000+i)+" 1 0 100 0 0 10 0")
	}
	f.table("tcp", lines...)
	first, total := listening(f.root, 4)
	if total != 10 || len(first) != 4 {
		t.Fatalf("totale %d, restituite %d: il tetto deve troncare ma dichiarare il totale", total, len(first))
	}
	for i := 1; i < len(first); i++ {
		if first[i-1].Port >= first[i].Port {
			t.Errorf("ordine non crescente per porta: %+v", first)
		}
	}
	for i := 0; i < 20; i++ {
		again, _ := listening(f.root, 4)
		for j := range again {
			if again[j] != first[j] {
				t.Fatalf("ordine instabile tra due snapshot: %+v vs %+v", first, again)
			}
		}
	}
}

// Piu' processi sullo stesso socket (fork): vince il PID piu' basso, sempre.
// "999" e "1000": con l'ordine lessicografico di Glob vinceva 1000.
func TestListeningLowestPIDWins(t *testing.T) {
	f := newFakeProc(t)
	f.table("tcp", tcpListen22)
	f.proc(1000, "/usr/sbin/sshd-child", "1001")
	f.proc(999, "/usr/sbin/sshd", "1001")
	got, _ := listening(f.root, 10)
	if len(got) != 1 || got[0].PID != 999 || got[0].Exe != "/usr/sbin/sshd" {
		t.Fatalf("atteso PID 999, trovato %+v", got)
	}
}

func TestListeningMissingProc(t *testing.T) {
	got, total := listening(t.TempDir(), 10)
	if len(got) != 0 || total != 0 {
		t.Errorf("senza /proc non devono comparire voci: %+v", got)
	}
}

func TestScanProtoIgnoresGarbage(t *testing.T) {
	f := newFakeProc(t)
	f.table("tcp", "corta", "", "   0: zz:zz 00000000:0000 0A 0 0 0 0 0 0 1 1 1 1 1 1", tcpListen22)
	got, _ := listening(f.root, 10)
	if len(got) != 1 || got[0].Port != 22 {
		t.Errorf("righe malformate devono essere scartate senza panic: %+v", got)
	}
}
