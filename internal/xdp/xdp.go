// Package xdp gestisce attach XDP (generic mode) e la trie LPM delle subnet bloccate.
//
// Nota di contesto: il programma XDP di questo progetto fa due cose, drop di 4
// porte UDP e drop di subnet configurate. Entrambe sono replicabili con nftables in
// due righe, senza hook nel driver. XDP serve per filtrare a 10-100 Gbps, non per
// "chiudere delle porte". Qui e' scelto perche' il drop avviene prima dello stack di
// rete e non lascia tracce in conntrack, non perche' sia necessario.
package xdp

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// lpmKey ha lo stesso layout di lpm_key in zerotrust.c.
//
//	prefixlen@0 (4) | addr@4 (4)  = 8 byte
//
// Addr e' l'indirizzo in NETWORK BYTE ORDER, grezzo. Per questo si usa net.IP
// e non un uint32: nel passaggio uint32 <-> struct i byte verrebbero invertiti,
// e la chiave non matcherebbe piu' nessuna subnet. era esattamente il bug della v1.
type lpmKey struct {
	PrefixLen uint32
	Addr      [4]byte
}

// Attach aggancia il programma XDP all'interfaccia indicata, o a quella della route di default.
//
// XDPGenericMode: il programma gira nel percorso software della ricezione invece che
// nel driver nativo. Serve perche' i driver nativi esistono solo per schede
// specifiche (mlx, i40e, e1000e...) e la dev box puo' essere un Wi-Fi, un dongle USB
// o un tunnel VPN. Il prezzo e' prestazioni: in generic mode ogni pacchetto attraversa
// il percorso software, quindi piu' CPU che con il driver nativo.
//
// NOTA: XDP vede SOLO i pacchetti in ingresso. Non e' un filtro di flusso: non
// distingue una connessione da uno scan, e non vede nulla di quello che esce.
//
// BUG: si aggancia a UNA sola interfaccia. Se la route di default passa per un tunnel
// (WireGuard, tailscale) il filtro va sul tunnel e chi arriva dall'Ethernet o dal Wi-Fi
// non incontra nulla. Se invece sei su Wi-Fi con Ethernet attivo, lo stesso vale al
// contrario. Il drop di broadcast in particolare dovrebbe stare su tutte le interfacce
// fisiche: per quello serve un attach multi-interfaccia, non uno solo.
func Attach(prog *ebpf.Program, custom string) (link.Link, *net.Interface, error) {
	iface, err := defaultInterface(custom)
	if err != nil {
		return nil, nil, err
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // universale (Wi-Fi, Ethernet, VPN)
	})
	if err != nil {
		// Errore tipico: un altro programma XDP e' gia' agganciato a questa
		// interfaccia. XDP e' esclusivo per interfaccia, non si accumula.
		return nil, iface, fmt.Errorf("attach XDP su %s: %w", iface.Name, err)
	}
	return l, iface, nil
}

// BlockSubnets inserisce i CIDR IPv4 nella trie.
//
// net.ParseCIDR restituisce due indirizzi: quello passato e quello mascherato alla
// lunghezza della rete. Si usa il mascherato (`ipn.IP`) perche' la trie pretende che
// i bit sotto la maschera siano zero: con l'indirizzo non mascherato la chiave /24
// su 192.168.1.77 non matcherebbe mai.
//
// ATTENZIONE: il drop e' su saddr, quindi scarta anche le RISPOSTE provenienti da
// quelle subnet. Se il gateway o il DNS stanno dentro una subnet bloccata, perdi
// connettivita' e risoluzione. Non includerli.
func BlockSubnets(m *ebpf.Map, cidrs []string) int {
	n := 0
	for _, c := range cidrs {
		_, ipn, err := net.ParseCIDR(c)
		if err != nil || ipn.IP.To4() == nil {
			log.Printf("⚠️ CIDR IPv4 non valido: %q", c)
			continue
		}
		ones, _ := ipn.Mask.Size()
		k := lpmKey{PrefixLen: uint32(ones)}
		copy(k.Addr[:], ipn.IP.To4()) // byte grezzi = network order
		if err := m.Put(k, uint32(1)); err != nil {
			log.Printf("⚠️ subnet %s: %v", c, err)
			continue
		}
		log.Printf("🚫 Subnet bloccata in XDP: %s", c)
		n++
	}
	return n
}

// defaultInterface individua l'interfaccia su cui montare XDP.
//
// Il trucco del Dial UDP: connect() su un socket UDP NON trasmette nulla, non
// genera traffico. Serve solo a far scegliere al kernel la route, e dal LocalAddr
// ottenere l'IP sorgente che quella route avrebbe usato. Piu' economico e senza
// effetti di un pacchetto di prova, che su una rete ostile sarebbe informazione
// donata all'attaccante.
//
// BUG: come sopra, si copre una sola interfaccia. Inoltre, se l'utente ha piu' di
// una scheda attiva, quella scelta silenziosa esclude dalla protezione tutte le altre.
func defaultInterface(custom string) (*net.Interface, error) {
	// Se specificata, si usa quella e basta: nessuna euristica.
	if custom != "" {
		return net.InterfaceByName(custom)
	}
	conn, err := net.Dial("udp", "1.1.1.1:80") // nessun pacchetto inviato: serve solo la route
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)

	// Si riscandaglia tutte le interfacce cercando quella che possiede quell'IP.
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			// Solo *net.IPNet: le voci *net.IPAddr (indirizzo senza maschera)
			// si presentano in alcuni casi e verrebbero ignorate.
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(local.IP) {
				return &ifc, nil
			}
		}
	}
	return nil, fmt.Errorf("nessuna interfaccia di default identificata (imposta 'interface')")
}
