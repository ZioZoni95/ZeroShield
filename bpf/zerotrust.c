// Copyright (c) 2026 ZioZoni95
// SPDX-License-Identifier: MIT

// Codice kernel-space di zt-shield.
//
// Due programmi eBPF, caricati in un unico oggetto:
//
//   1. SEC("xdp")          - gira nel contesto del driver di rete, alla RICEZIONE,
//                            prima dello stack TCP/IP e prima di netfilter. Vede solo
//                            i pacchetti in ingresso e puo' scartarli senza allocare.
//   2. SEC("lsm/file_open") - invocato dal kernel per OGNI open() di OGNI processo del
//                            sistema. Restituire un errno negativo nega l'operazione.
//
// I programmi non possono chiamare funzioni libc: solo helper BPF e accesso diretto
// alla memoria del kernel tramite BPF_CORE_READ (CO-RE, rilocato a runtime via BTF,
// quindi lo stesso oggetto resta valido tra versioni diverse di kernel).
//
// Compilazione e link con il Go: gestiti da bpf2go (vedi bpf/gen.go).
//
// Nota: `//go:build ignore` qui sotto e' rumore. I build tag sono un concetto del
// toolchain Go, che non compila mai i .c.

//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// EtherType IPv4 (+ VLAN taggate, scartate prima solo perche' non parsate).
// Il resto (ARP, IPv6, PPPoE) esce dal confronto: coperto da resolved/UFW, non da XDP.
#define ETH_P_IP 0x0800
#define ETH_P_8021Q 0x8100 // VLAN singola
#define ETH_P_8021AD 0x88A8 // QinQ (solo outer tag scartato, poi si rivaluta)

// FMODE_READ per struct file->f_mode: se un open e' write-only (creazione chiave,
// truncate log, backup in scrittura) non contiene dati da esfiltrare in lettura.
// Bloccare anche O_WRONLY rompe ssh-keygen e i backup senza aggiungere sicurezza.
#define FMODE_READ 0x1

// Errno restituito all'utente quando l'accesso e' negato. Deve essere NEGATIVO:
// il contratto degli hook LSM e' "0 = consenti, <0 = nega con errno".
// (Restituirlo positivo e' un errore classico: l'utente vede successo e nessun errore.)
#define EACCES   13

// Indici nella mappa `settings`. Chiavi intere perche' sono gli unici indici
// di array semplici usabili in BPF senza costruire struct.
#define SETTING_ENFORCE 0 // 1 = nega l'accesso, 0 = solo audit (logga e lascia passare)
#define SETTING_POISON  1 // 1 = drop LLMNR/mDNS/NBT-NS in ingresso

// Obbligatoria: senza, il kernel non autorizza gli helper GPL-only e i programmi
// che usano BPF_CORE_READ vengono rifiutati dal loader.
char LICENSE[] SEC("license") = "GPL";

// ---------------------------------------------------------------------------
// Layout delle chiavi
// ---------------------------------------------------------------------------
//
// Regola generale: il layout C deve essere IDENTICO a quello Go
// (internal/lsm/lsm.go, internal/xdp/xdp.go). Se divergono, i campi vengono letti
// sfalsati o i match falliscono in silenzio. I `pad` espliciti servono a due
// motivi: allineare la struct ai requisiti del tipo di mappa, e occupare i byte di
// padding che il compilatore inserirebbe comunque, rendendoli espliciti.

// Chiave della trie LPM: lunghezza del prefisso in bit + indirizzo IPv4.
// I bit di host dell'indirizzo devono essere ZERO, altrimenti la lookup non
// matcha: per questo Go usa l'indirizzo gia' mascherato di ParseCIDR.
struct lpm_key {
    __u32 prefixlen;
    __u8  addr[4]; // network byte order, copiato grezzo da __be32
};

// Identita' di un file: inode + device, con padding esplicito per allineare a 16 byte.
// L'inode da solo non e' univoco: lo stesso numero su due filesystem sono due file
// diversi. `dev` e' i_sb->s_dev, il device del superblocco.
struct file_key {
    __u64 ino;
    __u32 dev;
    __u32 pad;
};

// Coppia (regola, binario autorizzato). Layout identico a file_key: il terzo campo
// e' l'id della regola invece del padding, cosi' la whitelist e' per regola.
// Chiave tripla: la stessa chiave privata puo' valere per piu' regole senza conflitti.
struct allow_key {
    __u64 ino;
    __u32 dev;
    __u32 rule;
};

// ---------------------------------------------------------------------------
// Mappe
// ---------------------------------------------------------------------------

// Impostazioni lette dai programmi a ogni invocazione. Array invece che hash: le
// chiavi sono due interi costanti, quindi lookup O(1) senza hash.
// La mappa vive in userspace: Go la aggiorna, il kernel la legge. Se manca una voce,
// setting() restituisce il default, quindi un programma caricato da solo funziona.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} settings SEC(".maps");

// Subnet da scartare in XDP, in Longest Prefix Match.
// NO_PREALLOC: le chiavi hanno lunghezza variabile, la preallocazione non ha senso.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} infected_subnets SEC(".maps");

// File protetti -> id regola (>= 1). Valore 0 significa "non protetto".
// 16384 entry perche' le regole sui browser possono coprire centinaia di profili e
// database di login senza saturare la mappa.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct file_key);
    __type(value, __u32);
} protected_files SEC(".maps");

// Binari autorizzati per regola -> 1. La chiave (dev, ino, rule) e' il cuore della
// sicurezza di questo programma: vedi la sezione dell'hook LSM.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct allow_key);
    __type(value, __u32);
} allowed_exes SEC(".maps");

// ---------------------------------------------------------------------------
// Eventi verso userspace
// ---------------------------------------------------------------------------
//
// Il layout DEVE combaciare con audit.Event in internal/audit/audit.go.
// Offsets: pid@0, comm@4, rule@20, ino@24, action@32, pad@36, sizeof=40.
// `action` distingue bloccato (1) da solo-audit (0): in audit si osserva cosa
// sarebbe successo senza rompere nulla.

struct audit_event {
    __u32 pid;
    char  comm[16]; // TASK_COMM_LEN: troncato dal kernel, non null-terminato
    __u32 rule;
    __u64 ino;
    __u32 action; // 1 = bloccato, 0 = solo audit
    __u32 pad;    // allinea sizeof a 40/8
};

// Ring buffer: coda circolare lock-free tra producer (il kernel) e consumer (Go).
// Se e' pieno, reserve restituisce NULL e l'evento viene perso: corretto, un audit
// log non deve mai bloccare il sistema.
// 256 KB: abbastanza per non perdere eventi in raffica, non abbastanza da pesare
// sulla memoria.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} audit_logs SEC(".maps");

// Helper: legge un'impostazione con fallback. __always_inline perche' una funzione
// esterna non e' ammessa in BPF e il verifier la richiede sempre inlined.
static __always_inline __u32 setting(__u32 key, __u32 def) {
    __u32 *v = bpf_map_lookup_elem(&settings, &key);
    return v ? *v : def;
}

// ---------------------------------------------------------------------------
// 1. XDP: protocolli di poisoning + subnet ostili
// ---------------------------------------------------------------------------
//
// Punto di osservazione: driver di rete, in ricezione. Da qui due vantaggi: nessuna
// allocazione e nessun percorso nel kernel, quindi il drop e' a costo ~null. Il
// rovescio e' che questo e' XDP in *generic mode* (vedi internal/xdp), che si inserisce
// nel percorso software e non in quello hardware del driver.
//
// Bounds checking: in BPF non esiste la segnalazione di errori. Ogni dereferenziatura
// deve essere preceduta da un confronto esplicito con data_end, altrimenti il verifier
// rifiuta il programma. Il pattern e' sempre lo stesso: calcolare il puntatore
// all'elemento successivo e verificare che non superi data_end PRIMA di leggerlo.
SEC("xdp")
int xdp_shield(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Header Ethernet: 14 byte (mac dst, mac src, ethertype).
    // VLAN: un tag 802.1Q aggiunge 4 byte. Senza unwrap tutto il traffico
    // su LAN taggate (aziendale tipica) passava senza alcun controllo.
    // Si gestisce un solo livello: QinQ doppio-tag resta PASS (raro su workstation).
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // pacchetto troncato: lascialo allo stack
    __u16 proto = bpf_ntohs(eth->h_proto);
    void *nh = (void *)(eth + 1);
    if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
        struct vlan_hdr *vh = nh;
        if ((void *)(vh + 1) > data_end)
            return XDP_PASS;
        proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
        nh = (void *)(vh + 1);
    }
    if (proto != ETH_P_IP)
        return XDP_PASS; // ARP/IPv6/PPPoE: niente da fare qui

    // Header IP: variabile (20 + opzioni). Pacchetti troncati o malformi
    // passano oltre e li gestira' il kernel.
    struct iphdr *ip = nh;
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // -- Drop dei protocolli di poisoning -------------------------------------------------
    // LLMNR (5355), mDNS (5353), NBT-NS (137), NetBIOS-DGM (138).
    if (ip->protocol == IPPROTO_UDP && setting(SETTING_POISON, 1)) {
        // Frammenti non-primi: non contengono l'header UDP all'offset calcolato.
        // Leggere sport/dport li' significa leggere payload casuale -> falso drop
        // o mancato drop. Si salta il check L4 (resta il check subnet su saddr).
        // frag_off e' in network order: maschera 0x3FFF = offset+MF, 0x2000 = MF.
        // Si usa bpf_ntohs prima della maschera per confronto corretto.
        __u16 frag = bpf_ntohs(ip->frag_off);
        if ((frag & 0x3FFF) == 0) {
            __u32 ihl = ip->ihl * 4; // IHL e' espresso in word da 32 bit
            if (ihl >= sizeof(*ip)) { // header senza opzioni o piu': non puo' andare in underflow
                struct udphdr *udp = (void *)ip + ihl;
                if ((void *)(udp + 1) <= data_end) { // 8 byte: sport + dport + len + checksum
                    __u16 sport = bpf_ntohs(udp->source);
                    __u16 dport = bpf_ntohs(udp->dest);

                    // FIX: si controllano SIA sport SIA dport. La risposta avvelenata
                    // di Responder/Inveigh viaggia con sport=5355 e dport effimera:
                    // guardare solo dport intercettava le query altrui, non l'attacco.
                    if (sport == 5355 || dport == 5355 ||
                        sport == 5353 || dport == 5353 ||
                        sport == 137 || dport == 137 ||
                        sport == 138 || dport == 138)
                        return XDP_DROP;
                }
            }
        }
    }

    // -- Drop delle subnet ostili --------------------------------------------------------
    // Lookup a /32: con la LPM una ricerca a /32 trova anche le entry piu' corte,
    // quindi basta inserire /24 e interrogare con /32.
    struct lpm_key key = { .prefixlen = 32 };
    // __be32 -> 4 byte grezzi = network byte order, l'ordine atteso dalla trie.
    // Non usare bpf_ntohl qui: la chiave deve restare in network order.
    __builtin_memcpy(key.addr, &ip->saddr, 4);

    __u32 *blocked = bpf_map_lookup_elem(&infected_subnets, &key);
    if (blocked && *blocked == 1)
        return XDP_DROP;

    // Nota: il drop e' su saddr, quindi scarta il traffico PROVENIENTE dalle subnet
    // bloccate, risposte comprese. Dopo una compromissione di rete l'attaccante e' gia'
    // nella tua stessa LAN, quindi questa regola non lo raggiunge: serve a filtrare
    // scansioni da reti note, non a fermare un host interno.
    return XDP_PASS;
}

// ---------------------------------------------------------------------------
// 2. LSM: isolamento dei segreti
// ---------------------------------------------------------------------------
//
// lsm/file_open viene chiamato dal kernel per ogni open() di tutto il sistema:
// systemd, dbus, container, tutto. Il costo percorso e' UNA lookup in una hash map
// da 8 byte, trascurabile.
//
// Regola implementata: "un file e' segreto se e' in protected_files; puo' aprirlo solo
// il binario la cui immagine eseguibile e' in allowed_exes per la stessa regola".
//
// Perche' exe_file e non comm: `comm` e' il nome del thread e puo' essere cambiato da
// QUALSIASI processo senza privilegi con prctl(PR_SET_NAME). exe_file e' l'inode
// dell'immagine eseguibile, che un processo utente non puo' spoofare.
//
// Limite noto e strutturale: i binari in whitelist sono lettori di file con opzioni
// controllate dall'utente. `git hash-object ~/.kube/config` apre quel file con
// exe_file=/usr/bin/git, che e' in whitelist: la verifica regge, ma "chi apre" e'
// scelto da chiunque passi per git o aws. Non e' un bug implementabile via patch:
// e' una conseguenza di mettere in whitelist binari che leggono file.
SEC("lsm/file_open")
int BPF_PROG(zt_file_open, struct file *file) {
    // Write-only open (creazione chiavi, truncate, backup in scrittura): non
    // esfiltra nulla in lettura, quindi si lascia passare. Senza questo check
    // ssh-keygen su ~/.ssh/id_* nuova e i backup venivano negati anche a root.
    // f_mode e' letto con CORE perche' l'offset cambia tra versioni kernel.
    fmode_t fmode = BPF_CORE_READ(file, f_mode);
    if (!(fmode & FMODE_READ))
        return 0;

    // Il file che sta per essere aperto.
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0; // impossibile in pratica: fail-open

    // Chiave del file target. i_sb->s_dev e' il device del superblocco: corrisponde
    // a st_dev in userspace su ext4/xfs, ma DIVERGE su btrfs (subvolume) e overlayfs
    // (Docker). Su questi filesystem la chiave non matcha e la protezione e' silenziosamente
    // inerte. Se stai su Docker o btrfs, verifica con il test 1 di TESTING.md.
    struct file_key fk = {};
    fk.ino = BPF_CORE_READ(inode, i_ino);
    fk.dev = BPF_CORE_READ(inode, i_sb, s_dev);

    __u32 *rp = bpf_map_lookup_elem(&protected_files, &fk);
    if (!rp)
        return 0; // file non protetto: percorso caldo, esce subito
    __u32 rule = *rp; // id della regola che protegge questo file

    // -- Identita' del processo chiamante -------------------------------------------------
    // exe_file e' l'immagine eseguibile del processo (per uno script e' l'interprete).
    // Lettura a stadi con null-check: il verifier rifiuta la catena singola
    // task->mm->exe_file->f_inode e i kernel thread hanno mm=NULL.
    // Senza stadi, rischio di reject al load o fault su thread kernel.
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task)
        return 0;
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0; // kernel thread / io_uring worker senza mm: fail-open, non blocco
    struct file *exe_file = BPF_CORE_READ(mm, exe_file);
    if (!exe_file)
        return 0;
    struct inode *exe = BPF_CORE_READ(exe_file, f_inode);
    if (exe) {
        struct allow_key ak = {};
        ak.ino = BPF_CORE_READ(exe, i_ino);
        ak.dev = BPF_CORE_READ(exe, i_sb, s_dev);
        ak.rule = rule; // la stessa chiave privata puo' valere solo per regole diverse
        if (bpf_map_lookup_elem(&allowed_exes, &ak))
            return 0; // binario autorizzato per questa regola
    }

    // NOTA (io_uring): le open via IORING_OP_OPENAT girano in un worker il cui mm
    // puo' essere NULL o diverso dal richiedente. Con il null-check sopra, un worker
    // senza mm passa in fail-open (accesso consentito + nessun evento): falso NEGATIVO
    // mirato, preferito al falso positivo di blocco che c'era prima (tool legittimi
    // con EACCES inspiegabile). Il trade-off e' noto: io_uring resta un canale
    // di bypass per chi sa usarlo, da chiudere con hook dedicati in futuro.
    //
    // NOTA (uid): non c'e' un controllo sull'uid del chiamante, di proposito. Il demone
    // gira come root e l'hook e' globale, quindi anche root e' vincolato. Effetto
    // collaterale: se un binario legittimo non finisce in whitelist, nemmeno root
    // riesce piu' a leggere quel file (backup, rsync, recovery).

    // -- Audit + decisione ----------------------------------------------------------------
    __u32 enforce = setting(SETTING_ENFORCE, 1);

    // reserve + submit invece di output: reserve non puo' fallire per spazio
    // (restituisce NULL) e permette di non scrivere nulla, quindi l'evento non blocca mai.
    struct audit_event *event = bpf_ringbuf_reserve(&audit_logs, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32; // i bit alti sono il tgid
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        event->rule = rule;
        event->ino = fk.ino;
        event->action = enforce ? 1 : 0; // 0 = osservato ma consentito (audit)
        event->pad = 0;
        bpf_ringbuf_submit(event, 0);
    }

    // In audit si restituisce 0: l'accesso passa e l'utente non se ne accorge.
    // In enforce si nega. NOTA: gli open write-only passano (check FMODE_READ
    // in testa): creazione chiavi e backup in scrittura funzionano, resta
    // bloccata solo la lettura/esfiltrazione.
    return enforce ? -EACCES : 0;
}
