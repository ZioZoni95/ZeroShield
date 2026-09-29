//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800
#define EACCES   13

#define SETTING_ENFORCE 0 // 1 = blocca, 0 = solo audit
#define SETTING_POISON  1 // 1 = drop LLMNR/mDNS/NBT-NS in ingresso

char LICENSE[] SEC("license") = "GPL";

// Chiave LPM: prefisso (bit) + IPv4 in network byte order
struct lpm_key {
    __u32 prefixlen;
    __u8  addr[4];
};

// Identità di un file: device (encoding kernel) + inode. Padding esplicito.
struct file_key {
    __u64 ino;
    __u32 dev;
    __u32 pad;
};

// Coppia (regola, binario autorizzato). Stesso layout di file_key.
struct allow_key {
    __u64 ino;
    __u32 dev;
    __u32 rule;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} settings SEC(".maps");

// Subnet da bloccare via XDP (Longest Prefix Match)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} infected_subnets SEC(".maps");

// File protetti -> id regola (>= 1)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct file_key);
    __type(value, __u32);
} protected_files SEC(".maps");

// Binari autorizzati, per regola (identità del file eseguibile)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct allow_key);
    __type(value, __u32);
} allowed_exes SEC(".maps");

struct audit_event {
    __u32 pid;
    char  comm[16];
    __u32 rule;
    __u64 ino;
    __u32 action; // 1 = bloccato, 0 = solo audit
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} audit_logs SEC(".maps");

static __always_inline __u32 setting(__u32 key, __u32 def) {
    __u32 *v = bpf_map_lookup_elem(&settings, &key);
    return v ? *v : def;
}

// --- 1. XDP: protocolli di poisoning + subnet ostili ---
SEC("xdp")
int xdp_shield(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // LLMNR (5355), mDNS (5353), NBT-NS (137/138): mai in ingresso
    if (ip->protocol == IPPROTO_UDP && setting(SETTING_POISON, 1)) {
        __u32 ihl = ip->ihl * 4;
        if (ihl >= sizeof(*ip)) {
            struct udphdr *udp = (void *)ip + ihl;
            if ((void *)(udp + 1) <= data_end) {
                __u16 dport = bpf_ntohs(udp->dest);
                if (dport == 5355 || dport == 5353 || dport == 137 || dport == 138)
                    return XDP_DROP;
            }
        }
    }

    struct lpm_key key = { .prefixlen = 32 };
    __builtin_memcpy(key.addr, &ip->saddr, 4);

    __u32 *blocked = bpf_map_lookup_elem(&infected_subnets, &key);
    if (blocked && *blocked == 1)
        return XDP_DROP;

    return XDP_PASS;
}

// --- 2. LSM: isolamento segreti ---
SEC("lsm/file_open")
int BPF_PROG(zt_file_open, struct file *file) {
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    struct file_key fk = {};
    fk.ino = BPF_CORE_READ(inode, i_ino);
    fk.dev = BPF_CORE_READ(inode, i_sb, s_dev);

    __u32 *rp = bpf_map_lookup_elem(&protected_files, &fk);
    if (!rp)
        return 0;
    __u32 rule = *rp;

    // Identità del binario che sta aprendo il file
    struct task_struct *task = bpf_get_current_task_btf();
    struct inode *exe = BPF_CORE_READ(task, mm, exe_file, f_inode);
    if (exe) {
        struct allow_key ak = {};
        ak.ino = BPF_CORE_READ(exe, i_ino);
        ak.dev = BPF_CORE_READ(exe, i_sb, s_dev);
        ak.rule = rule;
        if (bpf_map_lookup_elem(&allowed_exes, &ak))
            return 0;
    }

    __u32 enforce = setting(SETTING_ENFORCE, 1);

    struct audit_event *event = bpf_ringbuf_reserve(&audit_logs, sizeof(*event), 0);
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        event->rule = rule;
        event->ino = fk.ino;
        event->action = enforce ? 1 : 0;
        event->pad = 0;
        bpf_ringbuf_submit(event, 0);
    }

    return enforce ? -EACCES : 0;
}
