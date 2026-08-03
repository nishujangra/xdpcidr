// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

#include "struct.h"
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

#define MAX_BLOCKLIST 1000

// Blacklist IPv4
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv4_key);
    __type(value, struct ip_meta);
    __uint(max_entries, MAX_BLOCKLIST);
} blk_ip_v4 SEC(".maps");

// Blacklist IPv4 CIDR
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct ip_meta);
    __uint(max_entries, MAX_BLOCKLIST);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blk_cidr_v4 SEC(".maps");
