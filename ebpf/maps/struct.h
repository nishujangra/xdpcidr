// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

#ifndef STRUCT_H
#define STRUCT_H

// IPv4 Key
struct ipv4_key {
    __be32
        ip; // __be32 tells you the value is in network byte order (big-endian)
};

struct ipv4_lpm_key {
    __u32 prefixlen; // Prefix length (0-32 for IPv4)
    __u32 data;      // IP address in network byte order (big-endian)
};

// metadata
struct ip_meta {
    __u64 created_at;
};

#endif
