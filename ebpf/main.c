// Developed by: Nishant ndjangra1027@gmail.com -- nishujangra.dev

#include "maps/maps.c"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// Main entry point for XDP
SEC("xdp")
int xdp_cidr(struct xdp_md *ctx) {
    void *data = (void *)(long)(ctx->data);
    void *data_end = (void *)(long)(ctx->data_end);

    // sanity check eth header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_ABORTED;
    }

    // Check for IPv4
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);

        // bound check
        if ((void *)(iph + 1) > data_end) {
            return XDP_ABORTED;
        }

        // ihl is in 32-bit words, 5 is the minimum (no options)
        if (iph->ihl < 5) {
            return XDP_ABORTED;
        }

        if ((void *)iph + iph->ihl * 4 > data_end) {
            return XDP_ABORTED;
        }

        // check for IP blocklist map
        struct ipv4_key key = {
            .ip = iph->saddr,
        };

        struct ip_meta *meta = bpf_map_lookup_elem(&blk_ip_v4, &key);
        if (meta) {
            return XDP_DROP;
        }

        // check for CIDR blocklist map
        struct ipv4_lpm_key lpm_key = {
            .prefixlen = 32,
            .addr = iph->saddr,
        };

        struct ip_meta *meta_cidr = bpf_map_lookup_elem(&blk_cidr_v4, &lpm_key);
        if (meta_cidr) {
            return XDP_DROP;
        }
    }

    // Drop IPv6
    else if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
