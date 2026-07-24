// Developed by: Nishnat ndjangra1027@gmail.com -- nishujangra.dev

#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

// Main entry point for XDP
SEC("xdp")
int xdp_cidr(struct xdp_md *ctx) {
    void *data = (void *)(long)(ctx->data);
    void *data_end = (void *)(long)(ctx->data_end);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
