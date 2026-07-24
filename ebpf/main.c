// Developed by: Nishnat ndjangra1027@gmail.com -- nishujangra.dev

// Main entry point for XDP
SEC("xdp")
int xdp_cidr(struct xdp_md *ctx) { return XDP_PASS; }

char LICENSE[] SEC("license") = "GPL";
