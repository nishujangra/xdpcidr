 # xdpcidr

An XDP program that drops packets from blocked IPv4 addresses and CIDR ranges at the earliest point in the network stack.

## How it works

The XDP program (`ebpf/main.c`) inspects each incoming packet:

- IPv4 source addresses are checked against a per-CPU hash map (`blk_ip_v4`) for exact-match blocks.
- IPv4 source addresses are checked against an LPM trie (`blk_cidr_v4`) for CIDR-range blocks.
- Matching packets return `XDP_DROP`.
- IPv6 packets are dropped.
- All other packets return `XDP_PASS`.

Both maps hold up to 1000 entries and store an `ip_meta` value (creation timestamp).

## Layout

```
ebpf/
  main.c          XDP program
  maps/
    maps.c        map definitions
    struct.h      key and value structs
src/
  main.rs         userspace loader
```

## Build

```
clang -O2 -g -target bpf -c ebpf/main.c -o main.o -Iebpf
```

## License

GPL. See LICENSE.md.
