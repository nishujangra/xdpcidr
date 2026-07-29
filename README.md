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

Build the XDP object and the userspace loader:

```sh
make build-ebpf     # compiles ebpf/main.c -> ebpf/main.o
make build-dev      # cargo build (debug)
```

Or for a release build:

```sh
make build          # cargo build --release
```

## Usage

Loading and attaching an XDP program requires `CAP_BPF` and `CAP_NET_ADMIN`, so run
it as root:

```sh
sudo ./target/debug/xdpcidr --interface wlp0s20f3 --ebpf-path ebpf/main.o
```

The program stays attached until you press Ctrl+C, which detaches it.

### Flags

| Flag | Short | Default | Description |
| --- | --- | --- | --- |
| `--interface` | `-i` | `eth0` | Network interface to attach the XDP program to |
| `--ebpf-path` | `-e` | `/tmp/xdpcidr/xdpcidr.o` | Path to the compiled XDP object file |
| `--help` | `-h` | | Print help |

Both defaults usually need overriding:

- `--interface`: `eth0` won't exist on most modern systems, which use predictable
  names. List yours with `ip -brief link show` and pass the one you want (e.g.
  `wlp0s20f3`, `enp3s0`).
- `--ebpf-path`: the build writes `ebpf/main.o`, not `/tmp/xdpcidr/xdpcidr.o`.
  Nothing copies it there, so pass `--ebpf-path ebpf/main.o`.

### A note on `sudo cargo run`

`sudo cargo run` works, but builds as root and leaves root-owned files in `target/`,
after which unprivileged `cargo build` fails with `Permission denied`. Prefer
building unprivileged and running the binary under `sudo`, as above. If you've
already hit this:

```sh
sudo chown -R "$USER:$USER" target/
```

### Verifying it loaded

```sh
sudo bpftool prog show          # look for an xdp-type prog named xdp_cidr
sudo bpftool map show           # blk_ip_v4 and blk_cidr_v4
sudo bpftool net
ip link show dev <interface>    # shows an xdp/prog id when attached
```

## License

GPL. See LICENSE.md.
