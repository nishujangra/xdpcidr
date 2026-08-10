# xdpcidr

An XDP program that drops packets from blocked IPv4 addresses and CIDR ranges at
the earliest point in the network stack.

## How it works

The XDP program (`ebpf/main.c`) checks each packet's IPv4 source address against
two maps: a hash map (`blk_ip_v4`) for exact matches and an LPM trie
(`blk_cidr_v4`) for CIDR ranges. A hit returns `XDP_DROP`. IPv6 is dropped
wholesale; everything else passes.

The maps are pinned under `/sys/fs/bpf/xdpcidr/`, which is how `add`, `remove`
and `list` reach them from a separate invocation.

## Build

```sh
make build-ebpf     # ebpf/main.c -> ebpf/main.o
make build-dev      # cargo build (debug)
make build          # cargo build --release
```

## Usage

Everything needs root (`CAP_BPF` and `CAP_NET_ADMIN`).

Attach the program — this stays in the foreground until Ctrl+C:

```sh
sudo mkdir -p /sys/fs/bpf/xdpcidr
sudo ./target/debug/xdpcidr run -i wlp0s20f3
```

Then manage rules from another shell:

```sh
sudo ./target/debug/xdpcidr add 1.2.3.4
sudo ./target/debug/xdpcidr add 10.0.0.0/24
sudo ./target/debug/xdpcidr list
sudo ./target/debug/xdpcidr remove 10.0.0.0/24
```

### Commands

| Command | Description |
| --- | --- |
| `run` | Attach the program and pin its maps; `-i` interface (default `eth0`), `-e` object path (default `ebpf/main.o`) |
| `add <target>` | Block an address (`1.2.3.4`) or range (`10.0.0.0/24`) |
| `remove <target>` | Remove an address or range |
| `list` | Print blocked addresses and ranges |

`-i` usually needs overriding — `eth0` won't exist on most modern systems. List
yours with `ip -brief link show`.

Rules live in the pinned maps only while `run` is active; the pins are recreated
on each `run`.

## Notes

Attaching to your main interface drops all IPv6 traffic. Use `-i lo` to try it
out safely.

Avoid `sudo cargo run` — it builds as root and leaves root-owned files in
`target/`, breaking later unprivileged builds. Recover with:

```sh
sudo chown -R "$USER:$USER" target/
```

Verify it loaded:

```sh
sudo bpftool prog show          # an xdp-type prog named xdp_cidr
sudo bpftool map show           # blk_ip_v4 and blk_cidr_v4
ip link show dev <interface>    # shows an xdp/prog id when attached
```

## License

GPL. See LICENSE.md.
