// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

use aya::maps::{Map, MapData};

pub const BLOCKLIST_IP_V4: &str = "/sys/fs/bpf/xdpcidr/blk_ip_v4";
pub const BLOCKLIST_IP_V4_SUBNET: &str = "/sys/fs/bpf/xdpcidr/blk_cidr_v4";

// Opens a pinned map, wrapping it in the aya type matching how it was declared
// in ebpf/maps/maps.c: blk_ip_v4 is a HASH, blk_cidr_v4 is an LPM_TRIE.
pub fn opn_xpdcidr_ebpf_map(path: &str) -> anyhow::Result<Map> {
    let map = MapData::from_pin(path)?;

    Ok(match path {
        BLOCKLIST_IP_V4_SUBNET => Map::LpmTrie(map),
        _ => Map::HashMap(map),
    })
}
