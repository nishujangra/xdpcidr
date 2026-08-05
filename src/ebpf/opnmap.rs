// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

use aya::Pod;
use aya::maps::Map;
use aya::maps::{HashMap, MapData};

pub const BLOCKLIST_IP_V4: &str = "/sys/fs/bpf/rfw/blk_ip_v4";
pub const BLOCKLIST_IP_V4_SUBNET: &str = "/sys/fs/bpf/rfw/blk_cidr_v4";

pub fn opn_rfw_ebpf_map<K, V>(path: &str) -> anyhow::Result<HashMap<MapData, K, V>>
where
    K: Pod,
    V: Pod,
{
    let map = MapData::from_pin(path)?;
    Ok(HashMap::try_from(Map::HashMap(map))?)
}
