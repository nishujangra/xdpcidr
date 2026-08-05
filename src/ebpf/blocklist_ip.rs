// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

use std::net::Ipv4Addr;

use rfw_core::types::RuleEntry;

use crate::ebpf::opnmap::{BLOCKLIST_IP_V4, opn_xpdcidr_ebpf_map};

// add IPv4 to blocklist map
pub fn block_ipv4(ip: Ipv4Addr) -> anyhow::Result<()> {
    let mut map = opn_xpdcidr_ebpf_map(BLOCKLIST_IP_V4)?;

    let key = IPv4Key::from_ip(ip);

    let value = IPMeta {
        created_at: 0,
        reason: reason::MANUAL_BLOCK,
    };

    map.insert(key, value, 0)?;

    Ok(())
}