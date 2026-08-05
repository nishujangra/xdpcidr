// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

use std::net::Ipv4Addr;

use aya::maps::lpm_trie::Key;
use ipnet::Ipv4Net;

use rfw_core::types::RuleEntry;

use crate::ebpf::opnmap::{BLOCKLIST_IP_V4, BLOCKLIST_IP_V4_SUBNET, opn_xpdcidr_ebpf_map};

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

// add IPv4 subnet to CIDR blocklist map
pub fn block_ipv4_subnet(net: Ipv4Net) -> anyhow::Result<()> {
    let mut map = opn_xpdcidr_ebpf_map(BLOCKLIST_IP_V4_SUBNET)?;

    // network() masks off host bits, so 10.0.0.5/24 is stored as 10.0.0.0/24
    let key = Key::new(
        net.prefix_len() as u32,
        u32::from(net.network()).to_be(),
    );

    let value = IPMeta {
        created_at: 0,
        reason: reason::MANUAL_BLOCK,
    };

    map.insert(&key, value, 0)?;

    Ok(())
}

// List IPv4 entries
pub fn list_blocklist_v4() -> Vec<RuleEntry> {
    let Ok(map) = opn_xpdcidr_ebpf_map::<IPv4Key, IPMeta>(BLOCKLIST_IP_V4) else {
        return Vec::new();
    };

    map.iter()
        .filter_map(|r| r.ok())
        .map(|(k, v): (IPv4Key, IPMeta)| RuleEntry {
            ip: Ipv4Addr::from(u32::from_be(k.ip)).to_string(),
            reason: v.reason,
            created_at: v.created_at,
        })
        .collect()
}

// List IPv4 subnet entries
pub fn list_blocklist_v4_subnet() -> Vec<RuleEntry> {
    let Ok(map) = opn_xpdcidr_ebpf_map::<Key<u32>, IPMeta>(BLOCKLIST_IP_V4_SUBNET) else {
        return Vec::new();
    };

    map.iter()
        .filter_map(|r| r.ok())
        .map(|(k, v): (Key<u32>, IPMeta)| RuleEntry {
            ip: format!(
                "{}/{}",
                Ipv4Addr::from(u32::from_be(k.data())),
                k.prefix_len()
            ),
            reason: v.reason,
            created_at: v.created_at,
        })
        .collect()
}

// Delete from map
pub fn remove_blocklist_v4(ip: Ipv4Addr) -> anyhow::Result<()> {
    let mut map = opn_xpdcidr_ebpf_map::<IPv4Key, IPMeta>(BLOCKLIST_IP_V4)?;

    let key = IPv4Key::from_ip(ip);

    match map.remove(&key) {
        Ok(_) => {}
        Err(e) => {
            return Err(anyhow::anyhow!("failed to remove {}: {}", ip, e));
        }
    }

    Ok(())
}
