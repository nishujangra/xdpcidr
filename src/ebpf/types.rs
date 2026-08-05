// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

use serde::Serialize;

use std::net::Ipv4Addr;

use aya::Pod;

/// Mirrors `struct ipv4_key` in ebpf/maps/struct.h (key of `blk_ip_v4`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IPv4Key {
    /// IP in network byte order (big-endian).
    pub ip: u32,
}

/// Mirrors `struct ipv4_lpm_key` in ebpf/maps/struct.h (key of `blk_cidr_v4`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IPv4LpmKey {
    /// Prefix length, 0-32 for IPv4.
    pub prefixlen: u32,
    /// IP Subnet in network byte order (big-endian).
    pub addr: u32,
}

/// Mirrors `struct ip_meta` in ebpf/maps/struct.h (value of both maps).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IPMeta {
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct RuleEntry {
    pub ip: String,
    pub created_at: u64,
}

unsafe impl Pod for IPv4Key {}

unsafe impl Pod for IPv4LpmKey {}

unsafe impl Pod for IPMeta {}

impl IPv4Key {
    pub fn from_ip(ip: Ipv4Addr) -> Self {
        Self {
            ip: u32::from(ip).to_be(),
        }
    }
}

impl IPv4LpmKey {
    pub fn new(addr: Ipv4Addr, prefixlen: u32) -> Self {
        Self {
            prefixlen,
            addr: u32::from(addr).to_be(),
        }
    }
}
