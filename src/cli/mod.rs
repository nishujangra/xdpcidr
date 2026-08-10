use std::net::{IpAddr, Ipv4Addr};
use clap::Subcommand;
use ipnet::{IpNet, Ipv4Net};

#[derive(Debug, Subcommand)]
pub enum Command {
    // Attach the XDP program and pin its maps, then wait for Ctrl+C
    Run {
        #[arg(short, long, default_value = "eth0")]
        interface: String,

        #[arg(short, long, default_value = "ebpf/main.o")]
        ebpf_path: String,
    },

    // Block an IPv4 address or CIDR range
    Add {
        /// e.g. 1.2.3.4 or 10.0.0.0/24
        target: Target,
    },

    // Remove an IPv4 address or CIDR range from blocklist
    Remove {
        /// e.g. 1.2.3.4 or 10.0.0.0/24
        target: Target,
    },

    // List blocked addresses and CIDR ranges
    List,
}
