// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

use std::net::{IpAddr, Ipv4Addr};
use clap::Subcommand;
use ipnet::{IpNet, Ipv4Net};

pub mod add;
pub mod list;
pub mod remove;

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

// Target is either IPv4 or IPv4 subnet. V6 parses but will get error
#[derive(Debug, Clone)]
pub enum Target {
    Addr(Ipv4Addr),
    Net(Ipv4Net),
    V6(String),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Addr(ip) => write!(f, "{}", ip),
            Self::Net(net) => write!(f, "{}", net),
            Self::V6(s) => write!(f, "{}", s),
        }
    }
}

impl std::str::FromStr for Target {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Prefix = range, so parse the two forms with matching type; both for v4
        if s.contains('/') {
            match s.parse::<IpNet>()? {
                IpNet::V4(net) => Ok(Self::Net(net)),
                IpNet::V6(_) => Ok(Self::V6(s.to_string())),
            }
        } else {
            match s.parse::<IpAddr>()? {
                IpAddr::V4(ip) => Ok(Self::Addr(ip)),
                IpAddr::V6(_) => Ok(Self::V6(s.to_string())),
            }
        }
    }
}
