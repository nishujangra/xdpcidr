use std::net::Ipv4Addr;
use clap::Subcommand;
use ipnet::Ipv4Net;

#[derive(Debug, Subcommand)]
pub enum Command {    
    // Block an IPv4 address or CIDR range
    Add { target: Target },
    
    // Remove an IPv4 address or CIDR range from blocklist
    Remove { target: Target },
    
    // List blocked addresses and CIDR ranges
    List,
}

// Target is either IPv4 or IPv4 subnet
#[derive(Debug, Clone)]
pub enum Target {
    Addr(Ipv4Addr),
    Net(Ipv4Net),
}

impl std::str::FromStr for Target {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('/') {
            Ok(Self::Net(s.parse::<Ipv4Net>()?))
        } else {
            Ok(Self::Addr(s.parse::<Ipv4Addr>()?))
        }
    }
}
