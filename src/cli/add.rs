// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

use crate::cli::Target;
use crate::ebpf::blocklist::{block_ipv4, block_ipv4_subnet};

pub fn run(target: Target) {
    let result = match target {
        Target::Addr(ip) => block_ipv4(ip),
        Target::Net(net) => block_ipv4_subnet(net),
        Target::V6(s) => {
            eprintln!("IPv6 is not supported yet: {}", s);
            return;
        }
    };

    match result {
        Ok(()) => println!("Blocked: {}", target),
        Err(e) => eprintln!("Error: {}", e),
    }
}
