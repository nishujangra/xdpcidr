// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

use crate::cli::Target;
use crate::ebpf::blocklist::{remove_blocklist_v4, remove_blocklist_v4_subnet};

pub fn run(target: Target) {
    let result = match target {
        Target::Addr(ip) => remove_blocklist_v4(ip),
        Target::Net(net) => remove_blocklist_v4_subnet(net),
        Target::V6(s) => {
            eprintln!("IPv6 is not supported yet: {}", s);
            return;
        }
    };

    match result {
        Ok(()) => println!("Removed: {}", target),
        Err(e) => eprintln!("Error: {}", e),
    }
}
