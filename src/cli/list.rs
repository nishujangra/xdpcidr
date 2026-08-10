// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

use crate::ebpf::blocklist::{list_blocklist_v4, list_blocklist_v4_subnet};

pub fn run() {
    let addrs = list_blocklist_v4();
    let nets = list_blocklist_v4_subnet();

    if addrs.is_empty() && nets.is_empty() {
        println!("Blocklist is empty.");
        return;
    }

    for entry in addrs {
        println!("{}", entry.ip);
    }

    for entry in nets {
        println!("{}", entry.ip);
    }
}
