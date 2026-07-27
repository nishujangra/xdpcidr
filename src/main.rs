// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

use clap::Parser;

#[derive(Debug, Parser)]
#[command(about = "xdpcidr - eBPF based blocklist")]
struct CliArgs {
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    #[arg(short, long, default_value = "/tmp/xdpcidr/xdpcidr.o")]
    ebpf_path: String,
}

fn main() {
    println!("Ohh yeah!!!!!!!!!!!!!");
}
