// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

use aya::programs::XdpFlags;
use aya::{Ebpf, programs::Xdp};
use clap::Parser;

pub mod ebpf;

#[derive(Debug, Parser)]
#[command(about = "xdpcidr - eBPF based blocklist")]
struct CliArgs {
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    #[arg(short, long, default_value = "ebpf/main.o")]
    ebpf_path: String,
}

//#[tokio::main]
fn main() -> Result<(), anyhow::Error> {
    println!("Ohh yeah!!!!!!!!!!!!!");

    let args = CliArgs::parse();

    let mut ebpf = Ebpf::load_file(&args.ebpf_path)?;

    let program: &mut Xdp = ebpf
        .program_mut("xdp_cidr")
        .ok_or_else(|| anyhow::anyhow!("program xdpcidr not found in ELF"))?
        .try_into()?;

    program.load()?;
    program.attach(&args.interface, XdpFlags::default())?;

    //pin maps
    for (name, map) in ebpf.maps_mut() {
        let path = format!("/sys/fs/bpf/xdpcidr/{name}");

        // remove old pin if exist
        let _ = std::fs::remove_file(&path);

        map.pin(&path)?;

        println!("Pinned Map {} -> {}", name, path);
    }

    println!("xdpcidr-ebpf program attached. Press Ctrl+C to stop.");

    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })?;
    rx.recv()?;

    println!("\n\nDetaching...");

    Ok(())
}
