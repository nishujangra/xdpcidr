// --- Developed By: Nishant ndjangra1027@gmail.com -- nishujangra.dev

use aya::programs::XdpFlags;
use aya::{Ebpf, programs::Xdp};
use clap::Parser;

pub mod cli;
pub mod ebpf;

use crate::cli::Command;

#[derive(Debug, Parser)]
#[command(name = "xdpcidr")]
#[command(about = "xdpcidr - eBPF based blocklist")]
struct CliArgs {
    #[command(subcommand)]
    command: Option<Command>,
}

fn main() -> Result<(), anyhow::Error> {
    let args = CliArgs::parse();

    match args.command {
        Some(Command::Run {
            interface,
            ebpf_path,
        }) => attach(&interface, &ebpf_path)?,

        Some(Command::Add { target }) => cli::add::run(target),

        Some(Command::Remove { target }) => cli::remove::run(target),

        Some(Command::List) => cli::list::run(),

        None => eprintln!("No subcommand given. Use --help."),
    }

    Ok(())
}

// Loads the XDP object, attaches it to the interface and pins its maps, then
// blocks until Ctrl+C. The pins are what let `add`/`remove`/`list` reach the
// maps from a separate invocation.
fn attach(interface: &str, ebpf_path: &str) -> Result<(), anyhow::Error> {
    let mut ebpf = Ebpf::load_file(ebpf_path)?;

    let program: &mut Xdp = ebpf
        .program_mut("xdp_cidr")
        .ok_or_else(|| anyhow::anyhow!("program xdpcidr not found in ELF"))?
        .try_into()?;

    program.load()?;
    program.attach(interface, XdpFlags::default())?;

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
