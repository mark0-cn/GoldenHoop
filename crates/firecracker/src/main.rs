use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "goldenhoop-firecracker", version)]
struct Args {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Observe actual KVM access; does not establish a usable runtime profile.
    ProbeKvm,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Args::parse().command {
        Action::ProbeKvm => {
            let observation = goldenhoop_firecracker::kvm::probe_kvm();
            println!("{}", serde_json::to_string(&observation)?);
            if observation.state != goldenhoop_firecracker::kvm::KvmState::Ready {
                std::process::exit(2);
            }
        }
    }
    Ok(())
}
