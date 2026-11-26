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
    /// Private actual jailed boot/guest/collection gate; no profile publication.
    ProbeGuest {
        #[arg(long)]
        config: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Args::parse().command {
        Action::ProbeKvm => {
            let observation = goldenhoop_firecracker::kvm::probe_kvm();
            println!("{}", serde_json::to_string(&observation)?);
            if observation.state != goldenhoop_firecracker::kvm::KvmState::Ready {
                std::process::exit(2);
            }
        }
        Action::ProbeGuest { config } => {
            #[cfg(target_os = "linux")]
            {
                use std::io::Read;
                let file = std::fs::File::open(config)?;
                let mut bytes = Vec::new();
                file.take(65537).read_to_end(&mut bytes)?;
                if bytes.len() > 65536 {
                    return Err("boot configuration exceeds limit".into());
                }
                let input = serde_json::from_slice(&bytes)?;
                let report = goldenhoop_firecracker::machine::validate_guest(input).await;
                println!("{}", serde_json::to_string(&report)?);
                if !report.passed {
                    std::process::exit(2);
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = config;
                return Err("jailed guest validation requires Linux x86_64 KVM".into());
            }
        }
    }
    Ok(())
}
