use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "goldenhoop-firecracker", version)]
struct Args {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Foreground native installation service, independent of the API worker.
    Manage {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    /// Request draining; the service's parent still confirms final collection.
    ManagerStop {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    /// Observe actual KVM access; does not establish a usable runtime profile.
    ProbeKvm,
    /// Private actual jailed boot/guest/collection gate; no profile publication.
    ProbeGuest {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    /// Private root lifecycle service, launched only from a durable driver intent.
    Supervise {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        sandbox: uuid::Uuid,
        #[arg(long)]
        generation: uuid::Uuid,
    },
    /// Exercise the native driver traits using private root-owned input files.
    DriverCall {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        request: std::path::PathBuf,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match Args::parse().command {
        Action::Manage { config } => {
            #[cfg(target_os = "linux")]
            goldenhoop_firecracker::lifecycle::run_manager(config).await?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = config;
                return Err("native manager requires Linux root/KVM".into());
            }
        }
        Action::ManagerStop { config } => {
            #[cfg(target_os = "linux")]
            {
                use goldenhoop_firecracker::lifecycle::{DriverConfig, FirecrackerDriver};
                FirecrackerDriver::connect(DriverConfig::read(&config)?)?
                    .request_manager_shutdown()
                    .await?;
                println!(
                    "{}",
                    serde_json::json!({"stop_requested":true,"cleanup":"pending"})
                );
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = config;
                return Err("native manager requires Linux root/KVM".into());
            }
        }
        Action::Supervise {
            config,
            sandbox,
            generation,
        } => {
            #[cfg(target_os = "linux")]
            goldenhoop_firecracker::lifecycle::run_supervisor(config, sandbox, generation).await?;
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (config, sandbox, generation);
                return Err("native supervisor requires Linux root/KVM".into());
            }
        }
        Action::DriverCall { config, request } => {
            #[cfg(target_os = "linux")]
            {
                let value =
                    goldenhoop_firecracker::lifecycle::run_driver_call(config, request).await?;
                println!("{}", serde_json::to_string(&value)?);
                if value["ok"] != true {
                    std::process::exit(2);
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (config, request);
                return Err("native driver requires Linux root/KVM".into());
            }
        }
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
