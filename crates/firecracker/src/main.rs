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
        #[arg(long)]
        checkpoint_config: Option<std::path::PathBuf>,
    },
    /// Verify a private retained capture; never grants restore authority.
    CheckpointInspect {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    /// Collect exact owned objects after the original writer and jail are gone.
    CheckpointCollect {
        #[arg(long)]
        config: std::path::PathBuf,
    },
    /// Private source-fenced single-use continuation and actual target gate.
    ProbeRestore {
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
        #[arg(long, hide = true)]
        image_fd: Option<u32>,
    },
    /// Exercise the native driver traits using private root-owned input files.
    DriverCall {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        request: std::path::PathBuf,
    },
}

fn checkpoint_store(
    config: std::path::PathBuf,
    collect: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(target_os = "linux")]
    {
        let config = goldenhoop_firecracker::checkpoint::CheckpointProbeConfig::read(&config)?;
        let value = if collect {
            goldenhoop_firecracker::checkpoint::collect_store(&config)?
        } else {
            goldenhoop_firecracker::checkpoint::inspect_store(&config)?
        };
        println!("{}", serde_json::to_string(&value)?);
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, collect);
        Err("native checkpoint store requires Linux root".into())
    }
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
            image_fd,
        } => {
            #[cfg(target_os = "linux")]
            {
                let input = image_fd
                    .map(goldenhoop_firecracker::lifecycle::inherited_input)
                    .transpose()?;
                goldenhoop_firecracker::lifecycle::run_supervisor_with_input(
                    config, sandbox, generation, input,
                )
                .await?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (config, sandbox, generation, image_fd);
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
        Action::CheckpointInspect { config } => checkpoint_store(config, false)?,
        Action::CheckpointCollect { config } => checkpoint_store(config, true)?,
        Action::ProbeRestore { config } => {
            #[cfg(target_os = "linux")]
            {
                let cfg = goldenhoop_firecracker::machine::RestoreProbeConfig::read(&config)?;
                let report = goldenhoop_firecracker::machine::validate_restore(cfg).await;
                println!("{}", serde_json::to_string(&report)?);
                if !matches!(report.result.as_str(), "passed" | "existing") {
                    std::process::exit(2);
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = config;
                return Err("native restore requires Linux x86_64 root/KVM".into());
            }
        }
        Action::ProbeGuest {
            config,
            checkpoint_config,
        } => {
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
                let checkpoint = checkpoint_config
                    .map(|path| {
                        goldenhoop_firecracker::checkpoint::CheckpointProbeConfig::read(&path)
                    })
                    .transpose()?;
                let report = goldenhoop_firecracker::machine::validate_guest_with_checkpoint(
                    input, checkpoint,
                )
                .await;
                println!("{}", serde_json::to_string(&report)?);
                if !report.passed {
                    std::process::exit(2);
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (config, checkpoint_config);
                return Err("jailed guest validation requires Linux x86_64 KVM".into());
            }
        }
    }
    Ok(())
}
