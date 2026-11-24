//! Run independently of the API so paused/abandoned workloads retain host-side TTLs.
use std::time::Duration;

use clap::Parser;
use goldenhoop_docker::{DockerConfig, DockerDriver, DockerProfile};
use uuid::Uuid;

#[derive(Parser)]
#[command(version, about = "Host-side GoldenHoop expiration worker")]
struct Args {
    #[arg(long, env = "GOLDENHOOP_INSTALLATION_ID")]
    installation_id: Uuid,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=300))]
    interval_seconds: u64,
    #[arg(long)]
    once: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut drivers = Vec::new();
    for profile in [DockerProfile::Gvisor, DockerProfile::RuncDevelopment] {
        drivers.push(
            DockerDriver::connect(DockerConfig {
                installation_id: args.installation_id,
                agent_image: String::new(), // Expiration never provisions or enters a workload.
                profile,
                allow_runc_development: false,
            })
            .await?,
        );
    }
    loop {
        let mut failed = false;
        for driver in &drivers {
            match driver.reap_expired().await {
                Ok(ids) => {
                    for id in ids {
                        println!(
                            "{}",
                            serde_json::json!({"event":"expired_sandbox_removed","sandbox_id":id})
                        );
                    }
                }
                Err(error) => {
                    failed = true;
                    eprintln!(
                        "{}",
                        serde_json::json!({"event":"expiry_scan_failed","error":error})
                    );
                }
            }
        }
        if args.once {
            return if failed {
                Err("expiration scan failed; cleanup is not confirmed".into())
            } else {
                Ok(())
            };
        }
        tokio::select! {
            result = tokio::signal::ctrl_c() => { result?; return Ok(()); },
            _ = tokio::time::sleep(Duration::from_secs(args.interval_seconds)) => {},
        }
    }
}
