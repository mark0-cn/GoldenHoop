use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "goldenhoop-image-builder", version)]
struct Args {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Read baked guest/tool content hashes; establishes no runtime capability.
    Inventory,
    /// Read baked assets and the tools used by read-only rootfs inspection.
    RootfsInventory,
    /// Convert /input/source.tar using /input/prepare.json in an isolated builder.
    Prepare,
    /// Wait for a trusted host decision on private stdin before conversion.
    AwaitPrepare,
    /// Inspect /input/rootfs.ext4 using /input/inspect-rootfs.json.
    InspectRootfs,
    /// Wait for a trusted host decision before read-only rootfs inspection.
    AwaitInspectRootfs,
}

#[cfg(target_os = "linux")]
enum Request {
    Prepare(goldenhoop_image_builder::PrepareRequest),
    Rootfs(goldenhoop_image_builder::RootfsInspectionRequest),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    #[cfg(target_os = "linux")]
    match args.command {
        Action::Inventory => println!(
            "{}",
            serde_json::to_string(&goldenhoop_image_builder::linux::inventory()?)?
        ),
        Action::RootfsInventory => println!(
            "{}",
            serde_json::to_string(&goldenhoop_image_builder::linux::rootfs::inventory()?)?
        ),
        Action::Prepare
        | Action::AwaitPrepare
        | Action::InspectRootfs
        | Action::AwaitInspectRootfs => {
            use std::sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            };
            let authorized = matches!(
                args.command,
                Action::AwaitPrepare | Action::AwaitInspectRootfs
            );
            goldenhoop_image_builder::linux::verify_isolation()?;
            if !authorized {
                goldenhoop_image_builder::linux::verify_context()?;
            }
            let request = match args.command {
                Action::InspectRootfs | Action::AwaitInspectRootfs => {
                    Request::Rootfs(goldenhoop_image_builder::linux::rootfs::read_request()?)
                }
                _ => Request::Prepare(goldenhoop_image_builder::linux::read_request()?),
            };
            let flag = Arc::new(AtomicBool::new(false));
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
            let signalled = flag.clone();
            let interrupted = Arc::new(tokio::sync::Notify::new());
            let notified = interrupted.clone();
            let signals = tokio::spawn(async move {
                tokio::select! {_=term.recv()=>(),_=interrupt.recv()=>()};
                signalled.store(true, Ordering::Release);
                notified.notify_one();
            });
            let permit = if authorized {
                Some(tokio::select! {
                    _ = interrupted.notified() => return Err("image preparation interrupted before authorization".into()),
                    result = tokio::time::timeout(std::time::Duration::from_secs(30), goldenhoop_image_builder::linux::read_host_permit()) => result.map_err(|_| "host preparation decision timed out")??,
                })
            } else {
                None
            };
            let (passed, output) = match (request, permit) {
                (Request::Prepare(request), permit) => {
                    let report = if let Some(permit) = permit {
                        goldenhoop_image_builder::linux::prepare_authorized(request, permit, flag)
                            .await
                    } else {
                        goldenhoop_image_builder::linux::prepare(request, flag).await
                    };
                    (report.passed, serde_json::to_string(&report)?)
                }
                (Request::Rootfs(request), permit) => {
                    let report = if let Some(permit) = permit {
                        goldenhoop_image_builder::linux::rootfs::inspect_authorized(
                            request, permit, flag,
                        )
                        .await
                    } else {
                        goldenhoop_image_builder::linux::rootfs::inspect(request, flag).await
                    };
                    (report.passed, serde_json::to_string(&report)?)
                }
            };
            signals.abort();
            println!("{output}");
            if !passed {
                std::process::exit(2);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        return Err("image conversion requires an isolated Linux builder".into());
    }
    #[allow(unreachable_code)]
    Ok(())
}
