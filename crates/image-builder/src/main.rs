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
    /// Convert /input/source.tar using /input/prepare.json in an isolated builder.
    Prepare,
    /// Wait for a trusted host decision on private stdin before conversion.
    AwaitPrepare,
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
        Action::Prepare | Action::AwaitPrepare => {
            use std::sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            };
            let authorized = matches!(args.command, Action::AwaitPrepare);
            goldenhoop_image_builder::linux::verify_isolation()?;
            if !authorized {
                goldenhoop_image_builder::linux::verify_context()?;
            }
            let request = goldenhoop_image_builder::linux::read_request()?;
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
            let report = if authorized {
                let permit = tokio::select! {
                    _ = interrupted.notified() => return Err("image preparation interrupted before authorization".into()),
                    result = tokio::time::timeout(std::time::Duration::from_secs(30), goldenhoop_image_builder::linux::read_host_permit()) => result.map_err(|_| "host preparation decision timed out")??,
                };
                goldenhoop_image_builder::linux::prepare_authorized(request, permit, flag).await
            } else {
                goldenhoop_image_builder::linux::prepare(request, flag).await
            };
            signals.abort();
            println!("{}", serde_json::to_string(&report)?);
            if !report.passed {
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
