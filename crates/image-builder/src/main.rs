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
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    #[cfg(target_os = "linux")]
    match args.command {
        Action::Inventory => println!("{}", goldenhoop_image_builder::linux::inventory()?),
        Action::Prepare => {
            use std::{
                io::Read,
                sync::{
                    Arc,
                    atomic::{AtomicBool, Ordering},
                },
            };
            goldenhoop_image_builder::linux::verify_context()?;
            let mut bytes = Vec::new();
            std::fs::File::open("/input/prepare.json")?
                .take(65537)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 65536 {
                return Err("image preparation request exceeds limit".into());
            }
            let request = serde_json::from_slice(&bytes)?;
            let flag = Arc::new(AtomicBool::new(false));
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
            let signalled = flag.clone();
            let signals = tokio::spawn(async move {
                tokio::select! {_=term.recv()=>(),_=interrupt.recv()=>()};
                signalled.store(true, Ordering::Release);
            });
            let report = goldenhoop_image_builder::linux::prepare(request, flag).await;
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
