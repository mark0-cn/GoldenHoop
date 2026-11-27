use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "goldenhoop-images", version)]
struct Args {
    #[arg(long)]
    database: PathBuf,
    #[arg(long)]
    artifact_root: PathBuf,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Export a pinned source without executing it; does not prepare a VM disk.
    Export {
        #[arg(long)]
        id: uuid::Uuid,
        #[arg(long)]
        generation: uuid::Uuid,
        #[arg(long)]
        source_image: String,
    },
    /// Collect only a stable exported generation, after its consumers are fenced.
    CollectExport {
        #[arg(long)]
        id: uuid::Uuid,
    },
}
#[cfg(target_os = "linux")]
fn trusted_path(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute()
        || path.components().any(|v| {
            matches!(
                v,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("image state requires an absolute trusted host path".into());
    }
    let mut current = Some(path);
    while let Some(value) = current {
        match std::fs::symlink_metadata(value) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o022 != 0 =>
            {
                return Err("image state path ownership differs".into());
            }
            Ok(metadata) if value != path && !metadata.is_dir() => {
                return Err("image state ancestor is not a directory".into());
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        current = value.parent();
    }
    Ok(())
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    #[cfg(target_os = "linux")]
    {
        use goldenhoop_artifacts::BlobStore;
        use goldenhoop_images::{ExportRequest, export::SourceExporter};
        use goldenhoop_store::Store;
        if unsafe { libc::geteuid() } != 0 {
            return Err("source preparation requires a trusted Linux root host service".into());
        }
        trusted_path(&args.database)?;
        trusted_path(&args.artifact_root)?;
        let store = Store::open(&args.database).await?;
        let blobs = BlobStore::local(&args.artifact_root, store.installation_id())?;
        let service = SourceExporter::connect(store.clone(), blobs).await?;
        let require_archive = matches!(&args.command, Action::Export { .. });
        let result = match args.command {
            Action::Export {
                id,
                generation,
                source_image,
            } => {
                service
                    .export(ExportRequest {
                        id,
                        generation,
                        source_image,
                    })
                    .await
            }
            Action::CollectExport { id } => service.collect(id).await,
        };
        store.close().await;
        let result = result?;
        println!("{}", serde_json::to_string(&result)?);
        if result.error.is_some()
            || result.provider_cleanup != "complete"
            || require_archive && !result.archive_ready
        {
            std::process::exit(2);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        return Err("source preparation requires a trusted Linux host service".into());
    }
    #[allow(unreachable_code)]
    Ok(())
}
