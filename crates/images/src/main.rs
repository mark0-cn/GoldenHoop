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
    /// Reconcile an interrupted source generation after its producer has exited.
    ReconcileExport {
        #[arg(long)]
        id: uuid::Uuid,
    },
    /// Prepare a private VM disk with a trusted pinned converter (default runsc).
    Prepare {
        #[arg(long)]
        id: uuid::Uuid,
        #[arg(long)]
        generation: uuid::Uuid,
        #[arg(long)]
        source_image: String,
        #[arg(long)]
        builder_image: String,
        #[arg(long, default_value_t = 1024 * 1024 * 1024)]
        disk_bytes: u64,
        #[arg(long, value_enum, default_value = "runsc")]
        runtime: goldenhoop_image_builder::BuilderRuntime,
        #[arg(long)]
        allow_runc_development: bool,
    },
    /// Collect a stable private disk after fencing all of its consumers.
    CollectImage {
        #[arg(long)]
        id: uuid::Uuid,
    },
    /// Reconcile acknowledged private converter output after producer exit.
    ReconcileImage {
        #[arg(long)]
        id: uuid::Uuid,
    },
    /// Abort an acknowledged failed pre-input job after fencing its producer.
    AbortBeforeInput {
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
        use goldenhoop_images::{
            ExportRequest, ImagePrepareRequest, export::SourceExporter, prepare::ImagePreparer,
        };
        use goldenhoop_store::Store;
        if unsafe { libc::geteuid() } != 0 {
            return Err("source preparation requires a trusted Linux root host service".into());
        }
        trusted_path(&args.database)?;
        trusted_path(&args.artifact_root)?;
        let store = Store::open(&args.database).await?;
        let blobs = BlobStore::local(&args.artifact_root, store.installation_id())?;
        let require_archive = matches!(&args.command, Action::Export { .. });
        let require_disk = matches!(&args.command, Action::Prepare { .. });
        let outcome = async {
            let (result, passed) = match args.command {
                Action::Export {
                    id,
                    generation,
                    source_image,
                } => {
                    let result = SourceExporter::connect(store.clone(), blobs.clone())
                        .await?
                        .export(ExportRequest {
                            id,
                            generation,
                            source_image,
                        })
                        .await?;
                    let passed = result.error.is_none()
                        && result.provider_cleanup == "complete"
                        && (!require_archive || result.archive_ready);
                    (serde_json::to_value(result)?, passed)
                }
                Action::CollectExport { id } => {
                    let result = SourceExporter::connect(store.clone(), blobs.clone())
                        .await?
                        .collect(id)
                        .await?;
                    let passed = result.error.is_none() && result.provider_cleanup == "complete";
                    (serde_json::to_value(result)?, passed)
                }
                Action::ReconcileExport { id } => {
                    let result = SourceExporter::connect(store.clone(), blobs.clone())
                        .await?
                        .reconcile(id)
                        .await?;
                    let passed = result.error.is_none() && result.provider_cleanup == "complete";
                    (serde_json::to_value(result)?, passed)
                }
                Action::Prepare {
                    id,
                    generation,
                    source_image,
                    builder_image,
                    disk_bytes,
                    runtime,
                    allow_runc_development,
                } => {
                    let result = ImagePreparer::connect(
                        store.clone(),
                        blobs.clone(),
                        allow_runc_development,
                    )
                    .await?
                    .prepare(ImagePrepareRequest {
                        id,
                        generation,
                        source_image,
                        builder_image,
                        disk_bytes,
                        runtime,
                    })
                    .await?;
                    let passed = result.error.is_none()
                        && result.provider_cleanup == "complete"
                        && (!require_disk || result.image_ready);
                    (serde_json::to_value(result)?, passed)
                }
                Action::CollectImage { id } => {
                    let result = ImagePreparer::connect(store.clone(), blobs.clone(), false)
                        .await?
                        .collect(id)
                        .await?;
                    let passed = result.error.is_none() && result.provider_cleanup == "complete";
                    (serde_json::to_value(result)?, passed)
                }
                Action::ReconcileImage { id } => {
                    let result = ImagePreparer::connect(store.clone(), blobs.clone(), false)
                        .await?
                        .reconcile(id)
                        .await?;
                    let passed = result.error.is_none() && result.provider_cleanup == "complete";
                    (serde_json::to_value(result)?, passed)
                }
                Action::AbortBeforeInput { id } => {
                    let result = ImagePreparer::connect(store.clone(), blobs.clone(), false)
                        .await?
                        .abort_before_input(id)
                        .await?;
                    let passed = result.provider_cleanup == "complete" && !result.image_ready;
                    (serde_json::to_value(result)?, passed)
                }
            };
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((result, passed))
        }
        .await;
        store.close().await;
        let (result, passed) = outcome?;
        println!("{}", serde_json::to_string(&result)?);
        if !passed {
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
