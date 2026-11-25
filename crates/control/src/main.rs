use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, Subcommand};
use goldenhoop_artifacts::{BlobStore, S3Config};
use goldenhoop_control::{api, http::BearerAuth, worker::Worker};
use goldenhoop_store::Store;

#[derive(Clone, clap::ValueEnum)]
enum ArtifactBackend {
    Local,
    S3,
}
#[derive(clap::Args)]
struct ArtifactOptions {
    #[arg(
        long,
        env = "GOLDENHOOP_ARTIFACT_BACKEND",
        value_enum,
        default_value = "local"
    )]
    artifact_backend: ArtifactBackend,
    #[arg(long, env = "GOLDENHOOP_ARTIFACT_ROOT")]
    artifact_root: Option<PathBuf>,
    #[arg(long, env = "GOLDENHOOP_ARTIFACT_ENDPOINT")]
    artifact_endpoint: Option<String>,
    #[arg(long, env = "GOLDENHOOP_ARTIFACT_BUCKET")]
    artifact_bucket: Option<String>,
    #[arg(long, env = "GOLDENHOOP_ARTIFACT_REGION", default_value = "us-east-1")]
    artifact_region: String,
}
impl ArtifactOptions {
    fn connect(
        self,
        database: &std::path::Path,
        installation: uuid::Uuid,
    ) -> Result<BlobStore, Box<dyn std::error::Error>> {
        Ok(match self.artifact_backend {
            ArtifactBackend::Local => {
                if self.artifact_endpoint.is_some() || self.artifact_bucket.is_some() {
                    return Err("S3 options require --artifact-backend s3".into());
                }
                let root = self.artifact_root.unwrap_or_else(|| {
                    database
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new("."))
                        .join("artifacts")
                });
                BlobStore::local(&root, installation)?
            }
            ArtifactBackend::S3 => {
                if self.artifact_root.is_some() {
                    return Err("--artifact-root cannot be used with S3".into());
                }
                BlobStore::s3(
                    S3Config {
                        endpoint: self
                            .artifact_endpoint
                            .ok_or("S3 artifact endpoint is required")?,
                        bucket: self
                            .artifact_bucket
                            .ok_or("S3 artifact bucket is required")?,
                        region: self.artifact_region,
                        access_key_id: std::env::var("GOLDENHOOP_ARTIFACT_ACCESS_KEY")
                            .map_err(|_| "GOLDENHOOP_ARTIFACT_ACCESS_KEY is required")?,
                        secret_access_key: std::env::var("GOLDENHOOP_ARTIFACT_SECRET_KEY")
                            .map_err(|_| "GOLDENHOOP_ARTIFACT_SECRET_KEY is required")?,
                        session_token: std::env::var("GOLDENHOOP_ARTIFACT_SESSION_TOKEN").ok(),
                    },
                    installation,
                )?
            }
        })
    }
}

#[derive(Parser)]
#[command(
    name = "goldenhoopd",
    version,
    about = "GoldenHoop control API and separately supervised worker"
)]
struct Args {
    #[arg(
        long,
        global = true,
        env = "GOLDENHOOP_DATABASE",
        default_value = "state/goldenhoop.db"
    )]
    database: PathBuf,
    #[command(subcommand)]
    command: Role,
}
#[derive(Subcommand)]
enum Role {
    Api {
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,
        #[arg(long, env = "GOLDENHOOP_API_TOKEN", hide_env_values = true)]
        token: String,
    },
    Worker {
        #[arg(
            long,
            env = "GOLDENHOOP_AGENT_IMAGE",
            default_value = "goldenhoop-agent:local"
        )]
        agent_image: String,
        #[arg(long, env = "GOLDENHOOP_KERNEL_PROBE_IMAGE")]
        kernel_probe_image: Option<String>,
        #[arg(long, env = "GOLDENHOOP_EGRESS_CONTROLLER_IMAGE")]
        egress_controller_image: Option<String>,
        #[arg(long)]
        allow_runc_development: bool,
        #[command(flatten)]
        artifacts: ArtifactOptions,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    match args.command {
        Role::Api { bind, token } => {
            BearerAuth::new(&token)?;
            if !bind.ip().is_loopback() {
                return Err(
                    "API must bind loopback; use a local TLS reverse proxy for remote clients"
                        .into(),
                );
            }
            let store = Store::open(&args.database).await?;
            let listener = tokio::net::TcpListener::bind(bind).await?;
            let router = api::router(store.clone(), &token)?;
            println!(
                "{}",
                serde_json::json!({"event":"api_started","address":listener.local_addr()?,"installation_id":store.installation_id()})
            );
            let result = axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await;
            store.close().await;
            result?;
        }
        Role::Worker {
            agent_image,
            kernel_probe_image,
            egress_controller_image,
            allow_runc_development,
            artifacts,
        } => {
            let store = Store::open(&args.database).await?;
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).create(true).truncate(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            // Keep the stable lock inode. Deleting it on exit would race a new worker.
            let lock = options.open(args.database.with_extension("worker.lock"))?;
            fs2::FileExt::try_lock_exclusive(&lock)
                .map_err(|_| "another worker already owns this local database")?;
            let artifacts = artifacts.connect(&args.database, store.installation_id())?;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let worker = Worker::new(
                store.clone(),
                agent_image,
                kernel_probe_image,
                allow_runc_development,
                format!("http://{}", listener.local_addr()?),
                artifacts,
                egress_controller_image,
            )
            .await?;
            let router = worker.router()?;
            let (shutdown, receive) = tokio::sync::watch::channel(false);
            let reconcile = tokio::spawn(worker.clone().run(receive.clone()));
            let heartbeat = tokio::spawn(worker.clone().heartbeat(receive.clone()));
            let sweep = tokio::spawn(worker.clone().sweep_artifacts(receive.clone()));
            let expire = tokio::spawn(worker.expire(receive));
            println!(
                "{}",
                serde_json::json!({"event":"worker_started","installation_id":store.installation_id()})
            );
            let signal = shutdown.clone();
            let result = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = signal.send(true);
                })
                .await;
            let _ = shutdown.send(true);
            let _ = tokio::join!(reconcile, heartbeat, expire, sweep);
            store.close().await;
            result?;
            drop(lock);
        }
    }
    Ok(())
}
