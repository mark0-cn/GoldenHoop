//! Private durable-policy contract producer. No public capability publication.
use clap::{Parser, Subcommand};
use goldenhoop_egress::{Config, ProtectedBindingReceipt};
use goldenhoop_protocol::{ApiError, CommandSpec, DesiredState};
use goldenhoop_store::{NetworkOperatorPolicy, Store};
use std::{net::SocketAddr, path::PathBuf};
use uuid::Uuid;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    database: PathBuf,
    #[arg(long)]
    sandbox: Uuid,
    #[command(subcommand)]
    action: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Trusted contract setup. Effective layers come only from stored intent.
    StagePublic {
        #[arg(long)]
        checkpoint_json: String,
        #[arg(long)]
        upstream: SocketAddr,
    },
    Stage {
        #[arg(long)]
        checkpoint_json: String,
        #[arg(long)]
        upstream: SocketAddr,
        #[arg(long)]
        config_json: String,
    },
    Update {
        #[arg(long)]
        desired_revision: u64,
        #[arg(long)]
        config_json: String,
    },
    Read,
    Command {
        #[arg(long)]
        command_json: String,
    },
    Desired {
        #[arg(long,value_parser=["running","paused","terminated"])]
        state: String,
    },
}
async fn run(args: &Args, store: &Store) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let id = args.sandbox;
    let network = store.network_allocation(id).await?;
    Ok(match &args.action {
        Action::StagePublic {
            checkpoint_json,
            upstream,
        } => {
            store
                .bind_network_operator(&NetworkOperatorPolicy::default())
                .await?;
            serde_json::to_value(
                store
                    .stage_public_network_policy(
                        id,
                        network.generation,
                        serde_json::from_str(checkpoint_json)?,
                        *upstream,
                    )
                    .await?,
            )?
        }
        Action::Stage {
            checkpoint_json,
            upstream,
            config_json,
        } => {
            let checkpoint: ProtectedBindingReceipt = serde_json::from_str(checkpoint_json)?;
            let config: Config = serde_json::from_str(config_json)?;
            serde_json::to_value(
                store
                    .stage_network_policy(id, network.generation, checkpoint, *upstream, config)
                    .await?,
            )?
        }
        Action::Update {
            desired_revision,
            config_json,
        } => serde_json::to_value(
            store
                .update_network_policy(
                    id,
                    network.generation,
                    *desired_revision,
                    serde_json::from_str(config_json)?,
                )
                .await?,
        )?,
        Action::Read => serde_json::to_value(store.network_policy(id).await?)?,
        Action::Command { command_json } => {
            let spec: CommandSpec = serde_json::from_str(command_json)?;
            serde_json::to_value(
                store
                    .create_execution(id, &spec, &Uuid::new_v4().to_string())
                    .await?,
            )?
        }
        Action::Desired { state } => serde_json::to_value(
            store
                .set_desired(
                    id,
                    serde_json::from_value::<DesiredState>(serde_json::json!(state))?,
                    &Uuid::new_v4().to_string(),
                )
                .await?,
        )?,
    })
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let store = Store::open(&args.database).await?;
    let result = run(&args, &store).await;
    store.close().await;
    match result {
        Ok(value) => println!("{}", serde_json::json!({"result":value})),
        Err(error) => {
            let value = error.downcast_ref::<ApiError>().map_or_else(
                || serde_json::json!({"message":error.to_string()}),
                |e| serde_json::to_value(e).expect("API error"),
            );
            println!("{}", serde_json::json!({"error":value}));
            std::process::exit(1);
        }
    }
    Ok(())
}
