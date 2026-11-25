//! Allocation-only real-backend contract. No workload is attached or published.
use chrono::{Duration, Utc};
use clap::{Parser, ValueEnum};
use goldenhoop_docker::{
    DockerConfig, DockerDriver, DockerNetworkProvider, DockerProfile, NetworkPlan,
};
use goldenhoop_egress::{Allocation, NetworkIdentity};
use goldenhoop_protocol::*;
use goldenhoop_runtime::RuntimeDriver;
use goldenhoop_store::{
    NetworkAbsence, NetworkAllocation, NetworkNativeBinding, NetworkPhase, Store,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::Write, path::PathBuf};
use uuid::Uuid;

#[derive(Clone, Copy, ValueEnum)]
enum Action {
    Init,
    Recover,
    Native,
    Negative,
    RejectNonempty,
    Collect,
    Confirm,
}
#[derive(Parser)]
struct Args {
    #[arg(long)]
    database: PathBuf,
    #[arg(long, value_enum)]
    action: Action,
    #[arg(long)]
    sandbox: Option<Uuid>,
    #[arg(long, default_value = "goldenhoop-agent:test")]
    agent_image: String,
    #[arg(long)]
    fault_after_create: bool,
    #[arg(long)]
    native_ifindex: Option<u32>,
    #[arg(long, conflicts_with = "fault_after_create")]
    fault_after_native: bool,
    #[arg(long)]
    leading_zero_subnet: bool,
    #[arg(long)]
    absence_json: Option<String>,
}
fn invalid() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidRequest,
        "invalid allocation contract request",
    )
}
fn require(value: bool) -> Result<(), ApiError> {
    if value {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::Conflict,
            "allocation contract observation differs",
        ))
    }
}
fn frame(value: &Value) {
    println!("{value}");
    std::io::stdout().flush().expect("contract stdout");
}

async fn plan(store: &Store, record: &NetworkAllocation) -> Result<NetworkPlan, ApiError> {
    let history = store
        .network_allocation_history(record.sandbox_id, None, 128)
        .await?;
    let dispatch = history
        .iter()
        .find(|r| r.phase == NetworkPhase::Provisioning)
        .ok_or_else(invalid)?;
    require(dispatch.generation == record.generation)?;
    Ok(NetworkPlan {
        identity: record.identity(),
        provisioning_token: dispatch.token.ok_or_else(invalid)?,
        expires_at: store.sandbox(record.sandbox_id).await?.sandbox.expires_at,
    })
}
async fn exercise(args: &Args, store: &Store) -> Result<Value, ApiError> {
    require(!args.leading_zero_subnet || matches!(args.action, Action::Init))?;
    require(
        matches!(args.action, Action::Native)
            || (args.native_ifindex.is_none() && !args.fault_after_native),
    )?;
    let provider = DockerNetworkProvider::connect().await?;
    if matches!(args.action, Action::Init) {
        require(args.sandbox.is_none() && store.work().await?.is_empty())?;
        // Probe the existing default-deny runc development driver rather than
        // inventing an available profile. Its own probe sandbox is collected.
        let driver = DockerDriver::connect(DockerConfig {
            installation_id: store.installation_id(),
            agent_image: args.agent_image.clone(),
            profile: DockerProfile::RuncDevelopment,
            allow_runc_development: true,
        })
        .await?;
        let profile = driver.probe().await;
        require(
            profile.availability == Availability::Available
                && profile.capabilities.contains(&Capability::NetworkIsolation)
                && !profile.capabilities.contains(&Capability::NetworkPolicy),
        )?;
        let request: CreateSandbox = serde_json::from_value(
            json!({"profile":profile.id,"image":args.agent_image,"ttl_seconds":600}),
        )
        .map_err(|_| invalid())?;
        let created = store
            .create_sandbox(&profile, &request, "allocation-contract")
            .await?;
        let mut identity = NetworkIdentity {
            installation_id: store.installation_id(),
            sandbox_id: created.sandbox.id,
            generation: Uuid::new_v4(),
            profile: profile.id.clone(),
        };
        if args.leading_zero_subnet {
            // Select a test vector before any network reservation or provider
            // write. This never retries an attempted external creation.
            let selected = (0..1024)
                .find_map(|_| {
                    identity.generation = Uuid::new_v4();
                    let hash = identity.digest();
                    (hash.as_bytes()[2] == b'0' || hash.as_bytes()[6] == b'0')
                        .then_some(identity.generation)
                })
                .ok_or_else(invalid)?;
            identity.generation = selected;
        }
        let reserved = store
            .reserve_network(created.sandbox.id, identity.generation)
            .await?;
        let dispatch = store
            .begin_network_provisioning(reserved.sandbox_id, reserved.generation, reserved.revision)
            .await?;
        let plan = plan(store, &dispatch).await?;
        frame(&json!({"intent":dispatch,"plan":plan,"probe_capabilities":profile.capabilities}));
        let observed = provider.create_fresh(&plan).await?;
        if args.fault_after_create {
            // The provider call has returned; only the journal consumer loses
            // the result. This is an actual process exit, not a TCP-loss claim.
            eprintln!("controlled exit after provider creation before journal binding");
            std::process::exit(75);
        }
        return Ok(
            json!({"scope":"owned empty network only; no workload or enforcement claim","provider":observed,"journal":store.network_allocation(dispatch.sandbox_id).await?}),
        );
    }
    require(!args.fault_after_create)?;
    let id = args.sandbox.ok_or_else(invalid)?;
    let record = store.network_allocation(id).await?;
    let plan = plan(store, &record).await?;
    match args.action {
        Action::Init => unreachable!(),
        Action::Recover => {
            let observed = provider.lookup(&plan).await?.ok_or_else(invalid)?;
            Ok(json!({"provider":observed,"journal":record,"creation_replayed":false}))
        }
        Action::Native => {
            // The trusted outer contract independently observes the actual host
            // bridge index. This input/record alone does not attest a lookup.
            let observed = provider.lookup(&plan).await?.ok_or_else(invalid)?;
            require(observed.attached_endpoints == 0)?;
            let native = NetworkNativeBinding {
                network_id: observed.network_id.clone(),
                allocation: Allocation {
                    installation_id: record.installation_id,
                    sandbox_id: record.sandbox_id,
                    generation: record.generation,
                    bridge: record.bridge.clone(),
                    ifindex: args.native_ifindex.ok_or_else(invalid)?,
                },
            };
            let checkpoint = store
                .bind_native_network(
                    id,
                    record.generation,
                    record.token.ok_or_else(invalid)?,
                    native,
                )
                .await?;
            require(
                checkpoint.phase == NetworkPhase::Provisioning && checkpoint.binding.is_none(),
            )?;
            if args.fault_after_native {
                eprintln!(
                    "controlled exit after native journal checkpoint before consumer acknowledgement"
                );
                std::process::exit(76);
            }
            Ok(
                json!({"provider":observed,"journal":checkpoint,"packet_installation_performed":false}),
            )
        }
        Action::Negative => {
            let original = provider.lookup(&plan).await?.ok_or_else(invalid)?;
            require(original.attached_endpoints == 0 && original.network_id != "0".repeat(64))?;
            let mut checks = BTreeSet::new();
            for field in 0..4 {
                let mut wrong = plan.clone();
                match field {
                    0 => wrong.identity.installation_id = Uuid::new_v4(),
                    1 => wrong.provisioning_token = Uuid::new_v4(),
                    2 => wrong.identity.profile = "foreign-profile".into(),
                    _ => wrong.expires_at += Duration::seconds(1),
                };
                let error = provider
                    .lookup(&wrong)
                    .await
                    .expect_err("foreign resource must refuse");
                require(error.code == ErrorCode::Conflict)?;
                checks.insert(format!("foreign_plan_field_{field}"));
            }
            require(
                provider
                    .create_fresh(&plan)
                    .await
                    .expect_err("duplicate creation must refuse")
                    .code
                    == ErrorCode::Conflict,
            )?;
            checks.insert("existing_creation_refused".into());
            require(
                provider
                    .remove_empty(&plan, Some(&"0".repeat(64)))
                    .await
                    .expect_err("wrong ID must refuse")
                    .code
                    == ErrorCode::Conflict,
            )?;
            checks.insert("foreign_collection_id_refused".into());
            let mut expired = plan.clone();
            expired.identity.generation = Uuid::new_v4();
            expired.expires_at = Utc::now() - Duration::seconds(1);
            require(
                provider
                    .create_fresh(&expired)
                    .await
                    .expect_err("expired allocation must refuse")
                    .code
                    == ErrorCode::InvalidRequest,
            )?;
            checks.insert("expired_creation_refused".into());
            let final_observed = provider.lookup(&plan).await?.ok_or_else(invalid)?;
            require(final_observed.network_id == original.network_id)?;
            Ok(json!({"checks":checks,"provider":final_observed,"journal":record}))
        }
        Action::RejectNonempty => {
            let original = provider.lookup(&plan).await?.ok_or_else(invalid)?;
            require(original.attached_endpoints > 0)?;
            require(
                provider
                    .remove_empty(&plan, Some(&original.network_id))
                    .await
                    .expect_err("live endpoints must refuse")
                    .code
                    == ErrorCode::Conflict,
            )?;
            let observed = provider.lookup(&plan).await?.ok_or_else(invalid)?;
            require(observed.network_id == original.network_id && observed.attached_endpoints > 0)?;
            Ok(json!({"live_collection_refused":true,"provider":observed}))
        }
        Action::Collect => {
            let observed = provider.lookup(&plan).await?.ok_or_else(invalid)?;
            let collecting = store
                .begin_network_collection(id, record.generation, record.revision)
                .await?;
            let removal = provider
                .remove_empty(&plan, Some(&observed.network_id))
                .await?;
            let repeated = provider
                .remove_empty(&plan, Some(&observed.network_id))
                .await?;
            require(removal.provider_absent && repeated.provider_absent)?;
            Ok(
                json!({"provider":removal,"repeated_provider_absence":repeated,"journal":collecting,"kernel_confirmation_pending":true}),
            )
        }
        Action::Confirm => {
            let raw = args
                .absence_json
                .as_deref()
                .filter(|s| s.len() <= 4096)
                .ok_or_else(invalid)?;
            let absence: NetworkAbsence = serde_json::from_str(raw).map_err(|_| invalid())?;
            // The outer contract must supply actual fresh provider/kernel
            // observations. This example never converts EOF into absence.
            let collected = store
                .confirm_network_absence(
                    id,
                    record.generation,
                    record.token.ok_or_else(invalid)?,
                    absence,
                )
                .await?;
            let mut terminal = store.sandbox(id).await?;
            terminal.sandbox.state = SandboxState::Failed;
            terminal.sandbox.cleanup = CleanupState::Complete;
            terminal.sandbox.reason =
                Some("allocation-only contract; no workload was published".into());
            store.observe(terminal).await?;
            store
                .finish_operations(
                    id,
                    "create",
                    OperationState::Failed,
                    Some(ApiError::new(
                        ErrorCode::BackendUnavailable,
                        "allocation-only contract; no workload was published",
                    )),
                )
                .await?;
            Ok(
                json!({"journal":collected,"sandbox":store.sandbox(id).await?.sandbox,"history":store.network_allocation_history(id,None,128).await?}),
            )
        }
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let store = Store::open(&args.database).await?;
    frame(&json!({"installation_id":store.installation_id()}));
    let result = exercise(&args, &store).await;
    store.close().await;
    match result {
        Ok(value) => {
            frame(&json!({"result":value}));
            Ok(())
        }
        Err(error) => {
            frame(&json!({"error":error}));
            Err("allocation contract failed".into())
        }
    }
}
