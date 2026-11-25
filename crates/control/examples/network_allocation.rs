//! Allocation-only real-backend contract. No workload is attached or published.
use chrono::{Duration, Utc};
use clap::{Parser, ValueEnum};
use goldenhoop_docker::{
    DockerConfig, DockerControllerProvider, DockerDriver, DockerNetworkProvider, DockerProfile,
    NetworkPlan,
};
use goldenhoop_egress::{
    Allocation, NetworkIdentity,
    controller::{CallError, Reply as ControllerReply, Request as ControllerRequest},
    native::{NativeBridgeObservation, NativeBridgePlan},
};
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
    ControllerCreate,
    ControllerRecover,
    ControllerRun,
    ControllerCollect,
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
    #[arg(long)]
    controller_image: Option<String>,
    #[arg(long)]
    fault_after_controller: bool,
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
async fn controller_call(
    session: &mut goldenhoop_docker::ControllerSession,
    request: ControllerRequest,
) -> Result<Value, ApiError> {
    match session
        .call(
            request,
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await
        .map_err(|_| invalid())?
    {
        ControllerReply::Result(value) => Ok(value),
        ControllerReply::Error(error) => Err(error),
    }
}

async fn exercise_controller(
    args: &Args,
    store: &Store,
    provider: &DockerNetworkProvider,
    record: &NetworkAllocation,
    network: &NetworkPlan,
) -> Result<Value, ApiError> {
    // This private contract reconstructs a checkpoint from the actual database
    // and verifies the original provider before any privileged process write.
    // It does not implement the production worker's controller dispatch journal.
    let native = record.native.as_ref().ok_or_else(invalid)?;
    require(
        record.phase == NetworkPhase::Provisioning
            && record.binding.is_none()
            && record.token == Some(network.provisioning_token),
    )?;
    let observed = provider.lookup(network).await?.ok_or_else(invalid)?;
    require(observed.network_id == native.network_id && observed.attached_endpoints == 0)?;
    let sandbox = store.sandbox(record.sandbox_id).await?;
    require(
        sandbox.sandbox.expires_at == network.expires_at && sandbox.sandbox.expires_at > Utc::now(),
    )?;
    let controllers =
        DockerControllerProvider::connect(args.controller_image.as_deref().ok_or_else(invalid)?)
            .await?;
    let plan = controllers.plan(NativeBridgePlan {
        identity: record.identity(),
        allocation: native.allocation.clone(),
        provisioning_token: network.provisioning_token,
        expires_at: network.expires_at,
    })?;
    frame(&json!({"controller_plan":plan,"journal_native_checkpoint":native}));
    if matches!(args.action, Action::ControllerCreate) {
        let created = controllers.create_fresh(&plan).await?;
        frame(&json!({"created_controller":created}));
        if args.fault_after_controller {
            eprintln!(
                "controlled exit after controller creation before caller acknowledgement or start"
            );
            std::process::exit(77);
        }
        return Ok(json!({"controller":created,"workload_or_packet_publication":false}));
    }
    let actual = controllers.lookup(&plan).await?.ok_or_else(invalid)?;
    if matches!(args.action, Action::ControllerRecover) {
        return Ok(json!({"controller":actual,"creation_replayed":false,"start_replayed":false}));
    }
    if matches!(args.action, Action::ControllerCollect) {
        let removed = controllers.collect(&plan, &actual.container_id).await?;
        let replay = controllers.collect(&plan, &actual.container_id).await?;
        require(
            removed.provider_absent
                && replay.provider_absent
                && controllers.lookup(&plan).await?.is_none(),
        )?;
        return Ok(
            json!({"removed":removed,"repeated_collection":replay,"native_collection_attested":false}),
        );
    }
    let mut refusals = BTreeSet::new();
    for field in 0..4 {
        let mut wrong = plan.clone();
        match field {
            0 => wrong.native.provisioning_token = Uuid::new_v4(),
            1 => wrong.native.expires_at += Duration::seconds(1),
            2 => wrong.native.allocation.ifindex += 1,
            _ => wrong.native.identity.profile = "foreign-profile".into(),
        };
        require(
            controllers.lookup(&wrong).await.is_err()
                && controllers
                    .collect(&wrong, &actual.container_id)
                    .await
                    .is_err(),
        )?;
        refusals.insert(format!("foreign_plan_{field}"));
    }
    let foreign = "0".repeat(64);
    require(
        controllers.collect(&plan, &foreign).await.is_err()
            && controllers.start_created(&plan, &foreign).await.is_err(),
    )?;
    require(
        controllers
            .lookup(&plan)
            .await?
            .is_some_and(|c| c.container_id == actual.container_id && c.status == "created"),
    )?;
    let mut session = controllers
        .start_created(&plan, &actual.container_id)
        .await?;
    let result=async {
        let mut wrong=plan.native.allocation.clone();wrong.ifindex+=1;
        require(matches!(session.call(ControllerRequest::Open {allocation:wrong},tokio::time::Instant::now()+std::time::Duration::from_secs(5)).await,Err(CallError::InvalidRequest)))?;
        let unopened=controller_call(&mut session,ControllerRequest::Inspect {}).await.unwrap_err();require(unopened.code==ErrorCode::InvalidState && !session.is_uncertain())?;
        let bound=controller_call(&mut session,ControllerRequest::BindNative {plan:plan.native.clone()}).await?;
        let alias:NativeBridgeObservation=serde_json::from_value(bound.clone()).map_err(|_|invalid())?;
        require(alias.identity_sha256==plan.native.identity.digest() && alias.allocation.owner()==plan.native.allocation.owner() && alias.alias==plan.native.allocation.owner() && alias.provisioning_token==plan.native.provisioning_token)?;
        let opened=controller_call(&mut session,ControllerRequest::Open {allocation:plan.native.allocation.clone()}).await?;
        require(opened["installed"]==false && opened["revision"].is_null() && opened["uncertain"]==false)?;
        let refused=controller_call(&mut session,ControllerRequest::BindNative {plan:plan.native.clone()}).await.unwrap_err();require(refused.code==ErrorCode::Conflict)?;
        require(matches!(session.call(ControllerRequest::Inspect {},tokio::time::Instant::now()).await,Err(CallError::ExpiredDeadline)))?;
        let inspected=controller_call(&mut session,ControllerRequest::Inspect {}).await?;require(inspected==opened)?;
        require(controllers.create_fresh(&plan).await.is_err() && controllers.start_created(&plan,&actual.container_id).await.is_err())?;
        Ok::<Value,ApiError>(json!({"native_alias":bound,"manager":opened,"foreign_refusals":refusals,"duplicate_create_start_refused":true,"expired_local_call_did_not_fence_channel":!session.is_uncertain()}))
    }.await;
    let exited = session.close().await;
    if result.is_err() || exited.is_err() {
        let cleanup = controllers.collect(&plan, &actual.container_id).await;
        frame(&json!({"controller_failure_collection":cleanup.as_ref().ok()}));
    }
    let result = result?;
    let exited = exited?;
    require(
        controllers
            .start_created(&plan, &actual.container_id)
            .await
            .is_err(),
    )?;
    Ok(
        json!({"exchange":result,"exited":exited,"exited_controller_not_restarted":true,"workload_or_packet_publication":false}),
    )
}

async fn exercise(args: &Args, store: &Store) -> Result<Value, ApiError> {
    let controller = matches!(
        args.action,
        Action::ControllerCreate
            | Action::ControllerRecover
            | Action::ControllerRun
            | Action::ControllerCollect
    );
    require(controller || (args.controller_image.is_none() && !args.fault_after_controller))?;
    require(!args.fault_after_controller || matches!(args.action, Action::ControllerCreate))?;
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
    if controller {
        return exercise_controller(args, store, &provider, &record, &plan).await;
    }
    match args.action {
        Action::Init => unreachable!(),
        Action::ControllerCreate
        | Action::ControllerRecover
        | Action::ControllerRun
        | Action::ControllerCollect => unreachable!("handled above"),
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
