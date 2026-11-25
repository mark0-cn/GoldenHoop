//! Durable host process orchestration, with read-only pre-native probes.
use chrono::Utc;
use goldenhoop_docker::{DockerControllerProvider, DockerNetworkProvider, NetworkPlan};
use goldenhoop_egress::{HostProcessPlan, ProbeObservation, ProbePurpose};
use goldenhoop_protocol::{ApiError, ErrorCode};
use goldenhoop_store::{
    ControllerAbsence, ControllerPhase, NetworkController, NetworkNativeBinding, Store,
};
use std::time::Duration;
use uuid::Uuid;
fn unknown() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "host process settlement or observation is unconfirmed",
    )
}

pub async fn collect(
    store: &Store,
    mut record: NetworkController,
) -> Result<NetworkController, ApiError> {
    let provider = DockerControllerProvider::connect(record.plan.image_id()).await?;
    record = store
        .begin_controller_collection(
            record.sandbox_id,
            record.controller_generation,
            record.revision,
        )
        .await?;
    let observed = match &record.plan {
        HostProcessPlan::Controller(p) => provider.lookup(p).await?,
        HostProcessPlan::Probe(p) => provider.lookup_probe(p).await?,
    };
    if record.container_id.is_none() {
        if let Some(actual) = observed {
            record = store
                .record_controller_created(
                    record.sandbox_id,
                    record.controller_generation,
                    record.create_token.ok_or_else(unknown)?,
                    &actual.container_id,
                )
                .await?;
        } else if record.create_token.is_some() {
            return Err(unknown());
        }
    }
    let observed_at = if let Some(id) = &record.container_id {
        let removed = match &record.plan {
            HostProcessPlan::Controller(p) => provider.collect(p, id).await?,
            HostProcessPlan::Probe(p) => provider.collect_probe(p, id).await?,
        };
        if !removed.provider_absent {
            return Err(unknown());
        }
        removed.observed_at
    } else {
        Utc::now()
    };
    store
        .confirm_controller_absence(
            record.sandbox_id,
            record.controller_generation,
            record.collection_token.ok_or_else(unknown)?,
            ControllerAbsence {
                container_id: record.container_id.clone(),
                creation_settled: true,
                start_settled: true,
                provider_absent: true,
                observed_at,
            },
        )
        .await
}

/// Continue only positively unstarted phases. A missing dispatched create or a
/// still-Created object after a start intent is unknown, never a replay target.
pub async fn run_probe(
    store: &Store,
    record: &NetworkController,
) -> Result<(ProbeObservation, NetworkController), ApiError> {
    let authoritative = store
        .network_controller(record.sandbox_id, record.controller_generation)
        .await?;
    if !matches!(authoritative.plan, HostProcessPlan::Probe(_)) {
        return Err(ApiError::new(
            ErrorCode::InvalidState,
            "probe orchestration requires a probe plan",
        ));
    }
    let result = run_probe_inner(store, record).await;
    if result.is_err() {
        let fresh = store
            .network_controller(record.sandbox_id, record.controller_generation)
            .await?;
        if fresh.phase != ControllerPhase::Collected {
            collect(store, fresh).await?;
        }
    }
    result
}
async fn run_probe_inner(
    store: &Store,
    record: &NetworkController,
) -> Result<(ProbeObservation, NetworkController), ApiError> {
    let mut record = store
        .network_controller(record.sandbox_id, record.controller_generation)
        .await?;
    let plan = match &record.plan {
        HostProcessPlan::Probe(p) => p.clone(),
        _ => return Err(unknown()),
    };
    plan.validate_dispatch_at(Utc::now())?;
    let provider = DockerControllerProvider::connect(&plan.image_id).await?;
    if record.phase == ControllerPhase::Reserved {
        record = store
            .begin_controller_create(
                record.sandbox_id,
                record.controller_generation,
                record.revision,
            )
            .await?;
        let actual = provider.create_probe(&plan).await?;
        record = store
            .record_controller_created(
                record.sandbox_id,
                record.controller_generation,
                record.create_token.ok_or_else(unknown)?,
                &actual.container_id,
            )
            .await?;
    } else if record.phase == ControllerPhase::Creating {
        let actual = provider.lookup_probe(&plan).await?.ok_or_else(unknown)?;
        record = store
            .record_controller_created(
                record.sandbox_id,
                record.controller_generation,
                record.create_token.ok_or_else(unknown)?,
                &actual.container_id,
            )
            .await?;
    }
    let id = record.container_id.clone().ok_or_else(unknown)?;
    if record.phase == ControllerPhase::Created {
        record = store
            .begin_controller_start(
                record.sandbox_id,
                record.controller_generation,
                record.revision,
            )
            .await?;
        provider.start_probe(&plan, &id).await?;
        record = store
            .record_controller_running(
                record.sandbox_id,
                record.controller_generation,
                record.start_token.ok_or_else(unknown)?,
                &id,
            )
            .await?;
    } else if record.phase == ControllerPhase::Starting {
        let actual = provider.lookup_probe(&plan).await?.ok_or_else(unknown)?;
        if actual.container_id != id || !matches!(actual.status.as_str(), "running" | "exited") {
            return Err(unknown());
        }
        record = store
            .record_controller_running(
                record.sandbox_id,
                record.controller_generation,
                record.start_token.ok_or_else(unknown)?,
                &id,
            )
            .await?;
    }
    if record.phase != ControllerPhase::Running {
        return Err(unknown());
    }
    let result = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            plan.validate_dispatch_at(Utc::now())?;
            let actual = provider.lookup_probe(&plan).await?.ok_or_else(unknown)?;
            if actual.container_id != id || actual.paused || actual.dead || actual.restarting {
                return Err(unknown());
            }
            if actual.status == "exited" {
                break;
            }
            if !actual.running || tokio::time::Instant::now() >= deadline {
                return Err(unknown());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        provider.probe_result(&plan, &id).await
    }
    .await;
    let collected = collect(store, record).await?;
    Ok((result?, collected))
}

pub async fn discover_native(
    store: &Store,
    id: Uuid,
    probe_generation: Uuid,
    image: &str,
) -> Result<(NetworkNativeBinding, ProbeObservation, NetworkController), ApiError> {
    let network = store.network_allocation(id).await?;
    let sandbox = store.sandbox(id).await?;
    let plan = NetworkPlan {
        identity: network.identity(),
        provisioning_token: network.token.ok_or_else(unknown)?,
        expires_at: sandbox.sandbox.expires_at,
    };
    let provider = DockerNetworkProvider::connect().await?;
    let before = provider.lookup(&plan).await?.ok_or_else(unknown)?;
    if before.attached_endpoints != 0 {
        return Err(unknown());
    }
    let reserved = store
        .reserve_network_probe(
            id,
            network.generation,
            probe_generation,
            image,
            ProbePurpose::Discover,
            Some(&before.network_id),
        )
        .await?;
    let (observed, collected) = run_probe(store, &reserved).await?;
    let ProbeObservation::Native(native) = &observed else {
        return Err(unknown());
    };
    let after = provider.lookup(&plan).await?.ok_or_else(unknown)?;
    if before.network_id != after.network_id
        || after.attached_endpoints != 0
        || native.ipv4_gateway != after.ipv4_gateway
        || native.ipv6_gateway != after.ipv6_gateway
    {
        return Err(unknown());
    }
    let binding = NetworkNativeBinding {
        network_id: after.network_id,
        allocation: native.allocation.clone(),
    };
    store
        .bind_native_network(
            id,
            network.generation,
            plan.provisioning_token,
            binding.clone(),
        )
        .await?;
    Ok((binding, observed, collected))
}
