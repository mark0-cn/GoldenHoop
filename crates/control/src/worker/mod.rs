mod artifacts;
mod contexts;
mod credential_probe;
mod credentials;
mod driver;
mod executions;
mod lifecycle;
mod network_bootstrap;
mod network_probe;
pub use credentials::{CredentialOptions, CredentialProbe, CredentialSetup};
pub use driver::RuntimeSetup;
use driver::WorkerDriver;
pub use network_bootstrap::{NetworkOptions, NetworkSetup};
mod network_policy;
mod networks;
mod restorations;
mod sessions;
mod snapshots;

use std::{
    collections::HashMap,
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    middleware,
    routing::post,
};
use chrono::Utc;
use goldenhoop_core::{expired, require_capability, transition};
use goldenhoop_docker::{DockerConfig, DockerDriver, DockerProfile};
use goldenhoop_protocol::*;
use goldenhoop_runtime::*;
use goldenhoop_store::{Store, StoredSandbox, WorkerRegistration};
use tokio::{
    sync::{Mutex, Semaphore, watch},
    task::JoinSet,
};
use tower::limit::ConcurrencyLimitLayer;
use uuid::Uuid;

use crate::{InternalFileCall, InternalSandboxCall, http::*};

pub struct Worker {
    store: Store,
    drivers: HashMap<String, Arc<dyn WorkerDriver>>,
    registration: WorkerRegistration,
    locks: Mutex<HashMap<Uuid, Weak<Mutex<()>>>>,
    concurrency: Arc<Semaphore>,
    cancellations: Mutex<HashMap<Uuid, Instant>>,
    context_closures: Mutex<HashMap<Uuid, Instant>>,
    artifacts: goldenhoop_artifacts::BlobStore,
    artifact_concurrency: Arc<Semaphore>,
    snapshot_concurrency: Arc<Semaphore>,
    network_controller_image: Option<String>,
    network_options: Option<NetworkOptions>,
    credentials: Option<Arc<CredentialSetup>>,
    network_tasks: Mutex<HashMap<Uuid, network_policy::NetworkTask>>,
}

impl Worker {
    pub async fn new(
        store: Store,
        runtime: RuntimeSetup,
        endpoint: String,
        artifacts: goldenhoop_artifacts::BlobStore,
        network: NetworkSetup,
    ) -> Result<Arc<Self>, ApiError> {
        let RuntimeSetup {
            agent_image,
            kernel_probe_image,
            allow_runc_development,
            firecracker_config,
        } = runtime;
        if agent_image.is_none() && firecracker_config.is_none() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "worker requires an explicitly configured runtime",
            ));
        }
        #[cfg(not(target_os = "linux"))]
        if firecracker_config.is_some() {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "Firecracker requires Linux root with actual KVM",
            ));
        }
        let NetworkSetup {
            controller_image: network_controller_image,
            options: network_options,
            credentials,
        } = network;
        if agent_image.is_none()
            && (network_options.is_some()
                || network_controller_image.is_some()
                || credentials.is_some())
        {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "protected networking requires a configured container runtime",
            ));
        }
        let credentials = credentials.map(Arc::new);
        if let Some(credentials) = &credentials {
            if network_options.is_none() || network_controller_image.is_none() {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    "credential broker requires protected network configuration",
                ));
            }
            store.verify_vault_key(&credentials.key).await?;
        }
        if artifacts.installation_id() != store.installation_id() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "artifact storage installation identity mismatch",
            ));
        }
        store.bind_artifact_backend(artifacts.binding()).await?;
        if let Some(image) = &network_controller_image {
            goldenhoop_docker::DockerControllerProvider::connect(image).await?;
        }
        if let Some(options) = &network_options {
            if network_controller_image.is_none() {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    "protected networking requires a pinned controller image",
                ));
            }
            options.validate()?;
            store.bind_network_operator(&options.operator).await?;
        }
        let mut drivers: HashMap<String, Arc<dyn WorkerDriver>> = HashMap::new();
        let mut profiles = Vec::new();
        if let Some(agent_image) = &agent_image {
            for profile in [DockerProfile::Gvisor, DockerProfile::RuncDevelopment] {
                let driver = Arc::new(
                    DockerDriver::connect(DockerConfig {
                        installation_id: store.installation_id(),
                        agent_image: agent_image.clone(),
                        profile,
                        allow_runc_development,
                    })
                    .await?,
                );
                let mut observed = driver.probe().await;
                if observed.availability == Availability::Available
                    && let Some(image) = &kernel_probe_image
                {
                    observed = match driver.probe_code_contexts(image).await {
                        Ok(profile) => profile,
                        Err(error) => {
                            report("kernel_probe_failed", &error);
                            driver.profile_snapshot().await
                        }
                    };
                }
                if observed.availability == Availability::Available {
                    match driver.probe_isolated_sandboxes().await {
                        Ok(()) => {
                            observed.capabilities.insert(Capability::IsolatedSessions);
                        }
                        Err(error) => report("isolated_runtime_probe_failed", &error),
                    }
                }
                profiles.push(observed);
                drivers.insert(profile.id().into(), driver);
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(path) = firecracker_config {
            use goldenhoop_firecracker::lifecycle::{DriverConfig, FirecrackerDriver};
            let unavailable = || {
                ApiError::new(
                    ErrorCode::BackendUnavailable,
                    "native configuration, artifact or installation ownership is unconfirmed",
                )
            };
            let cfg = DriverConfig::read(&path).map_err(|_| unavailable())?;
            if cfg.installation_id != store.installation_id() {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    "native runtime installation identity must match the worker store",
                ));
            }
            let driver = Arc::new(FirecrackerDriver::connect(cfg).map_err(|_| unavailable())?);
            let observed = driver.probe().await;
            drivers.insert(observed.id.clone(), driver);
            profiles.push(observed);
        }
        let artifact_support = match artifacts.probe().await {
            Ok(()) => true,
            Err(error) => {
                report("artifact_storage_probe_failed", &error);
                false
            }
        };
        if artifact_support {
            for profile in &mut profiles {
                if profile.availability == Availability::Available
                    && profile.capabilities.contains(&Capability::Files)
                {
                    profile.capabilities.insert(Capability::Artifacts);
                }
            }
        }
        if network_options.is_some() {
            for profile in &mut profiles {
                if profile.availability == Availability::Available
                    && drivers
                        .get(&profile.id)
                        .is_some_and(|driver| driver.protected_docker().is_ok())
                {
                    // Internal candidate only. The public registration remains
                    // unavailable until real application and cleanup succeed.
                    profile.capabilities.insert(Capability::NetworkPolicy);
                    if credentials
                        .as_ref()
                        .is_some_and(|setup| setup.probe.is_some())
                    {
                        profile.capabilities.insert(Capability::SecretInjection);
                    }
                }
            }
        }
        let registration = WorkerRegistration {
            id: Uuid::new_v4(),
            endpoint,
            token: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
            heartbeat: Utc::now(),
            profiles,
        };
        let mut pending = registration.clone();
        if network_options.is_some() {
            for profile in &mut pending.profiles {
                if !profile.capabilities.contains(&Capability::NetworkPolicy) {
                    continue;
                }
                profile.availability = Availability::Unavailable;
                profile.capabilities.remove(&Capability::NetworkPolicy);
                profile.capabilities.remove(&Capability::SecretInjection);
                profile.reason = Some("protected network availability probe is in progress".into());
            }
        }
        store.register_worker(&pending).await?;
        let mut worker = Arc::new(Self {
            store,
            drivers,
            registration,
            locks: Mutex::new(HashMap::new()),
            concurrency: Arc::new(Semaphore::new(4)),
            cancellations: Mutex::new(HashMap::new()),
            context_closures: Mutex::new(HashMap::new()),
            artifacts,
            artifact_concurrency: Arc::new(Semaphore::new(2)),
            snapshot_concurrency: Arc::new(Semaphore::new(1)),
            network_controller_image,
            network_options,
            credentials,
            network_tasks: Mutex::new(HashMap::new()),
        });
        if worker.network_options.is_some() {
            let agent_image = agent_image.ok_or_else(|| {
                ApiError::new(
                    ErrorCode::InvalidRequest,
                    "protected network probe requires the configured container image",
                )
            })?;
            let (stop, receive) = watch::channel(false);
            let store = worker.store.clone();
            let heartbeat = tokio::spawn(network_probe::pending_heartbeat(store, pending, receive));
            let probing = worker.clone();
            let probe = tokio::spawn(async move {
                Box::pin(probing.probe_network_profiles(&agent_image)).await
            });
            let result = probe.await.map_err(|_| {
                ApiError::new(
                    ErrorCode::BackendUnavailable,
                    "network probe task did not settle",
                )
            })?;
            let _ = stop.send(true);
            heartbeat.await.map_err(|_| {
                ApiError::new(
                    ErrorCode::BackendUnavailable,
                    "network probe heartbeat did not settle",
                )
            })??;
            let profiles = result?;
            let owned = Arc::get_mut(&mut worker).ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Internal,
                    "network probe retained worker ownership",
                )
            })?;
            owned.registration.profiles = profiles;
            owned.registration.heartbeat = Utc::now();
            owned.store.register_worker(&owned.registration).await?;
        }
        Ok(worker)
    }

    pub fn router(self: &Arc<Self>) -> Result<Router, ApiError> {
        let auth = BearerAuth::new(&self.registration.token)?;
        Ok(Router::new()
            .route("/internal/files", post(files))
            .route(
                "/internal/snapshots",
                post(snapshots::create).layer(DefaultBodyLimit::max(8192)),
            )
            .route(
                "/internal/restorations",
                post(restorations::create).layer(DefaultBodyLimit::max(64 * 1024)),
            )
            .route("/internal/diagnostics", post(diagnostics))
            .route("/internal/artifact-content", post(artifacts::content))
            .fallback(not_found)
            .layer(DefaultBodyLimit::max(24 * 1024 * 1024))
            .layer(ConcurrencyLimitLayer::new(16))
            .layer(middleware::from_fn_with_state(auth, authenticate))
            .with_state(self.clone()))
    }

    async fn lock(&self, id: Uuid) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&id).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(id, Arc::downgrade(&lock));
        lock
    }

    pub async fn run(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut tasks = JoinSet::new();
        let mut offset = 0_usize;
        let mut artifact_offset = 0_usize;
        let mut snapshot_offset = 0_usize;
        loop {
            if *shutdown.borrow() {
                break;
            }
            if let Err(error) = self
                .schedule_snapshot_work(&mut tasks, &mut snapshot_offset)
                .await
            {
                report("snapshot_work_scan_failed", &error);
            }
            match self.store.work().await {
                Ok(mut work) => {
                    if !work.is_empty() {
                        let start = offset % work.len();
                        work.rotate_left(start);
                        offset = offset.wrapping_add(4);
                    }
                    for stored in work {
                        let Ok(permit) = self.concurrency.clone().try_acquire_owned() else {
                            break;
                        };
                        let Ok(guard) = self.lock(stored.sandbox.id).await.try_lock_owned() else {
                            continue;
                        };
                        let worker = self.clone();
                        let id = stored.sandbox.id;
                        tasks.spawn(async move {
                            let _guard = guard;
                            let _permit = permit;
                            if let Err(error) = worker.reconcile(id).await {
                                if let Err(persist) = worker.record_error(id, &error).await {
                                    report("observation_persist_failed", &persist);
                                }
                                report("reconciliation_failed", &error);
                            }
                        });
                    }
                }
                Err(error) => report("work_scan_failed", &error),
            }
            while let Some(result) = tasks.try_join_next() {
                if result.is_err() {
                    eprintln!("{{\"event\":\"reconciliation_task_failed\"}}");
                }
            }
            if let Err(error) = self.store.settle_network_policy_changes().await {
                report("network_policy_change_settlement_failed", &error);
            }
            match self.store.artifact_work().await {
                Ok(mut work) => {
                    if !work.is_empty() {
                        let start = artifact_offset % work.len();
                        work.rotate_left(start);
                        artifact_offset = artifact_offset.wrapping_add(2);
                    }
                    for stored in work {
                        let Ok(permit) = self.artifact_concurrency.clone().try_acquire_owned()
                        else {
                            break;
                        };
                        let id = stored.artifact.id;
                        let Ok(guard) = self.lock(id).await.try_lock_owned() else {
                            continue;
                        };
                        let worker = self.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            let _guard = guard;
                            if let Err(error) = worker.reconcile_artifact(id).await {
                                worker.artifact_error(id, &error).await;
                                report("artifact_reconciliation_failed", &error);
                            }
                        });
                    }
                }
                Err(error) => report("artifact_work_scan_failed", &error),
            }
            tokio::select! {result = shutdown.changed()=>{if result.is_err(){break;}},_ = tokio::time::sleep(Duration::from_millis(200))=>{}}
        }
        // Allow in-flight operations to finish. Crash recovery still uses owned labels.
        let drain = async { while tasks.join_next().await.is_some() {} };
        if tokio::time::timeout(Duration::from_secs(30), drain)
            .await
            .is_err()
        {
            tasks.shutdown().await;
        }
        let ids = self
            .network_tasks
            .lock()
            .await
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for id in ids {
            if let Err(error) = self.stop_network_task(id).await {
                report("network_session_shutdown_unconfirmed", &error);
            }
        }
    }

    pub async fn heartbeat(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        loop {
            let mut registration = self.registration.clone();
            registration.heartbeat = if *shutdown.borrow() {
                Utc::now() - chrono::Duration::seconds(60)
            } else {
                Utc::now()
            };
            if let Err(error) = self.store.register_worker(&registration).await {
                report("heartbeat_failed", &error);
            }
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {result = shutdown.changed()=>{if result.is_err(){return;}},_ = tokio::time::sleep(Duration::from_secs(2))=>{}}
        }
    }

    pub async fn expire(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        loop {
            for driver in self.drivers.values() {
                match driver.reap_expired().await {
                    Ok(ids) => {
                        for id in ids {
                            println!(
                                "{}",
                                serde_json::json!({"event":"expired_sandbox_removed","sandbox_id":id})
                            );
                        }
                    }
                    Err(error) => report("expiry_scan_failed", &error),
                }
            }
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {result = shutdown.changed()=>{if result.is_err(){return;}},_ = tokio::time::sleep(Duration::from_secs(1))=>{}}
        }
    }

    pub(super) async fn save(
        &self,
        mut stored: StoredSandbox,
        state: SandboxState,
        cleanup: CleanupState,
        reason: Option<String>,
    ) -> Result<StoredSandbox, ApiError> {
        if stored.sandbox.state != state && transition(stored.sandbox.state, state).is_err() {
            if stored.sandbox.state == SandboxState::Pending {
                stored.sandbox.state = SandboxState::Starting;
                self.store.observe(stored.clone()).await?;
            }
            if stored.sandbox.state != SandboxState::Unknown
                && transition(stored.sandbox.state, state).is_err()
            {
                transition(stored.sandbox.state, SandboxState::Unknown)?;
                stored.sandbox.state = SandboxState::Unknown;
                stored.sandbox.cleanup = CleanupState::Unknown;
                self.store.observe(stored.clone()).await?;
            }
        }
        stored.sandbox.state = state;
        stored.sandbox.cleanup = cleanup;
        stored.sandbox.observed_at = Some(Utc::now());
        stored.sandbox.reason = reason;
        let id = stored.sandbox.id;
        self.store.observe(stored).await?;
        self.store.sandbox(id).await
    }
}

fn report(event: &str, error: &ApiError) {
    eprintln!("{}", serde_json::json!({"event":event,"error":error}));
}

async fn diagnostics(
    State(worker): State<Arc<Worker>>,
    ApiJson(call): ApiJson<InternalSandboxCall>,
) -> Result<Json<SandboxDiagnostics>, HttpError> {
    let _guard = worker.lock(call.sandbox_id).await.lock_owned().await;
    let stored = worker.store.sandbox(call.sandbox_id).await?;
    worker
        .store
        .authorize_feature(call.sandbox_id, Capability::Diagnostics)
        .await?;
    let profile = worker
        .registration
        .profiles
        .iter()
        .find(|profile| profile.id == stored.sandbox.profile)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::UnsupportedCapability,
                "sandbox profile is unavailable",
            )
        })?;
    require_capability(profile, Capability::Diagnostics)?;
    let driver = worker
        .drivers
        .get(&stored.sandbox.profile)
        .map(Arc::as_ref)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "worker has no driver for this profile",
            )
        })?;
    let runtime = if let Some(handle) = worker.recovered_handle(&stored, driver).await? {
        worker.require_network_dispatch(call.sandbox_id).await?;
        match driver.diagnostics(&handle).await {
            Ok(sample) => Some(sample),
            Err(error) if error.code == ErrorCode::NotFound => None,
            Err(error) => return Err(error.into()),
        }
    } else {
        None
    };
    Ok(Json(SandboxDiagnostics {
        sandbox: stored.sandbox,
        runtime,
    }))
}

async fn files(
    State(worker): State<Arc<Worker>>,
    ApiJson(call): ApiJson<InternalFileCall>,
) -> Result<Json<AgentResponse>, HttpError> {
    if !matches!(
        call.request,
        AgentRequest::WriteFile { .. }
            | AgentRequest::ReadFile { .. }
            | AgentRequest::ListFiles { .. }
            | AgentRequest::RemoveFile { .. }
    ) {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "private file route rejects other agent methods",
        )
        .into());
    }
    let _guard = worker.lock(call.sandbox_id).await.lock_owned().await;
    let stored = worker.store.sandbox(call.sandbox_id).await?;
    worker
        .store
        .authorize_work(call.sandbox_id, Capability::Files)
        .await?;
    let profile = worker
        .registration
        .profiles
        .iter()
        .find(|profile| profile.id == stored.sandbox.profile)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::UnsupportedCapability,
                "sandbox profile is unavailable",
            )
        })?;
    require_capability(profile, Capability::Files)?;
    let driver = worker
        .drivers
        .get(&stored.sandbox.profile)
        .map(Arc::as_ref)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "worker has no driver for this profile",
            )
        })?;
    let handle = stored.handle.ok_or_else(|| {
        ApiError::new(
            ErrorCode::BackendUnavailable,
            "runtime handle is not available",
        )
    })?;
    Ok(Json(worker.rpc(driver, &handle, &call.request).await?))
}
