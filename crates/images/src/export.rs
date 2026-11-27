//! Never-started immutable OCI export into installation-owned large storage.
//! All provider writes follow durable CAS; missing create acknowledgement is
//! fenced, and an uncertain storage upload is never declared collected.
use crate::{
    ExportReport, ExportRequest,
    coordination::{Coordinator, Producer, Stamp},
    hex_id,
};
use bollard::{Docker, errors::Error as DockerError, models::*, query_parameters::*};
use futures_util::StreamExt;
use goldenhoop_artifacts::{BlobStore, LargeBlobRef};
use goldenhoop_image_builder::MAX_ARCHIVE_BYTES;
use goldenhoop_protocol::{ApiError, ErrorCode};
use goldenhoop_store::{ImageJob, Store};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, future::Future, io, time::Duration};
use tokio_util::io::StreamReader;
use uuid::Uuid;

const ROLE: &str = "image-source-export";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Reserved,
    CreateDispatched,
    Observed,
    UploadDispatched,
    ArchiveStored,
    Removing,
    Ready,
    FailedCollected,
    Collecting,
    Collected,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    format: u32,
    phase: Phase,
    container_id: Option<String>,
    archive: Option<LargeBlobRef>,
    source_observation: Option<serde_json::Value>,
    error: Option<ApiError>,
    #[serde(default)]
    coordination: Option<Stamp>,
    #[serde(default)]
    recovery_observation: Option<serde_json::Value>,
    #[serde(default)]
    producer: Option<Producer>,
}
fn unavailable() -> ApiError {
    let mut error = ApiError::new(
        ErrorCode::BackendUnavailable,
        "source export is unconfirmed; reconcile its exact durable generation",
    );
    error.retryable = false;
    error
}
fn conflict() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "source export ownership, placement or state differs",
    )
}
fn missing(error: &DockerError) -> bool {
    matches!(
        error,
        DockerError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}
async fn bounded<T>(call: impl Future<Output = Result<T, DockerError>>) -> Result<T, ApiError> {
    tokio::time::timeout(Duration::from_secs(15), call)
        .await
        .map_err(|_| unavailable())?
        .map_err(|_| unavailable())
}
fn state(job: &ImageJob) -> Result<State, ApiError> {
    let value: State = serde_json::from_value(job.payload.clone()).map_err(|_| conflict())?;
    if value.format != 1
        || value.container_id.as_deref().is_some_and(|id| !hex_id(id))
        || value.archive.as_ref().is_some_and(|a| {
            a.installation_id != job.installation_id
                || a.id != job.id
                || a.generation.is_nil()
                || !hex_id(&a.sha256)
                || job.request.get("storage_binding").and_then(|v| v.as_str())
                    != Some(a.storage_binding.as_str())
                || a.size_bytes == 0
                || a.size_bytes > MAX_ARCHIVE_BYTES
        })
    {
        return Err(conflict());
    }
    if let Some(observed) = &value.source_observation
        && (observed.get("container_id").and_then(|v| v.as_str()) != value.container_id.as_deref()
            || observed.get("image_id") != job.request.get("source_image")
            || observed["state"]["Status"] != "created"
            || observed["state"]["Pid"] != 0
            || observed["state"]["Running"] != false
            || !observed["mounts"].as_array().is_some_and(|v| v.is_empty())
            || observed["readonly_rootfs"] != true
            || observed["network_mode"] != "none")
    {
        return Err(conflict());
    }
    if matches!(
        value.phase,
        Phase::Ready | Phase::Collecting | Phase::Collected
    ) && (value.archive.is_none()
        || value.container_id.is_none()
        || value.source_observation.is_none()
        || (value.error.is_some() && value.phase != Phase::Collecting))
    {
        return Err(conflict());
    }
    Ok(value)
}
async fn save(store: &Store, job: &mut ImageJob, value: &State) -> Result<(), ApiError> {
    *job = store
        .update_image_job(job, &serde_json::to_value(value).map_err(|_| conflict())?)
        .await?;
    Ok(())
}
fn name(job: &ImageJob) -> String {
    format!(
        "ghx-{}-{}",
        job.installation_id.simple(),
        job.generation.simple()
    )
}
fn labels(job: &ImageJob) -> HashMap<String, String> {
    HashMap::from([
        (
            "dev.goldenhoop.installation".into(),
            job.installation_id.to_string(),
        ),
        ("dev.goldenhoop.role".into(), ROLE.into()),
        ("dev.goldenhoop.image-job".into(), job.id.to_string()),
        (
            "dev.goldenhoop.generation".into(),
            job.generation.to_string(),
        ),
        (
            "dev.goldenhoop.request-sha256".into(),
            job.request_sha256.clone(),
        ),
    ])
}
fn owned(
    actual: &ContainerInspectResponse,
    job: &ImageJob,
    request: &ExportRequest,
) -> Result<String, ApiError> {
    let config = actual.config.as_ref().ok_or_else(conflict)?;
    let host = actual.host_config.as_ref().ok_or_else(conflict)?;
    let process = actual.state.as_ref().ok_or_else(conflict)?;
    let id = actual
        .id
        .as_ref()
        .filter(|v| hex_id(v))
        .ok_or_else(conflict)?;
    if actual.name.as_deref() != Some(&format!("/{}", name(job)))
        || actual.image.as_deref() != Some(&request.source_image)
        || actual.restart_count != Some(0)
        || process.status.as_ref().map(ToString::to_string).as_deref() != Some("created")
        || process.running != Some(false)
        || process.paused != Some(false)
        || process.restarting != Some(false)
        || process.dead != Some(false)
        || process.pid != Some(0)
        || actual.mounts.as_ref().is_some_and(|v| !v.is_empty())
        || config.entrypoint.as_deref() != Some(&["/goldenhoop-never-executed".to_owned()])
        || host.readonly_rootfs != Some(true)
        || host.network_mode.as_deref() != Some("none")
        || host.privileged == Some(true)
        || host.binds.as_ref().is_some_and(|v| !v.is_empty())
        || host.mounts.as_ref().is_some_and(|v| !v.is_empty())
        || host.cap_add.as_ref().is_some_and(|v| !v.is_empty())
        || host.cap_drop.as_deref() != Some(&["ALL".to_owned()])
        || !host.security_opt.as_ref().is_some_and(|v| {
            v.iter()
                .any(|v| v == "no-new-privileges" || v == "no-new-privileges:true")
        })
        || !config.labels.as_ref().is_some_and(|values| {
            labels(job)
                .iter()
                .all(|(key, value)| values.get(key) == Some(value))
        })
    {
        return Err(conflict());
    }
    if state(job)?
        .container_id
        .as_ref()
        .is_some_and(|expected| expected != id)
    {
        return Err(conflict());
    }
    Ok(id.clone())
}

#[derive(Clone)]
pub struct SourceExporter {
    docker: Docker,
    store: Store,
    blobs: BlobStore,
    pub(crate) coordinator: Coordinator,
}
impl SourceExporter {
    /// Local socket only. The caller provides trusted host state/storage and
    /// cannot switch installations or storage bindings during a generation.
    pub async fn connect(store: Store, blobs: BlobStore) -> Result<Self, ApiError> {
        if unsafe { libc::geteuid() } != 0 || store.installation_id() != blobs.installation_id() {
            return Err(conflict());
        }
        let docker = Docker::connect_with_socket_defaults().map_err(|_| unavailable())?;
        let docker = bounded(docker.negotiate_version()).await?;
        let version = bounded(docker.version()).await?;
        let api = version
            .api_version
            .as_deref()
            .and_then(|v| v.split_once('.'))
            .and_then(|(a, b)| Some((a.parse::<u16>().ok()?, b.parse::<u16>().ok()?)));
        if version.os.as_deref() != Some("linux")
            || version.arch.as_deref() != Some("amd64")
            || api.is_none_or(|v| v < (1, 53))
        {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "source export requires a Linux amd64 Docker API1.53 host",
            ));
        }
        let engine = bounded(docker.info()).await?.id.ok_or_else(unavailable)?;
        let coordinator = Coordinator::connect(&store, engine).await?;
        Ok(Self {
            docker,
            store,
            blobs,
            coordinator,
        })
    }
    async fn lookup(&self, key: &str) -> Result<Option<ContainerInspectResponse>, ApiError> {
        match tokio::time::timeout(
            Duration::from_secs(15),
            self.docker.inspect_container(key, None),
        )
        .await
        {
            Ok(Ok(value)) => Ok(Some(value)),
            Ok(Err(error)) if missing(&error) => Ok(None),
            _ => Err(unavailable()),
        }
    }
    async fn observe(
        &self,
        job: &ImageJob,
        request: &ExportRequest,
    ) -> Result<(String, serde_json::Value), ApiError> {
        let actual = self.lookup(&name(job)).await?.ok_or_else(unavailable)?;
        let id = owned(&actual, job, request)?;
        if state(job)?
            .container_id
            .as_deref()
            .is_some_and(|expected| expected != id)
        {
            return Err(conflict());
        }
        let observed = json!({"container_id":id,"image_id":actual.image,"name":actual.name,"state":actual.state,
            "restart_count":actual.restart_count,"mounts":actual.mounts,"readonly_rootfs":actual.host_config.as_ref().and_then(|h|h.readonly_rootfs),
            "network_mode":actual.host_config.as_ref().and_then(|h|h.network_mode.as_deref())});
        Ok((id, observed))
    }
    async fn remove(&self, job: &ImageJob, request: &ExportRequest) -> Result<(), ApiError> {
        let value = state(job)?;
        let id = value.container_id.as_deref().ok_or_else(unavailable)?;
        if let Some(actual) = self.lookup(id).await? {
            owned(&actual, job, request)?;
            let _ = bounded(self.docker.remove_container(
                id,
                Some(RemoveContainerOptions {
                    force: false,
                    v: false,
                    ..Default::default()
                }),
            ))
            .await;
        }
        if self.lookup(id).await?.is_some() || self.lookup(&name(job)).await?.is_some() {
            return Err(unavailable());
        }
        Ok(())
    }
    async fn hash_export(&self, id: &str) -> Result<(String, u64), ApiError> {
        let transfer = async {
            let mut body = Box::pin(self.docker.export_container(id));
            let mut hash = Sha256::new();
            let mut size = 0u64;
            while let Some(bytes) = body.next().await {
                let bytes = bytes.map_err(|_| unavailable())?;
                size = size.checked_add(bytes.len() as u64).ok_or_else(conflict)?;
                if size > MAX_ARCHIVE_BYTES {
                    return Err(ApiError::new(
                        ErrorCode::InvalidRequest,
                        "source export exceeds the archive limit",
                    ));
                }
                hash.update(&bytes);
            }
            if size == 0 {
                return Err(conflict());
            }
            Ok((format!("{:x}", hash.finalize()), size))
        };
        tokio::time::timeout(Duration::from_secs(180), transfer)
            .await
            .map_err(|_| unavailable())?
    }
    fn report(job: &ImageJob, value: &State) -> ExportReport {
        ExportReport {
            id: job.id,
            generation: job.generation,
            archive_ready: value.phase == Phase::Ready && value.error.is_none(),
            provider_cleanup: if matches!(
                value.phase,
                Phase::Ready | Phase::FailedCollected | Phase::Collected
            ) {
                "complete"
            } else {
                "unknown"
            }
            .into(),
            archive: value.archive.clone(),
            source_observation: value.source_observation.clone(),
            recovery_observation: value.recovery_observation.clone(),
            error: value.error.clone(),
        }
    }
    pub async fn export(&self, request: ExportRequest) -> Result<ExportReport, ApiError> {
        request.validate()?;
        let lease = self.coordinator.acquire(request.id)?;
        let initial = State {
            format: 1,
            phase: Phase::Reserved,
            container_id: None,
            archive: None,
            source_observation: None,
            error: None,
            coordination: Some(lease.stamp.clone()),
            recovery_observation: None,
            producer: Some(Producer::current()?),
        };
        let immutable = json!({"format":1,"source_image":request.source_image,"storage_binding":self.blobs.binding()});
        let mut job = self
            .store
            .reserve_image_job(
                request.id,
                request.generation,
                &immutable,
                &serde_json::to_value(&initial).map_err(|_| conflict())?,
            )
            .await?;
        let mut value = state(&job)?;
        lease.check(
            value.coordination.as_ref(),
            matches!(
                value.phase,
                Phase::Ready | Phase::Collected | Phase::FailedCollected
            ),
        )?;
        if value.phase == Phase::Ready {
            self.blobs
                .download_large(
                    value.archive.as_ref().ok_or_else(conflict)?,
                    tokio::io::sink(),
                )
                .await?;
            return Ok(Self::report(&job, &value));
        }
        if matches!(value.phase, Phase::FailedCollected | Phase::Collected) {
            return Ok(Self::report(&job, &value));
        }
        if value.phase != Phase::Reserved {
            return Err(unavailable());
        }
        value.producer = Some(Producer::current()?);
        let admission=async {
            let image = bounded(self.docker.inspect_image(&request.source_image)).await?;
            if image.id.as_deref() != Some(&request.source_image) || image.os.as_deref() != Some("linux")
                || image.architecture.as_deref() != Some("amd64")
                || image.config.as_ref().is_none_or(|v|v.volumes.as_ref().is_some_and(|v|!v.is_empty())) {
                return Err(ApiError::new(ErrorCode::UnsupportedCapability,"source must be a pinned linux/amd64 image without anonymous volume declarations"));
            }
            Ok::<_,ApiError>(())
        }.await;
        if let Err(error) = admission {
            value.phase = Phase::FailedCollected;
            value.error = Some(error);
            save(&self.store, &mut job, &value).await?;
            return Ok(Self::report(&job, &value));
        }
        // Every subsequent provider write follows a successful CAS. A competing
        // caller cannot reset this dispatched generation or reissue its create.
        value.phase = Phase::CreateDispatched;
        save(&self.store, &mut job, &value).await?;
        let operation = async {
            let created = bounded(self.docker.create_container(
                Some(CreateContainerOptions {
                    name: Some(name(&job)),
                    ..Default::default()
                }),
                ContainerCreateBody {
                    image: Some(request.source_image.clone()),
                    entrypoint: Some(vec!["/goldenhoop-never-executed".into()]),
                    cmd: Some(vec![]),
                    user: Some("65534:65534".into()),
                    labels: Some(labels(&job)),
                    host_config: Some(HostConfig {
                        network_mode: Some("none".into()),
                        readonly_rootfs: Some(true),
                        cap_drop: Some(vec!["ALL".into()]),
                        security_opt: Some(vec!["no-new-privileges:true".into()]),
                        memory: Some(128 * 1024 * 1024),
                        memory_swap: Some(128 * 1024 * 1024),
                        pids_limit: Some(32),
                        nano_cpus: Some(1_000_000_000),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ))
            .await?;
            if !hex_id(&created.id) {
                return Err(conflict());
            }
            value.container_id = Some(created.id);
            value.phase = Phase::Observed;
            save(&self.store, &mut job, &value).await?;
            self.finish_archive(&mut job, &mut value, &request).await?;
            Ok::<_, ApiError>(())
        }
        .await;
        if let Err(error) = operation {
            // Keep a dispatched storage upload fenced even if the carrier can
            // be collected: cancelling a request is not provider settlement.
            let upload_unknown = value.phase == Phase::UploadDispatched;
            if value.phase == Phase::Ready {
                value.phase = Phase::Removing;
            }
            value.error = Some(error);
            save(&self.store, &mut job, &value).await?;
            if value.container_id.is_none()
                && let Some(actual) = self.lookup(&name(&job)).await?
            {
                value.container_id = Some(owned(&actual, &job, &request)?);
                save(&self.store, &mut job, &value).await?;
            }
            if value.container_id.is_some()
                && self.remove(&job, &request).await.is_ok()
                && !upload_unknown
                && value.archive.is_none()
            {
                value.phase = Phase::FailedCollected;
                save(&self.store, &mut job, &value).await?;
            }
        }
        Ok(Self::report(&job, &value))
    }
    /// Explicit collection of a stable published source archive. It cannot
    /// claim an in-flight/uncertain upload. A retried collector only deletes
    /// the same fenced immutable generation and cannot overwrite newer state.
    pub async fn collect(&self, id: Uuid) -> Result<ExportReport, ApiError> {
        let lease = self.coordinator.acquire(id)?;
        let mut job = self.store.image_job(id).await?;
        let mut value = state(&job)?;
        lease.check(
            value.coordination.as_ref(),
            matches!(
                value.phase,
                Phase::Ready | Phase::Collected | Phase::FailedCollected
            ),
        )?;
        if job.request.get("storage_binding").and_then(|v| v.as_str()) != Some(self.blobs.binding())
        {
            return Err(conflict());
        }
        if value.phase == Phase::Collected {
            return Ok(Self::report(&job, &value));
        }
        if !matches!(value.phase, Phase::Ready | Phase::Collecting) {
            return Err(unavailable());
        }
        if value.phase == Phase::Collecting {
            crate::coordination::recovery_storage(&self.blobs)?;
            value
                .producer
                .as_ref()
                .ok_or_else(unavailable)?
                .require_gone()?;
        }
        let source = job
            .request
            .get("source_image")
            .and_then(|v| v.as_str())
            .ok_or_else(conflict)?;
        let request = ExportRequest {
            id: job.id,
            generation: job.generation,
            source_image: source.into(),
        };
        request.validate()?;
        value.coordination = Some(lease.stamp.clone());
        value.producer = Some(Producer::current()?);
        value.phase = Phase::Collecting;
        save(&self.store, &mut job, &value).await?;
        self.remove(&job, &request).await?;
        self.blobs
            .collect_large(value.archive.as_ref().ok_or_else(conflict)?)
            .await?;
        value.phase = Phase::Collected;
        value.error = None;
        save(&self.store, &mut job, &value).await?;
        Ok(Self::report(&job, &value))
    }

    async fn finish_archive(
        &self,
        job: &mut ImageJob,
        value: &mut State,
        request: &ExportRequest,
    ) -> Result<(), ApiError> {
        if matches!(value.phase, Phase::Observed | Phase::UploadDispatched) {
            let committed = if let Some(reference) = &value.archive {
                self.blobs
                    .download_large(reference, tokio::io::sink())
                    .await
                    .is_ok()
            } else {
                false
            };
            if !committed {
                let (id, observed) = self.observe(job, request).await?;
                let (sha, size) = self.hash_export(&id).await?;
                if let Some(reference) = &value.archive {
                    if reference.sha256 != sha || reference.size_bytes != size {
                        return Err(conflict());
                    }
                } else {
                    value.archive = Some(self.blobs.large_reference(job.id, sha, size)?);
                }
                value.source_observation = Some(observed);
                value.phase = Phase::UploadDispatched;
                save(&self.store, job, value).await?;
                let body = Box::pin(self.docker.export_container(&id));
                let reader = StreamReader::new(body.map(|value| {
                    value.map_err(|_| io::Error::other("source export stream failed"))
                }));
                // Every object is create-only with exact readback. This resumes
                // the same journaled reference; it never allocates another one.
                self.blobs
                    .put_large(value.archive.as_ref().ok_or_else(conflict)?, reader)
                    .await?;
                value.source_observation = Some(self.observe(job, request).await?.1);
            }
            value.phase = Phase::ArchiveStored;
            save(&self.store, job, value).await?;
        }
        self.blobs
            .download_large(
                value.archive.as_ref().ok_or_else(conflict)?,
                tokio::io::sink(),
            )
            .await?;
        value.phase = Phase::Removing;
        save(&self.store, job, value).await?;
        self.remove(job, request).await?;
        self.blobs
            .download_large(
                value.archive.as_ref().ok_or_else(conflict)?,
                tokio::io::sink(),
            )
            .await?;
        value.error = None;
        value.phase = Phase::Ready;
        if let Some(observation) = &mut value.recovery_observation {
            observation["outcome"] = json!("ready");
        }
        save(&self.store, job, value).await
    }

    /// Reconcile the same local generation under an actual kernel writer lock.
    /// A missing unacknowledged create is still Unknown; no create is replayed.
    pub async fn reconcile(&self, id: Uuid) -> Result<ExportReport, ApiError> {
        let lease = self.coordinator.acquire(id)?;
        let mut job = self.store.image_job(id).await?;
        let mut value = state(&job)?;
        lease.check(
            value.coordination.as_ref(),
            matches!(
                value.phase,
                Phase::Ready | Phase::Collected | Phase::FailedCollected
            ),
        )?;
        if job.request.get("storage_binding").and_then(|v| v.as_str()) != Some(self.blobs.binding())
        {
            return Err(conflict());
        }
        let request = ExportRequest {
            id: job.id,
            generation: job.generation,
            source_image: job
                .request
                .get("source_image")
                .and_then(|v| v.as_str())
                .ok_or_else(conflict)?
                .into(),
        };
        request.validate()?;
        if matches!(value.phase, Phase::Collected | Phase::FailedCollected) {
            return Ok(Self::report(&job, &value));
        }
        if value.phase == Phase::Ready {
            if self
                .lookup(value.container_id.as_deref().ok_or_else(conflict)?)
                .await?
                .is_some()
                || self.lookup(&name(&job)).await?.is_some()
            {
                return Err(unavailable());
            }
            self.blobs
                .download_large(
                    value.archive.as_ref().ok_or_else(conflict)?,
                    tokio::io::sink(),
                )
                .await?;
            return Ok(Self::report(&job, &value));
        }
        crate::coordination::recovery_storage(&self.blobs)?;
        value
            .producer
            .as_ref()
            .ok_or_else(unavailable)?
            .require_gone()?;
        value.producer = Some(Producer::current()?);
        if value.recovery_observation.is_none() {
            value.recovery_observation = Some(
                json!({"from_phase":value.phase,"from_revision":job.revision,
                "original_error":value.error,"producer_fence":lease.stamp,"outcome":"unconfirmed"}),
            );
        }
        // Every recovery attempt records its own process before any mutation,
        // including a retry of a previously interrupted reconciler.
        save(&self.store, &mut job, &value).await?;
        let operation = async {
            if value.phase == Phase::Reserved {
                if self.lookup(&name(&job)).await?.is_some() || value.archive.is_some() {
                    return Err(unavailable());
                }
                value.error = Some(value.error.clone().unwrap_or_else(|| {
                    ApiError::new(
                        ErrorCode::BackendUnavailable,
                        "source producer interrupted before provider dispatch",
                    )
                }));
                value.phase = Phase::FailedCollected;
                value.recovery_observation.as_mut().ok_or_else(conflict)?["outcome"] =
                    json!("aborted_before_dispatch");
                return save(&self.store, &mut job, &value).await;
            }
            if value.phase == Phase::CreateDispatched {
                let actual = self.lookup(&name(&job)).await?.ok_or_else(unavailable)?;
                value.container_id = Some(owned(&actual, &job, &request)?);
                value.phase = Phase::Observed;
                save(&self.store, &mut job, &value).await?;
            }
            if value.phase == Phase::Collecting {
                self.remove(&job, &request).await?;
                self.blobs
                    .collect_large(value.archive.as_ref().ok_or_else(conflict)?)
                    .await?;
                value.phase = Phase::Collected;
                value.error = None;
                value.recovery_observation.as_mut().ok_or_else(conflict)?["outcome"] =
                    json!("collected");
                return save(&self.store, &mut job, &value).await;
            }
            if !matches!(
                value.phase,
                Phase::Observed | Phase::UploadDispatched | Phase::ArchiveStored | Phase::Removing
            ) {
                return Err(unavailable());
            }
            self.finish_archive(&mut job, &mut value, &request).await
        }
        .await;
        if let Err(error) = operation {
            if value.phase == Phase::Ready {
                value.phase = Phase::Removing;
            }
            if value.phase == Phase::Collected {
                value.phase = Phase::Collecting;
            }
            value.recovery_observation.as_mut().ok_or_else(conflict)?["last_error"] = json!(error);
            value.error = Some(error);
            save(&self.store, &mut job, &value).await?;
        }
        Ok(Self::report(&job, &value))
    }
}
