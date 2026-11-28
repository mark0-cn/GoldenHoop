//! Durable trusted-host source -> isolated converter -> verified disk pipeline.
//! Uncertain writes remain fenced, never silently replayed. Published disks
//! are private artifacts; runtime/snapshot/template capabilities are separate.
use crate::{
    ExportRequest, ImagePrepareReport, ImagePrepareRequest,
    coordination::{Coordinator, Producer, Stamp},
    export::SourceExporter,
    hex_id,
    host::{HostGuard, HostObservation},
    transfer::{self, FileStream},
};
use bollard::{
    Docker, container::LogOutput, errors::Error as DockerError, models::*, query_parameters::*,
};
use futures_util::{StreamExt, TryStreamExt};
use goldenhoop_artifacts::{BlobStore, LargeBlobRef};
use goldenhoop_image_builder::{
    BuilderInventory, BuilderLimits, BuilderRuntime, Content, HostPermit, PrepareReport,
    PrepareRequest, PreparedImage,
};
use goldenhoop_protocol::{ApiError, ErrorCode};
use goldenhoop_store::{ImageJob, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, future::Future, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

mod ready;
pub use ready::MaterializedImage;

const ROLE: &str = "image-prepare";
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Reserved,
    SourceDispatched,
    SourceReady,
    VolumesDispatched,
    VolumesReady,
    SeederDispatched,
    SeederObserved,
    InputUploadDispatched,
    InputReady,
    SeederRemoved,
    BuilderDispatched,
    BuilderObserved,
    StartDispatched,
    RunningObserved,
    AuthorizationDispatched,
    BuilderExited,
    OutputVerified,
    DiskUploadDispatched,
    DiskStored,
    ProviderCollecting,
    ProvidersCollected,
    SourceCollecting,
    Ready,
    FailedCollected,
    Collecting,
    Collected,
    AbortingBeforeInput,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    format: u32,
    phase: Phase,
    source: ExportRequest,
    archive: Option<LargeBlobRef>,
    inventory: Option<BuilderInventory>,
    request: Option<PrepareRequest>,
    nonce: Uuid,
    seeder_id: Option<String>,
    builder_id: Option<String>,
    host: Option<HostObservation>,
    converter_observation: Option<Value>,
    manifest: Option<PreparedImage>,
    disk: Option<LargeBlobRef>,
    error: Option<ApiError>,
    #[serde(default)]
    coordination: Option<Stamp>,
    #[serde(default)]
    recovery_observation: Option<Value>,
    #[serde(default)]
    producer: Option<Producer>,
}
fn conflict() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "image preparation ownership, placement or state differs",
    )
}
fn unknown() -> ApiError {
    let mut e = ApiError::new(
        ErrorCode::BackendUnavailable,
        "image preparation is unconfirmed; reconcile its exact durable generation",
    );
    e.retryable = false;
    e
}
fn bad_output(error: impl std::fmt::Display) -> ApiError {
    let mut result = ApiError::new(
        ErrorCode::BackendUnavailable,
        format!(
            "isolated converter output or host enforcement is unconfirmed: {}",
            error.to_string().chars().take(256).collect::<String>()
        ),
    );
    result.retryable = false;
    result
}
fn missing(e: &DockerError) -> bool {
    matches!(
        e,
        DockerError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}
async fn bounded<T>(call: impl Future<Output = Result<T, DockerError>>) -> Result<T, ApiError> {
    tokio::time::timeout(Duration::from_secs(15), call)
        .await
        .map_err(|_| unknown())?
        .map_err(|_| unknown())
}
async fn save(store: &Store, job: &mut ImageJob, value: &State) -> Result<(), ApiError> {
    *job = store
        .update_image_job(job, &serde_json::to_value(value).map_err(|_| conflict())?)
        .await?;
    Ok(())
}
async fn phase(
    store: &Store,
    job: &mut ImageJob,
    value: &mut State,
    next: Phase,
) -> Result<(), ApiError> {
    value.phase = next;
    save(store, job, value).await
}
fn resource(job: &ImageJob, suffix: &str) -> String {
    format!(
        "ghi-{}-{}-{suffix}",
        job.installation_id.simple(),
        job.generation.simple()
    )
}
fn labels(job: &ImageJob, part: &str) -> HashMap<String, String> {
    HashMap::from([
        (
            "dev.goldenhoop.installation".into(),
            job.installation_id.to_string(),
        ),
        ("dev.goldenhoop.role".into(), ROLE.into()),
        ("dev.goldenhoop.job".into(), job.id.to_string()),
        (
            "dev.goldenhoop.generation".into(),
            job.generation.to_string(),
        ),
        (
            "dev.goldenhoop.request-sha256".into(),
            job.request_sha256.clone(),
        ),
        ("dev.goldenhoop.part".into(), part.into()),
    ])
}
fn limits() -> BuilderLimits {
    BuilderLimits {
        memory_max: 1024 * 1024 * 1024,
        swap_max: 0,
        pids_max: 128,
        cpu_quota: 100000,
        cpu_period: 100000,
    }
}
fn mounts(job: &ImageJob, builder: bool) -> Vec<Mount> {
    let one = |part: &str, target: &str, readonly: bool| Mount {
        typ: Some(MountType::VOLUME),
        source: Some(resource(job, part)),
        target: Some(target.into()),
        read_only: Some(readonly),
        volume_options: Some(MountVolumeOptions {
            no_copy: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    if builder {
        vec![
            one("input", "/input", true),
            one("output", "/output", false),
        ]
    } else {
        vec![one("input", "/input", false)]
    }
}

pub(crate) fn same_mount(actual: &Mount, expected: &Mount) -> bool {
    actual.typ == expected.typ
        && actual.source == expected.source
        && actual.target == expected.target
        && actual.read_only.unwrap_or(false) == expected.read_only.unwrap_or(false)
        && actual.volume_options == expected.volume_options
        && actual.bind_options.is_none()
        && actual.image_options.is_none()
        && actual.tmpfs_options.is_none()
        && actual.consistency.is_none()
}
fn state(
    job: &ImageJob,
    request: &ImagePrepareRequest,
    blobs: &BlobStore,
) -> Result<State, ApiError> {
    let value: State = serde_json::from_value(job.payload.clone()).map_err(|_| conflict())?;
    value.source.validate()?;
    if value.format != 1
        || value.nonce.is_nil()
        || value.source.id == job.id
        || value.source.generation == job.generation
        || value.source.source_image != request.source_image
        || job.request.get("storage_binding").and_then(Value::as_str) != Some(blobs.binding())
        || [value.seeder_id.as_deref(), value.builder_id.as_deref()]
            .iter()
            .flatten()
            .any(|id| !hex_id(id))
    {
        return Err(conflict());
    }
    if let Some(archive) = &value.archive {
        if archive.installation_id != job.installation_id
            || archive.id != value.source.id
            || archive.storage_binding != blobs.binding()
            || archive.generation.is_nil()
        {
            return Err(conflict());
        }
        Content {
            sha256: archive.sha256.clone(),
            size_bytes: archive.size_bytes,
        }
        .validate(goldenhoop_image_builder::MAX_ARCHIVE_BYTES)
        .map_err(bad_output)?;
    }
    if let Some(inventory) = &value.inventory {
        inventory.validate().map_err(bad_output)?;
    }
    if let Some(conversion) = &value.request {
        conversion.validate().map_err(bad_output)?;
        let inventory = value.inventory.as_ref().ok_or_else(conflict)?;
        let archive = value.archive.as_ref().ok_or_else(conflict)?;
        if conversion.generation != job.generation
            || conversion.disk_bytes != request.disk_bytes
            || conversion.archive
                != (Content {
                    sha256: archive.sha256.clone(),
                    size_bytes: archive.size_bytes,
                })
            || conversion.agent != inventory.agent
            || conversion.init != inventory.init
        {
            return Err(conflict());
        }
    }
    if let Some(manifest) = &value.manifest {
        manifest
            .validate_for(
                value.request.as_ref().ok_or_else(conflict)?,
                value.inventory.as_ref().ok_or_else(conflict)?,
            )
            .map_err(bad_output)?;
    }
    if let Some(disk) = &value.disk {
        let manifest = value.manifest.as_ref().ok_or_else(conflict)?;
        if disk.id != job.id
            || disk.installation_id != job.installation_id
            || disk.storage_binding != blobs.binding()
            || disk.generation.is_nil()
            || disk.sha256 != manifest.disk.sha256
            || disk.size_bytes != manifest.disk.size_bytes
        {
            return Err(conflict());
        }
    }
    if matches!(
        value.phase,
        Phase::Ready | Phase::Collecting | Phase::Collected
    ) && (value.host.is_none()
        || value.disk.is_none()
        || value.manifest.is_none()
        || (value.error.is_some() && value.phase != Phase::Collecting))
    {
        return Err(conflict());
    }
    Ok(value)
}

#[derive(Clone)]
pub struct ImagePreparer {
    docker: Docker,
    store: Store,
    blobs: BlobStore,
    sources: SourceExporter,
    allow_runc_development: bool,
    coordinator: Coordinator,
}
impl ImagePreparer {
    pub async fn connect(
        store: Store,
        blobs: BlobStore,
        allow_runc_development: bool,
    ) -> Result<Self, ApiError> {
        let sources = SourceExporter::connect(store.clone(), blobs.clone()).await?;
        let coordinator = sources.coordinator.clone();
        let docker = bounded(
            Docker::connect_with_socket_defaults()
                .map_err(|_| unknown())?
                .negotiate_version(),
        )
        .await?;
        Ok(Self {
            docker,
            store,
            blobs,
            sources,
            allow_runc_development,
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
            Ok(Err(e)) if missing(&e) => Ok(None),
            _ => Err(unknown()),
        }
    }
    fn owned(
        &self,
        actual: &ContainerInspectResponse,
        job: &ImageJob,
        request: &ImagePrepareRequest,
        builder: bool,
    ) -> Result<String, ApiError> {
        let part = if builder { "builder" } else { "seeder" };
        let id = actual
            .id
            .as_deref()
            .filter(|v| hex_id(v))
            .ok_or_else(conflict)?;
        let config = actual.config.as_ref().ok_or_else(conflict)?;
        let host = actual.host_config.as_ref().ok_or_else(conflict)?;
        let caps = host
            .cap_add
            .as_ref()
            .map(|v| {
                let mut v = v
                    .iter()
                    .map(|s| s.strip_prefix("CAP_").unwrap_or(s))
                    .collect::<Vec<_>>();
                v.sort();
                v
            })
            .unwrap_or_default();
        let expected_caps = if builder {
            vec!["CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID"]
        } else {
            vec![]
        };
        let runtime = if builder && request.runtime == BuilderRuntime::Runsc {
            "runsc"
        } else {
            "runc"
        };
        let expected_mounts = mounts(job, builder);
        let expected_command: Vec<String> = if builder {
            vec!["await-prepare".into()]
        } else {
            vec![]
        };
        let observed = actual.mounts.as_ref().ok_or_else(conflict)?;
        if actual.image.as_deref() != Some(&request.builder_image)
            || actual.name.as_deref() != Some(format!("/{}", resource(job, part)).as_str())
            || actual.restart_count.unwrap_or(0) != 0
            || config.user.as_deref() != Some("0:0")
            || config.tty == Some(true)
            || config.healthcheck.is_some()
            || config.entrypoint.as_deref()
                != Some(&[if builder {
                    "/usr/local/bin/goldenhoop-image-builder".into()
                } else {
                    "/goldenhoop-never-executed".into()
                }])
            || config.cmd.as_deref() != Some(expected_command.as_slice())
            || builder
                && (config.hostname.as_deref()
                    != Some(job.generation.simple().to_string().as_str())
                    || config.open_stdin != Some(true)
                    || config.stdin_once == Some(true))
            || !config.labels.as_ref().is_some_and(|actual| {
                labels(job, part)
                    .iter()
                    .all(|(k, v)| actual.get(k) == Some(v))
            })
            || host.runtime.as_deref() != Some(runtime)
            || host.network_mode.as_deref() != Some("none")
            || host.readonly_rootfs != Some(true)
            || host.privileged == Some(true)
            || host.pid_mode.as_deref().is_some_and(|v| !v.is_empty())
            || host.ipc_mode.as_deref() != Some("private")
            || host.uts_mode.as_deref().is_some_and(|v| !v.is_empty())
            || host.binds.as_ref().is_some_and(|v| !v.is_empty())
            || host.tmpfs.as_ref().is_some_and(|v| !v.is_empty())
            || host.devices.as_ref().is_some_and(|v| !v.is_empty())
            || caps != expected_caps
            || host.cap_drop.as_deref() != Some(&["ALL".into()])
            || !host.security_opt.as_ref().is_some_and(|v| {
                v.iter()
                    .any(|v| v == "no-new-privileges" || v == "no-new-privileges:true")
            })
            || observed.len() != expected_mounts.len()
            || !expected_mounts.iter().all(|mount| {
                observed.iter().any(|v| {
                    v.typ.as_deref() == Some("volume")
                        && v.name == mount.source
                        && v.destination == mount.target
                        && v.rw == Some(mount.read_only != Some(true))
                })
            })
            || !host.mounts.as_ref().is_some_and(|actual| {
                actual.len() == expected_mounts.len()
                    && expected_mounts.iter().all(|expected| {
                        actual.iter().any(|observed| same_mount(observed, expected))
                    })
            })
        {
            return Err(conflict());
        }
        let value: State = serde_json::from_value(job.payload.clone()).map_err(|_| conflict())?;
        if (if builder {
            value.builder_id
        } else {
            value.seeder_id
        })
        .as_deref()
        .is_some_and(|v| v != id)
        {
            return Err(conflict());
        }
        Ok(id.into())
    }
    async fn inspect_owned(
        &self,
        job: &ImageJob,
        request: &ImagePrepareRequest,
        builder: bool,
    ) -> Result<ContainerInspectResponse, ApiError> {
        let actual = self
            .lookup(&resource(job, if builder { "builder" } else { "seeder" }))
            .await?
            .ok_or_else(unknown)?;
        self.owned(&actual, job, request, builder)?;
        Ok(actual)
    }
    async fn volume_owned(&self, job: &ImageJob, part: &str) -> Result<(), ApiError> {
        let value = bounded(self.docker.inspect_volume(&resource(job, part))).await?;
        if value.name != resource(job, part)
            || value.driver != "local"
            || !value.options.is_empty()
            || !labels(job, part)
                .iter()
                .all(|(k, v)| value.labels.get(k) == Some(v))
        {
            return Err(conflict());
        }
        Ok(())
    }
    async fn create_container(
        &self,
        job: &ImageJob,
        request: &ImagePrepareRequest,
        builder: bool,
    ) -> Result<String, ApiError> {
        let part = if builder { "builder" } else { "seeder" };
        let maximum = limits();
        let value = bounded(self.docker.create_container(
            Some(CreateContainerOptions {
                name: Some(resource(job, part)),
                ..Default::default()
            }),
            ContainerCreateBody {
                image: Some(request.builder_image.clone()),
                hostname: Some(job.generation.simple().to_string()),
                user: Some("0:0".into()),
                entrypoint: Some(vec![if builder {
                    "/usr/local/bin/goldenhoop-image-builder".into()
                } else {
                    "/goldenhoop-never-executed".into()
                }]),
                cmd: Some(if builder {
                    vec!["await-prepare".into()]
                } else {
                    vec![]
                }),
                labels: Some(labels(job, part)),
                env: Some(vec![
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
                    "LANG=C.UTF-8".into(),
                    "HOME=/".into(),
                ]),
                open_stdin: Some(builder),
                attach_stdin: Some(builder),
                attach_stdout: Some(builder),
                attach_stderr: Some(builder),
                stdin_once: Some(false),
                tty: Some(false),
                host_config: Some(HostConfig {
                    runtime: Some(if builder && request.runtime == BuilderRuntime::Runsc {
                        "runsc".into()
                    } else {
                        "runc".into()
                    }),
                    network_mode: Some("none".into()),
                    readonly_rootfs: Some(true),
                    ipc_mode: Some("private".into()),
                    cap_drop: Some(vec!["ALL".into()]),
                    cap_add: Some(if builder {
                        vec![
                            "CHOWN".into(),
                            "DAC_OVERRIDE".into(),
                            "FOWNER".into(),
                            "FSETID".into(),
                        ]
                    } else {
                        vec![]
                    }),
                    security_opt: Some(vec!["no-new-privileges:true".into()]),
                    mounts: Some(mounts(job, builder)),
                    memory: Some(maximum.memory_max as i64),
                    memory_swap: Some(maximum.memory_max as i64),
                    pids_limit: Some(maximum.pids_max as i64),
                    cpu_quota: Some(maximum.cpu_quota as i64),
                    cpu_period: Some(maximum.cpu_period as i64),
                    restart_policy: Some(RestartPolicy {
                        name: Some(RestartPolicyNameEnum::NO),
                        maximum_retry_count: Some(0),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ))
        .await?;
        if !hex_id(&value.id) {
            return Err(conflict());
        }
        Ok(value.id)
    }
    async fn remove_container(
        &self,
        job: &ImageJob,
        request: &ImagePrepareRequest,
        builder: bool,
    ) -> Result<(), ApiError> {
        let name = resource(job, if builder { "builder" } else { "seeder" });
        if let Some(actual) = self.lookup(&name).await? {
            let id = self.owned(&actual, job, request, builder)?;
            match bounded(self.docker.remove_container(
                &id,
                Some(RemoveContainerOptions {
                    force: true,
                    v: false,
                    link: false,
                }),
            ))
            .await
            {
                Ok(()) => (),
                Err(e) => {
                    if self.lookup(&id).await?.is_some() {
                        return Err(e);
                    }
                }
            }
            if self.lookup(&id).await?.is_some() {
                return Err(unknown());
            }
        }
        if self.lookup(&name).await?.is_some() {
            return Err(unknown());
        }
        let recorded: State =
            serde_json::from_value(job.payload.clone()).map_err(|_| conflict())?;
        let id = if builder {
            recorded.builder_id
        } else {
            recorded.seeder_id
        };
        if let Some(id) = id
            && self.lookup(&id).await?.is_some()
        {
            return Err(unknown());
        }
        Ok(())
    }
    async fn providers_collected(
        &self,
        job: &ImageJob,
        request: &ImagePrepareRequest,
        value: &State,
    ) -> Result<(), ApiError> {
        self.remove_container(job, request, true).await?;
        self.remove_container(job, request, false).await?;
        if let Some(host) = &value.host {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                if host
                    .collected(value.builder_id.as_deref().ok_or_else(conflict)?)
                    .map_err(bad_output)?
                {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(unknown());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        } else if value.builder_id.is_some()
            && !matches!(
                value.phase,
                Phase::BuilderDispatched | Phase::BuilderObserved
            )
        {
            return Err(unknown());
        }
        for part in ["input", "output"] {
            match tokio::time::timeout(
                Duration::from_secs(15),
                self.docker.inspect_volume(&resource(job, part)),
            )
            .await
            {
                Ok(Ok(_)) => {
                    self.volume_owned(job, part).await?;
                    bounded(self.docker.remove_volume(
                        &resource(job, part),
                        Some(RemoveVolumeOptions { force: false }),
                    ))
                    .await?;
                }
                Ok(Err(e)) if missing(&e) => (),
                _ => return Err(unknown()),
            }
            match tokio::time::timeout(
                Duration::from_secs(15),
                self.docker.inspect_volume(&resource(job, part)),
            )
            .await
            {
                Ok(Err(e)) if missing(&e) => (),
                _ => return Err(unknown()),
            }
        }
        Ok(())
    }
    fn report(job: &ImageJob, value: &State) -> ImagePrepareReport {
        ImagePrepareReport {
            id: job.id,
            generation: job.generation,
            phase: serde_json::to_value(value.phase)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| "invalid".into()),
            image_ready: value.phase == Phase::Ready && value.error.is_none(),
            provider_cleanup: if matches!(
                value.phase,
                Phase::Ready | Phase::Collected | Phase::FailedCollected
            ) {
                "complete"
            } else {
                "unknown"
            }
            .into(),
            manifest: value.manifest.clone(),
            disk: value.disk.clone(),
            host_observation: value
                .host
                .as_ref()
                .and_then(|v| serde_json::to_value(v).ok()),
            converter_observation: value.converter_observation.clone(),
            recovery_observation: value.recovery_observation.clone(),
            error: value.error.clone(),
        }
    }
    async fn absent(&self, job: &ImageJob, value: &State) -> Result<(), ApiError> {
        for part in ["builder", "seeder"] {
            if self.lookup(&resource(job, part)).await?.is_some() {
                return Err(unknown());
            }
        }
        for id in [value.builder_id.as_deref(), value.seeder_id.as_deref()]
            .into_iter()
            .flatten()
        {
            if self.lookup(id).await?.is_some() {
                return Err(unknown());
            }
        }
        for part in ["input", "output"] {
            match tokio::time::timeout(
                Duration::from_secs(15),
                self.docker.inspect_volume(&resource(job, part)),
            )
            .await
            {
                Ok(Err(e)) if missing(&e) => (),
                _ => return Err(unknown()),
            }
        }
        if let Some(host) = &value.host
            && !host
                .collected(value.builder_id.as_deref().ok_or_else(conflict)?)
                .map_err(bad_output)?
        {
            return Err(unknown());
        }
        Ok(())
    }
    async fn failure_observation(
        &self,
        job: &ImageJob,
        request: &ImagePrepareRequest,
    ) -> Result<Value, ApiError> {
        use std::io::Read;
        let actual = self.inspect_owned(job, request, true).await?;
        let id = actual.id.as_deref().ok_or_else(conflict)?;
        let pid = actual
            .state
            .as_ref()
            .and_then(|s| s.pid)
            .filter(|pid| *pid > 1 && *pid <= i64::from(i32::MAX));
        let process = pid.map(|pid| {
            let read = |name: &str| {
                std::fs::File::open(format!("/proc/{pid}/{name}"))
                    .ok()
                    .and_then(|file| {
                        let mut bytes = Vec::new();
                        file.take(4097).read_to_end(&mut bytes).ok()?;
                        if bytes.len() > 4096 {
                            None
                        } else {
                            Some(String::from_utf8_lossy(&bytes).into_owned())
                        }
                    })
            };
            json!({"pid":pid,"stat":read("stat"),"cgroup":read("cgroup")})
        });
        let logs = async {
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            let mut body = self.docker.logs(
                id,
                Some(LogsOptions {
                    stdout: true,
                    stderr: true,
                    follow: false,
                    tail: "all".into(),
                    ..Default::default()
                }),
            );
            while let Some(item) = body.next().await {
                let (target, message) = match item.map_err(|_| unknown())? {
                    LogOutput::StdOut { message } => (&mut stdout, message),
                    LogOutput::StdErr { message } => (&mut stderr, message),
                    _ => return Err(conflict()),
                };
                if target.len() + message.len() > 65536 {
                    return Err(bad_output("failure log limit"));
                }
                target.extend_from_slice(&message);
            }
            Ok::<_, ApiError>(
                json!({"capture":"complete","stdout_bytes":stdout.len(),"stdout_sha256":format!("{:x}",Sha256::digest(&stdout)),
                "stderr_bytes":stderr.len(),"stderr_sha256":format!("{:x}",Sha256::digest(&stderr)),
                "stdout_tail":String::from_utf8_lossy(&stdout[stdout.len().saturating_sub(2048)..]),
                "stderr_tail":String::from_utf8_lossy(&stderr[stderr.len().saturating_sub(4096)..])}),
            )
        };
        let logs = match tokio::time::timeout(Duration::from_secs(5), logs).await {
            Ok(Ok(value)) => value,
            _ => json!({"capture":"unconfirmed"}),
        };
        let observation = json!({"state":actual.state,"process":process,"logs":logs});
        // JSON escaping can expand bounded raw output. Diagnostics must not
        // overflow the durable job and prevent its subsequent scoped cleanup.
        if serde_json::to_vec(&observation).is_ok_and(|bytes| bytes.len() <= 16 * 1024) {
            Ok(observation)
        } else {
            Ok(
                json!({"capture":"unconfirmed","reason":"encoded failure observation exceeds limit"}),
            )
        }
    }
    async fn admission(&self, request: &ImagePrepareRequest) -> Result<(), ApiError> {
        if request.runtime == BuilderRuntime::RuncDevelopment && !self.allow_runc_development {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "runc conversion requires explicit development opt-in",
            ));
        }
        let info = bounded(self.docker.info()).await?;
        let runtime = if request.runtime == BuilderRuntime::Runsc {
            "runsc"
        } else {
            "runc"
        };
        if !info
            .runtimes
            .as_ref()
            .is_some_and(|v| v.contains_key(runtime))
        {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "the requested isolated builder runtime is unavailable",
            ));
        }
        let image = bounded(self.docker.inspect_image(&request.builder_image)).await?;
        let config = image.config.as_ref().ok_or_else(conflict)?;
        if image.id.as_deref() != Some(&request.builder_image)
            || image.os.as_deref() != Some("linux")
            || image.architecture.as_deref() != Some("amd64")
            || config.healthcheck.is_some()
            || config.volumes.as_ref().is_some_and(|v| !v.is_empty())
            || config.env.as_ref().is_some_and(|v| {
                v.iter().any(|v| {
                    !v.split_once('=').is_some_and(|(k, _)| {
                        ["PATH", "LANG", "HOME", "HOSTNAME", "TERM", "TZ"].contains(&k)
                    })
                })
            })
        {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "converter must be an administrator-trusted pinned linux/amd64 image without injected environment, health checks or anonymous volumes",
            ));
        }
        Ok(())
    }
    pub async fn prepare(
        &self,
        request: ImagePrepareRequest,
    ) -> Result<ImagePrepareReport, ApiError> {
        request.validate()?;
        let lease = self.coordinator.acquire(request.id)?;
        let initial = State {
            format: 1,
            phase: Phase::Reserved,
            source: ExportRequest {
                id: Uuid::new_v4(),
                generation: Uuid::new_v4(),
                source_image: request.source_image.clone(),
            },
            archive: None,
            inventory: None,
            request: None,
            nonce: Uuid::new_v4(),
            seeder_id: None,
            builder_id: None,
            host: None,
            converter_observation: None,
            manifest: None,
            disk: None,
            error: None,
            coordination: Some(lease.stamp.clone()),
            recovery_observation: None,
            producer: Some(Producer::current()?),
        };
        let immutable = json!({"format":1,"role":ROLE,"request":request,"storage_binding":self.blobs.binding()});
        let mut job = self
            .store
            .reserve_image_job(
                request.id,
                request.generation,
                &immutable,
                &serde_json::to_value(initial).map_err(|_| conflict())?,
            )
            .await?;
        let mut value = state(&job, &request, &self.blobs)?;
        lease.check(
            value.coordination.as_ref(),
            matches!(
                value.phase,
                Phase::Ready | Phase::Collected | Phase::FailedCollected
            ),
        )?;
        if value.phase == Phase::Ready {
            self.absent(&job, &value).await?;
            self.blobs
                .download_large(value.disk.as_ref().ok_or_else(conflict)?, tokio::io::sink())
                .await?;
            return Ok(Self::report(&job, &value));
        }
        if matches!(value.phase, Phase::Collected | Phase::FailedCollected) {
            return Ok(Self::report(&job, &value));
        }
        if value.phase != Phase::Reserved {
            return Err(unknown());
        }
        value.producer = Some(Producer::current()?);
        if let Err(error) = self.admission(&request).await {
            value.error = Some(error);
            phase(&self.store, &mut job, &mut value, Phase::FailedCollected).await?;
            return Ok(Self::report(&job, &value));
        }
        let result = async {
            phase(&self.store, &mut job, &mut value, Phase::SourceDispatched).await?;
            let source = self.sources.export(value.source.clone()).await?;
            if !source.archive_ready
                || source.provider_cleanup != "complete"
                || source.error.is_some()
            {
                if source.provider_cleanup == "complete" && source.archive.is_none() {
                    value.error = Some(source.error.unwrap_or_else(unknown));
                    phase(&self.store, &mut job, &mut value, Phase::FailedCollected).await?;
                    return Ok(());
                }
                return Err(source.error.unwrap_or_else(unknown));
            }
            value.archive = Some(source.archive.ok_or_else(conflict)?);
            phase(&self.store, &mut job, &mut value, Phase::SourceReady).await?;
            for part in ["input", "output"] {
                match tokio::time::timeout(
                    Duration::from_secs(15),
                    self.docker.inspect_volume(&resource(&job, part)),
                )
                .await
                {
                    Ok(Err(e)) if missing(&e) => (),
                    _ => return Err(conflict()),
                }
            }
            phase(&self.store, &mut job, &mut value, Phase::VolumesDispatched).await?;
            for part in ["input", "output"] {
                bounded(self.docker.create_volume(VolumeCreateRequest {
                    name: Some(resource(&job, part)),
                    driver: Some("local".into()),
                    labels: Some(labels(&job, part)),
                    ..Default::default()
                }))
                .await?;
                self.volume_owned(&job, part).await?;
            }
            phase(&self.store, &mut job, &mut value, Phase::VolumesReady).await?;
            phase(&self.store, &mut job, &mut value, Phase::SeederDispatched).await?;
            value.seeder_id = Some(self.create_container(&job, &request, false).await?);
            phase(&self.store, &mut job, &mut value, Phase::SeederObserved).await?;
            let seeder = self.inspect_owned(&job, &request, false).await?;
            let seeder_state = seeder.state.as_ref().ok_or_else(conflict)?;
            if seeder_state.pid != Some(0)
                || seeder_state.running == Some(true)
                || seeder_state.status != Some(ContainerStateStatusEnum::CREATED)
            {
                return Err(conflict());
            }
            let id = value.seeder_id.as_deref().ok_or_else(conflict)?.to_owned();
            let inventory: BuilderInventory = serde_json::from_slice(
                &tokio::time::timeout(Duration::from_secs(30), async {
                    FileStream::open(
                        &self.docker,
                        &id,
                        "/opt/goldenhoop/inventory.json",
                        "inventory.json",
                        65536,
                    )
                    .await?
                    .small()
                    .await
                })
                .await
                .map_err(|_| unknown())?
                .map_err(bad_output)?,
            )
            .map_err(bad_output)?;
            inventory.validate().map_err(bad_output)?;
            value.request = Some(PrepareRequest {
                generation: job.generation,
                archive: Content {
                    sha256: value.archive.as_ref().ok_or_else(conflict)?.sha256.clone(),
                    size_bytes: value.archive.as_ref().ok_or_else(conflict)?.size_bytes,
                },
                agent: inventory.agent.clone(),
                init: inventory.init.clone(),
                disk_bytes: request.disk_bytes,
            });
            value.inventory = Some(inventory);
            phase(
                &self.store,
                &mut job,
                &mut value,
                Phase::InputUploadDispatched,
            )
            .await?;
            let (output, input) = tokio::io::duplex(128 * 1024);
            let upload = self.docker.upload_to_container(
                &id,
                Some(UploadToContainerOptions {
                    path: "/input".into(),
                    no_overwrite_dir_non_dir: Some("true".into()),
                    copy_uidgid: Some("true".into()),
                }),
                bollard::body_try_stream(ReaderStream::new(input)),
            );
            let produce = transfer::input(
                output,
                &self.blobs,
                value.archive.as_ref().ok_or_else(conflict)?,
                value.request.as_ref().ok_or_else(conflict)?,
            );
            let (uploaded, produced) = tokio::time::timeout(Duration::from_secs(300), async {
                tokio::join!(upload, produce)
            })
            .await
            .map_err(|_| unknown())?;
            uploaded.map_err(|_| unknown())?;
            produced?;
            phase(&self.store, &mut job, &mut value, Phase::InputReady).await?;
            let actual = self.inspect_owned(&job, &request, false).await?;
            if actual.state.as_ref().is_none_or(|s| {
                s.pid != Some(0)
                    || s.running == Some(true)
                    || s.status != Some(ContainerStateStatusEnum::CREATED)
            }) {
                return Err(conflict());
            }
            self.remove_container(&job, &request, false).await?;
            phase(&self.store, &mut job, &mut value, Phase::SeederRemoved).await?;
            phase(&self.store, &mut job, &mut value, Phase::BuilderDispatched).await?;
            value.builder_id = Some(self.create_container(&job, &request, true).await?);
            phase(&self.store, &mut job, &mut value, Phase::BuilderObserved).await?;
            self.inspect_owned(&job, &request, true).await?;
            let id = value.builder_id.as_deref().ok_or_else(conflict)?.to_owned();
            let mut attached = bounded(self.docker.attach_container(
                &id,
                Some(AttachContainerOptions {
                    stdin: true,
                    stdout: true,
                    stderr: true,
                    stream: true,
                    ..Default::default()
                }),
            ))
            .await?;
            phase(&self.store, &mut job, &mut value, Phase::StartDispatched).await?;
            bounded(self.docker.start_container(&id, None)).await?;
            let actual = self.inspect_owned(&job, &request, true).await?;
            let actual_state = actual.state.as_ref().ok_or_else(conflict)?;
            if actual_state.running != Some(true)
                || actual_state.restarting == Some(true)
                || actual_state.oom_killed == Some(true)
            {
                return Err(unknown());
            }
            let pid =
                u32::try_from(actual_state.pid.ok_or_else(conflict)?).map_err(|_| conflict())?;
            let guard = HostGuard::observe(&id, pid, &limits()).map_err(bad_output)?;
            value.host = Some(guard.observation.clone());
            phase(&self.store, &mut job, &mut value, Phase::RunningObserved).await?;
            let permit = HostPermit {
                format: 1,
                installation_id: job.installation_id,
                job_id: job.id,
                generation: job.generation,
                nonce: value.nonce,
                builder_image: request.builder_image.clone(),
                request_sha256: value
                    .request
                    .as_ref()
                    .ok_or_else(conflict)?
                    .fingerprint()
                    .map_err(bad_output)?,
                runtime: request.runtime,
                limits: guard.observation.limits.clone(),
            };
            let mut bytes = serde_json::to_vec(&permit).map_err(|_| conflict())?;
            bytes.push(b'\n');
            phase(
                &self.store,
                &mut job,
                &mut value,
                Phase::AuthorizationDispatched,
            )
            .await?;
            guard.still_live().map_err(bad_output)?;
            tokio::time::timeout(Duration::from_secs(5), async {
                attached.input.write_all(&bytes).await?;
                // Moby closes attached stdout/stderr when stdin reaches EOF
                // with StdinOnce=false. The newline delimits this one permit;
                // retain the input half until actual exit and output drainage.
                attached.input.flush().await
            })
            .await
            .map_err(|_| unknown())?
            .map_err(bad_output)?;
            let output = async {
                let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
                while let Some(item) = attached.output.next().await {
                    let (target, message) = match item.map_err(|_| unknown())? {
                        LogOutput::StdOut { message } => (&mut stdout, message),
                        LogOutput::StdErr { message } => (&mut stderr, message),
                        _ => return Err(conflict()),
                    };
                    if target.len() + message.len() > 65536 {
                        return Err(bad_output("converter output limit"));
                    }
                    target.extend_from_slice(&message);
                }
                Ok::<_, ApiError>((stdout, stderr))
            };
            let wait = async {
                self.docker
                    .wait_container(
                        &id,
                        Some(WaitContainerOptions {
                            condition: "not-running".into(),
                        }),
                    )
                    .try_next()
                    .await
                    .map_err(|_| unknown())?
                    .ok_or_else(unknown)
            };
            let (exit, (stdout, stderr)) = tokio::time::timeout(Duration::from_secs(660), async {
                tokio::try_join!(wait, output)
            })
            .await
            .map_err(|_| unknown())??;
            let actual = self.inspect_owned(&job, &request, true).await?;
            value.converter_observation=Some(json!({"wait_status_code":exit.status_code,"state":actual.state,
                "stdout_bytes":stdout.len(),"stdout_sha256":format!("{:x}",Sha256::digest(&stdout)),
                "stderr_bytes":stderr.len(),"stderr_sha256":format!("{:x}",Sha256::digest(&stderr)),
                "stderr_tail":String::from_utf8_lossy(&stderr[stderr.len().saturating_sub(2048)..])}));
            phase(&self.store, &mut job, &mut value, Phase::BuilderExited).await?;
            if exit.status_code != 0 { return Err(bad_output("converter exit; inspect the recorded bounded stderr")); }
            if actual.state.as_ref().is_none_or(|s| {
                s.running == Some(true)
                    || s.restarting == Some(true)
                    || s.oom_killed == Some(true)
                    || s.exit_code != Some(0)
                    || s.status != Some(ContainerStateStatusEnum::EXITED)
            }) {
                return Err(unknown());
            }
            let report: PrepareReport = serde_json::from_slice(&stdout).map_err(bad_output)?;
            if !report.passed
                || !report.staging_absent
                || !report.tools_collected
                || report.error.is_some()
            {
                return Err(bad_output("converter report"));
            }
            let manifest = report.manifest.ok_or_else(conflict)?;
            manifest
                .validate_for(
                    value.request.as_ref().ok_or_else(conflict)?,
                    value.inventory.as_ref().ok_or_else(conflict)?,
                )
                .map_err(bad_output)?;
            let output_root = format!("/output/{}", job.generation);
            let bytes = tokio::time::timeout(Duration::from_secs(30), async {
                FileStream::open(
                    &self.docker,
                    &id,
                    &format!("{output_root}/manifest.json"),
                    "manifest.json",
                    65536,
                )
                .await?
                .small()
                .await
            })
            .await
            .map_err(|_| unknown())?
            .map_err(bad_output)?;
            let recorded: PreparedImage = serde_json::from_slice(&bytes).map_err(bad_output)?;
            if serde_json::to_value(&recorded).map_err(|_| conflict())?
                != serde_json::to_value(&manifest).map_err(|_| conflict())?
            {
                return Err(conflict());
            }
            value.manifest = Some(manifest.clone());
            phase(&self.store, &mut job, &mut value, Phase::OutputVerified).await?;
            value.disk = Some(self.blobs.large_reference(
                job.id,
                manifest.disk.sha256.clone(),
                manifest.disk.size_bytes,
            )?);
            phase(
                &self.store,
                &mut job,
                &mut value,
                Phase::DiskUploadDispatched,
            )
            .await?;
            tokio::time::timeout(Duration::from_secs(900), async {
                let mut stream = FileStream::open(
                    &self.docker,
                    &id,
                    &format!("{output_root}/rootfs.ext4"),
                    "rootfs.ext4",
                    request.disk_bytes,
                )
                .await
                .map_err(bad_output)?;
                if stream.size != request.disk_bytes {
                    return Err(conflict());
                }
                self.blobs
                    .put_large(
                        value.disk.as_ref().ok_or_else(conflict)?,
                        stream.reader.as_mut().take(stream.size),
                    )
                    .await?;
                stream.finish().await.map_err(bad_output)
            })
            .await
            .map_err(|_| unknown())??;
            phase(&self.store, &mut job, &mut value, Phase::DiskStored).await?;
            phase(&self.store, &mut job, &mut value, Phase::ProviderCollecting).await?;
            self.providers_collected(&job, &request, &value).await?;
            phase(&self.store, &mut job, &mut value, Phase::ProvidersCollected).await?;
            phase(&self.store, &mut job, &mut value, Phase::SourceCollecting).await?;
            let collected = self.sources.collect(value.source.id).await?;
            if collected.archive_ready
                || collected.provider_cleanup != "complete"
                || collected.error.is_some()
            {
                return Err(unknown());
            }
            self.absent(&job, &value).await?;
            self.blobs
                .download_large(value.disk.as_ref().ok_or_else(conflict)?, tokio::io::sink())
                .await?;
            phase(&self.store, &mut job, &mut value, Phase::Ready).await?;
            Ok::<_, ApiError>(())
        }
        .await;
        if let Err(error) = result {
            if value.phase == Phase::Ready {
                value.phase = Phase::SourceCollecting;
            }
            value.error = Some(error);
            save(&self.store, &mut job, &value).await?;
            if value.builder_id.is_some() {
                let observation = match self.failure_observation(&job, &request).await {
                    Ok(value) => value,
                    Err(_) => json!({"capture":"unconfirmed"}),
                };
                value.converter_observation = Some(
                    json!({"before_failure":value.converter_observation,"before_collection":observation}),
                );
                save(&self.store, &mut job, &value).await?;
            }
            // Fence known compute owners on failure. In-flight archive upload
            // acknowledgement and disk writes remain Unknown; never declare
            // their volumes/storage collected merely because a client stopped.
            let input_unknown = value.phase == Phase::InputUploadDispatched;
            let disk_unknown = value.phase == Phase::DiskUploadDispatched;
            let no_source = matches!(value.phase, Phase::Reserved | Phase::SourceDispatched);
            let _ = self.remove_container(&job, &request, true).await;
            let _ = self.remove_container(&job, &request, false).await;
            if !input_unknown
                && !no_source
                && self
                    .providers_collected(&job, &request, &value)
                    .await
                    .is_ok()
                && !disk_unknown
            {
                let source = self.sources.collect(value.source.id).await;
                let disk = if let Some(reference) = &value.disk {
                    self.blobs.collect_large(reference).await
                } else {
                    Ok(())
                };
                if source.is_ok_and(|v| v.provider_cleanup == "complete" && v.error.is_none())
                    && disk.is_ok()
                {
                    phase(&self.store, &mut job, &mut value, Phase::FailedCollected).await?;
                }
            }
        }
        Ok(Self::report(&job, &value))
    }
    /// Recover acknowledged converter output and its exact immutable storage
    /// reference. Earlier uncertain create/start/permit phases are not replayed.
    pub async fn reconcile(&self, id: Uuid) -> Result<ImagePrepareReport, ApiError> {
        let lease = self.coordinator.acquire(id)?;
        let mut job = self.store.image_job(id).await?;
        let request: ImagePrepareRequest =
            serde_json::from_value(job.request.get("request").cloned().ok_or_else(conflict)?)
                .map_err(|_| conflict())?;
        request.validate()?;
        if request.id != job.id
            || request.generation != job.generation
            || job.request.get("role").and_then(Value::as_str) != Some(ROLE)
        {
            return Err(conflict());
        }
        let mut value = state(&job, &request, &self.blobs)?;
        lease.check(
            value.coordination.as_ref(),
            matches!(
                value.phase,
                Phase::Ready | Phase::Collected | Phase::FailedCollected
            ),
        )?;
        if matches!(value.phase, Phase::Collected | Phase::FailedCollected) {
            return Ok(Self::report(&job, &value));
        }
        if value.phase == Phase::Ready {
            self.absent(&job, &value).await?;
            self.blobs
                .download_large(value.disk.as_ref().ok_or_else(conflict)?, tokio::io::sink())
                .await?;
            return Ok(Self::report(&job, &value));
        }
        if !matches!(
            value.phase,
            Phase::OutputVerified
                | Phase::DiskUploadDispatched
                | Phase::DiskStored
                | Phase::ProviderCollecting
                | Phase::ProvidersCollected
                | Phase::SourceCollecting
                | Phase::Collecting
        ) || value.host.is_none()
            || value.manifest.is_none()
            || value.builder_id.is_none()
        {
            return Err(unknown());
        }
        crate::coordination::recovery_storage(&self.blobs)?;
        value
            .producer
            .as_ref()
            .ok_or_else(unknown)?
            .require_gone()?;
        value.producer = Some(Producer::current()?);
        if value.recovery_observation.is_none() {
            value.recovery_observation = Some(
                json!({"from_phase":value.phase,"from_revision":job.revision,
                "original_error":value.error,"producer_fence":lease.stamp,"outcome":"unconfirmed"}),
            );
        }
        save(&self.store, &mut job, &value).await?;
        let operation = async {
            if value.phase == Phase::Collecting {
                self.absent(&job, &value).await?;
                self.blobs
                    .collect_large(value.disk.as_ref().ok_or_else(conflict)?)
                    .await?;
                value.error = None;
                value.recovery_observation.as_mut().ok_or_else(conflict)?["outcome"] =
                    json!("collected");
                return phase(&self.store, &mut job, &mut value, Phase::Collected).await;
            }
            if matches!(
                value.phase,
                Phase::OutputVerified | Phase::DiskUploadDispatched
            ) {
                if value.disk.is_none() {
                    if value.phase != Phase::OutputVerified {
                        return Err(conflict());
                    }
                    let manifest = value.manifest.as_ref().ok_or_else(conflict)?;
                    value.disk = Some(self.blobs.large_reference(
                        job.id,
                        manifest.disk.sha256.clone(),
                        manifest.disk.size_bytes,
                    )?);
                }
                phase(
                    &self.store,
                    &mut job,
                    &mut value,
                    Phase::DiskUploadDispatched,
                )
                .await?;
                let reference = value.disk.as_ref().ok_or_else(conflict)?;
                if self
                    .blobs
                    .download_large(reference, tokio::io::sink())
                    .await
                    .is_err()
                {
                    let actual = self.inspect_owned(&job, &request, true).await?;
                    if actual.state.as_ref().is_none_or(|s| {
                        s.status != Some(ContainerStateStatusEnum::EXITED)
                            || s.running != Some(false)
                            || s.oom_killed != Some(false)
                            || s.exit_code != Some(0)
                    }) {
                        return Err(unknown());
                    }
                    let cid = value.builder_id.as_deref().ok_or_else(conflict)?;
                    let output = format!("/output/{}", job.generation);
                    let bytes = tokio::time::timeout(Duration::from_secs(30), async {
                        FileStream::open(
                            &self.docker,
                            cid,
                            &format!("{output}/manifest.json"),
                            "manifest.json",
                            65536,
                        )
                        .await?
                        .small()
                        .await
                    })
                    .await
                    .map_err(|_| unknown())?
                    .map_err(bad_output)?;
                    let observed: PreparedImage =
                        serde_json::from_slice(&bytes).map_err(bad_output)?;
                    if serde_json::to_value(observed).map_err(|_| conflict())?
                        != serde_json::to_value(value.manifest.as_ref().ok_or_else(conflict)?)
                            .map_err(|_| conflict())?
                    {
                        return Err(conflict());
                    }
                    tokio::time::timeout(Duration::from_secs(900), async {
                        let mut stream = FileStream::open(
                            &self.docker,
                            cid,
                            &format!("{output}/rootfs.ext4"),
                            "rootfs.ext4",
                            request.disk_bytes,
                        )
                        .await
                        .map_err(bad_output)?;
                        if stream.size != request.disk_bytes {
                            return Err(conflict());
                        }
                        self.blobs
                            .put_large(reference, stream.reader.as_mut().take(stream.size))
                            .await?;
                        stream.finish().await.map_err(bad_output)
                    })
                    .await
                    .map_err(|_| unknown())??;
                }
                self.blobs
                    .download_large(reference, tokio::io::sink())
                    .await?;
                value.recovery_observation.as_mut().ok_or_else(conflict)?["disk_commit_readback"] =
                    json!(reference);
                phase(&self.store, &mut job, &mut value, Phase::DiskStored).await?;
            }
            self.blobs
                .download_large(value.disk.as_ref().ok_or_else(conflict)?, tokio::io::sink())
                .await?;
            phase(&self.store, &mut job, &mut value, Phase::ProviderCollecting).await?;
            self.providers_collected(&job, &request, &value).await?;
            phase(&self.store, &mut job, &mut value, Phase::ProvidersCollected).await?;
            phase(&self.store, &mut job, &mut value, Phase::SourceCollecting).await?;
            let source = self.sources.collect(value.source.id).await?;
            if source.archive_ready
                || source.provider_cleanup != "complete"
                || source.error.is_some()
            {
                return Err(unknown());
            }
            self.absent(&job, &value).await?;
            self.blobs
                .download_large(value.disk.as_ref().ok_or_else(conflict)?, tokio::io::sink())
                .await?;
            value.error = None;
            value.recovery_observation.as_mut().ok_or_else(conflict)?["outcome"] = json!("ready");
            phase(&self.store, &mut job, &mut value, Phase::Ready).await
        }
        .await;
        if let Err(error) = operation {
            if value.phase == Phase::Ready {
                value.phase = Phase::SourceCollecting;
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

    /// Private maintenance after the original producer is fenced. Only fully
    /// acknowledged pre-input phases can use this path: it never claims an
    /// uncertain upload/start/create has settled merely because names are gone.
    pub async fn abort_before_input(&self, id: Uuid) -> Result<ImagePrepareReport, ApiError> {
        let lease = self.coordinator.acquire(id)?;
        let mut job = self.store.image_job(id).await?;
        let request: ImagePrepareRequest =
            serde_json::from_value(job.request.get("request").cloned().ok_or_else(conflict)?)
                .map_err(|_| conflict())?;
        request.validate()?;
        if request.id != job.id
            || request.generation != job.generation
            || job.request.get("role").and_then(Value::as_str) != Some(ROLE)
        {
            return Err(conflict());
        }
        let mut value = state(&job, &request, &self.blobs)?;
        lease.check(
            value.coordination.as_ref(),
            value.phase == Phase::FailedCollected,
        )?;
        if value.phase == Phase::FailedCollected {
            return Ok(Self::report(&job, &value));
        }
        value
            .producer
            .as_ref()
            .ok_or_else(unknown)?
            .require_gone()?;
        if !matches!(
            value.phase,
            Phase::SourceReady
                | Phase::VolumesReady
                | Phase::SeederObserved
                | Phase::AbortingBeforeInput
        ) || value.error.is_none()
            || value.archive.is_none()
            || value.inventory.is_some()
            || value.request.is_some()
            || value.builder_id.is_some()
            || value.host.is_some()
            || value.disk.is_some()
            || value.manifest.is_some()
        {
            return Err(unknown());
        }
        if let Some(actual) = self.lookup(&resource(&job, "seeder")).await? {
            self.owned(&actual, &job, &request, false)?;
            if actual.state.as_ref().is_none_or(|s| {
                s.status != Some(ContainerStateStatusEnum::CREATED)
                    || s.running == Some(true)
                    || s.pid != Some(0)
            }) {
                return Err(unknown());
            }
        }
        value.producer = Some(Producer::current()?);
        phase(
            &self.store,
            &mut job,
            &mut value,
            Phase::AbortingBeforeInput,
        )
        .await?;
        self.providers_collected(&job, &request, &value).await?;
        let source = self.sources.collect(value.source.id).await?;
        if source.archive_ready || source.provider_cleanup != "complete" || source.error.is_some() {
            return Err(unknown());
        }
        self.absent(&job, &value).await?;
        phase(&self.store, &mut job, &mut value, Phase::FailedCollected).await?;
        Ok(Self::report(&job, &value))
    }

    /// Private maintenance only, after all consumers of this immutable disk are
    /// fenced. Uncertain producers cannot be collected by this stable path.
    pub async fn collect(&self, id: Uuid) -> Result<ImagePrepareReport, ApiError> {
        let lease = self.coordinator.acquire(id)?;
        let mut job = self.store.image_job(id).await?;
        let request: ImagePrepareRequest =
            serde_json::from_value(job.request.get("request").cloned().ok_or_else(conflict)?)
                .map_err(|_| conflict())?;
        request.validate()?;
        if request.id != job.id
            || request.generation != job.generation
            || job.request.get("role").and_then(Value::as_str) != Some(ROLE)
        {
            return Err(conflict());
        }
        let mut value = state(&job, &request, &self.blobs)?;
        lease.check(
            value.coordination.as_ref(),
            matches!(
                value.phase,
                Phase::Ready | Phase::Collected | Phase::FailedCollected
            ),
        )?;
        if matches!(value.phase, Phase::Collected | Phase::FailedCollected) {
            return Ok(Self::report(&job, &value));
        }
        if !matches!(value.phase, Phase::Ready | Phase::Collecting) {
            return Err(unknown());
        }
        if value.phase == Phase::Collecting {
            crate::coordination::recovery_storage(&self.blobs)?;
            value
                .producer
                .as_ref()
                .ok_or_else(unknown)?
                .require_gone()?;
        }
        self.absent(&job, &value).await?;
        value.coordination = Some(lease.stamp.clone());
        value.producer = Some(Producer::current()?);
        phase(&self.store, &mut job, &mut value, Phase::Collecting).await?;
        self.blobs
            .collect_large(value.disk.as_ref().ok_or_else(conflict)?)
            .await?;
        value.error = None;
        phase(&self.store, &mut job, &mut value, Phase::Collected).await?;
        Ok(Self::report(&job, &value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn omitted_false_mount_flag_is_equivalent_but_changed_access_source_and_subpath_are_not() {
        let expected = Mount {
            typ: Some(MountType::VOLUME),
            source: Some("owned-volume".into()),
            target: Some("/output".into()),
            read_only: Some(false),
            volume_options: Some(MountVolumeOptions {
                no_copy: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let omitted:Mount=serde_json::from_value(json!({"Type":"volume","Source":"owned-volume","Target":"/output","VolumeOptions":{"NoCopy":true}})).unwrap();
        assert!(same_mount(&omitted, &expected));
        let mut changed = omitted.clone();
        changed.read_only = Some(true);
        assert!(!same_mount(&changed, &expected));
        let mut changed = omitted.clone();
        changed.source = Some("foreign-volume".into());
        assert!(!same_mount(&changed, &expected));
        let mut changed = omitted;
        changed.volume_options.as_mut().unwrap().subpath = Some("different-tree".into());
        assert!(!same_mount(&changed, &expected));
    }
}
