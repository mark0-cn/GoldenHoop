//! Owned Docker resources and an out-of-workload agent bridge.
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use bollard::{Docker, container::LogOutput, errors::Error as DockerError, exec::StartExecResults};
use bollard::{models::*, query_parameters::*};
use chrono::Utc;
use futures_util::StreamExt;
use goldenhoop_core::{expired, request_fingerprint, validate_create};
use goldenhoop_protocol::*;
use goldenhoop_runtime::*;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

mod contexts;
mod controllers;
mod guarded;
mod isolated;
mod networks;
mod sessions;
pub use controllers::{
    ControllerObservation, ControllerPlan, ControllerRemoval, ControllerSession,
    DockerControllerProvider,
};
pub use guarded::{WorkloadEndpoint, WorkloadNetworkPlan};
pub use networks::{DockerNetworkProvider, NetworkObservation, NetworkPlan, NetworkRemoval};
struct ProbeSupport {
    diagnostics: bool,
    shell: bool,
    pty: bool,
}

pub const INSTALL_LABEL: &str = "dev.goldenhoop.installation";
pub const SANDBOX_LABEL: &str = "dev.goldenhoop.sandbox";
pub const PROFILE_LABEL: &str = "dev.goldenhoop.profile";
pub const ROLE_LABEL: &str = "dev.goldenhoop.role";
pub const EXPIRY_LABEL: &str = "dev.goldenhoop.expires-at";
pub const REQUEST_LABEL: &str = "dev.goldenhoop.request-sha256";
const AGENT_PATH: &str = "/opt/goldenhoop/goldenhoop-agent";
const MAX_REPLY: usize = 24 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerProfile {
    Gvisor,
    RuncDevelopment,
}
impl DockerProfile {
    pub fn id(self) -> &'static str {
        match self {
            Self::Gvisor => "local-gvisor",
            Self::RuncDevelopment => "local-runc-dev",
        }
    }
    fn runtime(self) -> &'static str {
        match self {
            Self::Gvisor => "runsc",
            Self::RuncDevelopment => "runc",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DockerConfig {
    pub installation_id: Uuid,
    /// A locally cached, administrator-trusted GoldenHoop agent image.
    pub agent_image: String,
    pub profile: DockerProfile,
    pub allow_runc_development: bool,
}

#[derive(Clone)]
pub struct DockerDriver {
    docker: Docker,
    config: DockerConfig,
    profile: Arc<RwLock<RuntimeProfile>>,
    bundle: Arc<Mutex<Option<String>>>,
    probes: Arc<Mutex<()>>,
    removals: Arc<Mutex<HashMap<Uuid, Weak<Mutex<()>>>>>,
}

fn backend(error: DockerError) -> ApiError {
    // Opt-in is restricted to the public-image contract workflow. Public API
    // errors remain redacted; normal worker runs never print backend payloads.
    if std::env::var("GOLDENHOOP_TEST_BACKEND_DIAGNOSTICS").as_deref() == Ok("1") {
        eprintln!("goldenhoop test backend diagnostic: {error:?}");
    }
    let code = match error {
        DockerError::DockerResponseServerError {
            status_code: 404, ..
        } => ErrorCode::NotFound,
        DockerError::DockerResponseServerError {
            status_code: 409, ..
        } => ErrorCode::Conflict,
        _ => ErrorCode::BackendUnavailable,
    };
    // Backend errors can contain registry credentials and host details.
    ApiError::new(code, "Docker operation failed; inspect worker diagnostics")
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
fn unavailable(message: &str) -> ApiError {
    ApiError::new(ErrorCode::BackendUnavailable, message)
}

fn valid_deadline(
    created: chrono::DateTime<Utc>,
    expires: chrono::DateTime<Utc>,
    ttl: u64,
) -> bool {
    let Some(duration) = i64::try_from(ttl)
        .ok()
        .and_then(chrono::Duration::try_seconds)
    else {
        return false;
    };
    created
        .checked_add_signed(duration)
        .is_some_and(|latest| expires > created && expires <= latest)
}

impl DockerDriver {
    pub async fn connect(config: DockerConfig) -> Result<Self, ApiError> {
        // Socket/named-pipe transport only. No unauthenticated daemon TCP fallback.
        let docker = Docker::connect_with_socket_defaults().map_err(backend)?;
        let docker = docker.negotiate_version().await.map_err(backend)?;
        let profile = RuntimeProfile {
            id: config.profile.id().into(),
            placement: Placement::Local,
            isolation: match config.profile {
                DockerProfile::Gvisor => Isolation::Gvisor,
                DockerProfile::RuncDevelopment => Isolation::Oci,
            },
            availability: Availability::Unverified,
            capabilities: BTreeSet::new(),
            code_languages: Default::default(),
            max_resources: ResourceLimits {
                cpu_millis: 16_000,
                memory_bytes: 32 * 1024 * 1024 * 1024,
                pids: 4096,
            },
            max_ttl_seconds: 86_400,
            reason: Some("runtime smoke test has not run".into()),
        };
        Ok(Self {
            docker,
            config,
            profile: Arc::new(RwLock::new(profile)),
            bundle: Arc::new(Mutex::new(None)),
            probes: Arc::new(Mutex::new(())),
            removals: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn installation_id(&self) -> Uuid {
        self.config.installation_id
    }

    fn labels(&self, role: &str) -> HashMap<String, String> {
        HashMap::from([
            (
                INSTALL_LABEL.into(),
                self.config.installation_id.to_string(),
            ),
            (PROFILE_LABEL.into(), self.config.profile.id().into()),
            (ROLE_LABEL.into(), role.into()),
        ])
    }

    fn owns(&self, labels: Option<&HashMap<String, String>>, role: &str) -> bool {
        labels.is_some_and(|labels| {
            labels.get(INSTALL_LABEL) == Some(&self.config.installation_id.to_string())
                && labels.get(PROFILE_LABEL).map(String::as_str) == Some(self.config.profile.id())
                && labels.get(ROLE_LABEL).map(String::as_str) == Some(role)
        })
    }

    async fn owned(
        &self,
        handle: &RuntimeHandle,
    ) -> Result<Option<ContainerInspectResponse>, ApiError> {
        if handle.profile != self.config.profile.id() {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "runtime handle profile mismatch",
            ));
        }
        let observation = match self
            .docker
            .inspect_container(&handle.backend_ref, None)
            .await
        {
            Ok(value) => value,
            Err(error) if missing(&error) => return Ok(None),
            Err(error) => return Err(backend(error)),
        };
        let labels = observation
            .config
            .as_ref()
            .and_then(|config| config.labels.as_ref());
        if !self.owns(labels, "sandbox")
            || labels.and_then(|labels| labels.get(SANDBOX_LABEL))
                != Some(&handle.sandbox_id.to_string())
        {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "resource ownership mismatch",
            ));
        }
        Ok(Some(observation))
    }

    async fn ensure_bundle(&self) -> Result<String, ApiError> {
        let mut cached = self.bundle.lock().await;
        if let Some(volume) = &*cached {
            return Ok(volume.clone());
        }
        let image = self
            .docker
            .inspect_image(&self.config.agent_image)
            .await
            .map_err(backend)?;
        let image_id = image
            .id
            .ok_or_else(|| unavailable("agent image has no content identity"))?;
        if image
            .config
            .as_ref()
            .and_then(|c| c.labels.as_ref())
            .and_then(|labels| labels.get("dev.goldenhoop.agent.libc"))
            .map(String::as_str)
            != Some("musl")
        {
            return Err(unavailable(
                "agent image must contain the trusted static musl agent",
            ));
        }
        let digest = image_id
            .strip_prefix("sha256:")
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| unavailable("agent image has an invalid content identity"))?;
        let volume = format!(
            "goldenhoop-{}-{}-{digest}",
            self.config.installation_id,
            self.config.profile.runtime()
        );
        self.docker
            .create_volume(VolumeCreateRequest {
                name: Some(volume.clone()),
                labels: Some(self.labels("agent-bundle")),
                ..Default::default()
            })
            .await
            .map_err(backend)?;
        let observed = self.docker.inspect_volume(&volume).await.map_err(backend)?;
        if !self.owns(Some(&observed.labels), "agent-bundle") {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "agent volume ownership mismatch",
            ));
        }
        let name = format!("goldenhoop-bootstrap-{}", Uuid::new_v4());
        let mut helper_labels = self.labels("bootstrap");
        helper_labels.insert(
            EXPIRY_LABEL.into(),
            (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
        );
        let helper = self.docker.create_container(
            Some(CreateContainerOptionsBuilder::default().name(&name).build()),
            ContainerCreateBody {
                image: Some(image_id), user: Some("0:0".into()), working_dir: Some("/".into()),
                healthcheck: Some(HealthConfig { test: Some(vec!["NONE".into()]), ..Default::default() }),
                entrypoint: Some(vec!["/bin/sh".into()]),
                cmd: Some(vec!["-c".into(), "cp /usr/local/bin/goldenhoop-agent /bundle/.agent-new && chmod 0555 /bundle/.agent-new && mv /bundle/.agent-new /bundle/goldenhoop-agent".into()]),
                labels: Some(helper_labels),
                host_config: Some(HostConfig {
                    runtime: Some(self.config.profile.runtime().into()),
                    network_mode: Some("none".into()), readonly_rootfs: Some(true),
                    cap_drop: Some(vec!["ALL".into()]), security_opt: Some(vec!["no-new-privileges".into()]),
                    memory: Some(128 * 1024 * 1024), nano_cpus: Some(1_000_000_000), pids_limit: Some(32),
                    mounts: Some(vec![Mount { target: Some("/bundle".into()), source: Some(volume.clone()), typ: Some(MountType::VOLUME), read_only: Some(false), ..Default::default() }]),
                    ..Default::default()
                }),
                ..Default::default()
            }
        ).await;
        let helper = match helper {
            Ok(value) => value,
            Err(error) => {
                self.remove_helper(&name).await?;
                return Err(backend(error));
            }
        };
        let outcome = async {
            self.docker
                .start_container(&helper.id, None)
                .await
                .map_err(backend)?;
            let result = tokio::time::timeout(
                Duration::from_secs(20),
                self.docker.wait_container(&helper.id, None).next(),
            )
            .await
            .map_err(|_| unavailable("agent bootstrap timed out"))?
            .ok_or_else(|| unavailable("agent bootstrap has no terminal result"))?
            .map_err(backend)?;
            if result.status_code != 0 {
                return Err(unavailable("agent bootstrap failed"));
            }
            Ok(())
        }
        .await;
        // Cleanup runs even on failed startup/wait. Confirm absence before returning.
        self.remove_helper(&helper.id).await?;
        outcome?;
        *cached = Some(volume.clone());
        Ok(volume)
    }

    async fn remove_helper(&self, id: &str) -> Result<(), ApiError> {
        match self.docker.inspect_container(id, None).await {
            Ok(value)
                if self.owns(
                    value.config.as_ref().and_then(|c| c.labels.as_ref()),
                    "bootstrap",
                ) => {}
            Ok(_) => {
                return Err(ApiError::new(
                    ErrorCode::Forbidden,
                    "bootstrap ownership mismatch",
                ));
            }
            Err(error) if missing(&error) => return Ok(()),
            Err(error) => return Err(backend(error)),
        }
        self.docker
            .remove_container(
                id,
                Some(
                    RemoveContainerOptionsBuilder::default()
                        .force(true)
                        .v(true)
                        .build(),
                ),
            )
            .await
            .map_err(backend)?;
        match self.docker.inspect_container(id, None).await {
            Err(error) if missing(&error) => Ok(()),
            Err(error) => Err(backend(error)),
            Ok(_) => Err(unavailable("bootstrap cleanup is not confirmed")),
        }
    }

    async fn provision(
        &self,
        sandbox: &Sandbox,
        request: &CreateSandbox,
    ) -> Result<RuntimeHandle, ApiError> {
        let handle = self.prepare_runtime(sandbox, request, None).await?;
        self.start_prepared(&handle).await
    }

    async fn prepare_runtime(
        &self,
        sandbox: &Sandbox,
        request: &CreateSandbox,
        network: Option<&WorkloadNetworkPlan>,
    ) -> Result<RuntimeHandle, ApiError> {
        if request.resources.memory_bytes < 64 * 1024 * 1024 || request.resources.pids < 16 {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "agent requires at least 64 MiB and 16 PIDs",
            ));
        }
        let volume = self.ensure_bundle().await?;
        let image = self
            .docker
            .inspect_image(&request.image)
            .await
            .map_err(backend)?;
        if image.os.as_deref() != Some("linux") || image.architecture.as_deref() != Some("amd64") {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "workload image must be Linux amd64",
            ));
        }
        let image_config = image.config.unwrap_or_default();
        if image_config.volumes.as_ref().is_some_and(|v| !v.is_empty()) {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "image-declared volumes require an explicit volume policy",
            ));
        }
        // Override all image environment values, including dynamic loader hooks.
        let mut environment: HashMap<String, String> = image_config
            .env
            .unwrap_or_default()
            .iter()
            .filter_map(|item| {
                item.split_once('=')
                    .map(|(key, _)| (key.into(), String::new()))
            })
            .collect();
        environment.extend([
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            ("HOME".into(), "/workspace".into()),
            ("LANG".into(), "C.UTF-8".into()),
            ("GOLDENHOOP_ISOLATED_AGENT".into(), "1".into()),
        ]);
        let mut labels = self.labels("sandbox");
        labels.insert(SANDBOX_LABEL.into(), sandbox.id.to_string());
        labels.insert(EXPIRY_LABEL.into(), sandbox.expires_at.to_rfc3339());
        labels.insert(REQUEST_LABEL.into(), request_fingerprint(request)?);
        let name = format!("goldenhoop-{}-{}", self.config.installation_id, sandbox.id);
        let mut handle = RuntimeHandle {
            sandbox_id: sandbox.id,
            profile: request.profile.clone(),
            backend_ref: name.clone(),
        };
        let mut body = ContainerCreateBody {
            image: image.id,
            user: Some("0:0".into()),
            working_dir: Some("/workspace".into()),
            entrypoint: Some(vec![AGENT_PATH.into(), "serve".into()]),
            cmd: Some(vec![]),
            env: Some(
                environment
                    .into_iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect(),
            ),
            labels: Some(labels),
            // The none driver initializes an isolated namespace with loopback.
            // NetworkDisabled skips that initialization entirely on Docker.
            // Image-defined health checks would otherwise execute as supervisor root.
            healthcheck: Some(HealthConfig {
                test: Some(vec!["NONE".into()]),
                ..Default::default()
            }),
            host_config: Some(HostConfig {
                runtime: Some(self.config.profile.runtime().into()),
                network_mode: Some("none".into()),
                readonly_rootfs: Some(true),
                init: Some(true),
                privileged: Some(false),
                cap_drop: Some(vec!["ALL".into()]),
                cap_add: Some(
                    [
                        "SETUID",
                        "SETGID",
                        "KILL",
                        "CHOWN",
                        "FOWNER",
                        "DAC_OVERRIDE",
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                ),
                security_opt: Some(vec!["no-new-privileges".into()]),
                ipc_mode: Some("private".into()),
                nano_cpus: Some(i64::from(request.resources.cpu_millis) * 1_000_000),
                memory: Some(i64::try_from(request.resources.memory_bytes).map_err(|_| {
                    ApiError::new(ErrorCode::InvalidRequest, "memory limit is too large")
                })?),
                memory_swap: Some(i64::try_from(request.resources.memory_bytes).map_err(|_| {
                    ApiError::new(ErrorCode::InvalidRequest, "memory limit is too large")
                })?),
                pids_limit: Some(i64::from(request.resources.pids)),
                mounts: Some(vec![Mount {
                    target: Some("/opt/goldenhoop".into()),
                    source: Some(volume),
                    typ: Some(MountType::VOLUME),
                    read_only: Some(true),
                    volume_options: Some(MountVolumeOptions {
                        no_copy: Some(true),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                tmpfs: Some(HashMap::from([
                    (
                        "/workspace".into(),
                        "rw,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=2770".into(),
                    ),
                    (
                        "/tmp".into(),
                        "rw,exec,nosuid,nodev,size=256m,mode=1777".into(),
                    ),
                    (
                        "/run/goldenhoop".into(),
                        "rw,nosuid,nodev,size=8m,mode=700".into(),
                    ),
                ])),
                log_config: Some(HostConfigLogConfig {
                    typ: Some("json-file".into()),
                    config: Some(HashMap::from([
                        ("max-size".into(), "1m".into()),
                        ("max-file".into(), "1".into()),
                    ])),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        if let Some(network) = network {
            body.host_config
                .as_mut()
                .expect("fixed host config")
                .network_mode = Some(network.network_id.clone());
            body.labels.as_mut().expect("fixed labels").insert(
                guarded::NETWORK_PLAN_LABEL.into(),
                serde_json::to_string(network)
                    .map_err(|_| unavailable("invalid owned workload network plan"))?,
            );
        }
        match self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().name(&name).build()),
                body,
            )
            .await
        {
            Ok(created) => handle.backend_ref = created.id,
            Err(DockerError::DockerResponseServerError {
                status_code: 409, ..
            }) => {
                let observation = self
                    .owned(&handle)
                    .await?
                    .ok_or_else(|| unavailable("conflicting sandbox disappeared"))?;
                guarded::match_requested_plan(&observation, network)?;
                let labels = observation
                    .config
                    .as_ref()
                    .and_then(|config| config.labels.as_ref());
                if labels.and_then(|labels| labels.get(REQUEST_LABEL))
                    != Some(&request_fingerprint(request)?)
                    || labels.and_then(|labels| labels.get(EXPIRY_LABEL))
                        != Some(&sandbox.expires_at.to_rfc3339())
                {
                    return Err(ApiError::new(
                        ErrorCode::Conflict,
                        "sandbox ID has a different create request",
                    ));
                }
                handle.backend_ref = observation
                    .id
                    .ok_or_else(|| unavailable("container has no identity"))?;
            }
            Err(error) => return Err(backend(error)),
        }
        Ok(handle)
    }

    async fn start_prepared(&self, handle: &RuntimeHandle) -> Result<RuntimeHandle, ApiError> {
        let outcome = async {
            let observation = self
                .owned(handle)
                .await?
                .ok_or_else(|| unavailable("sandbox disappeared during start"))?;
            if observation.state.as_ref().and_then(|state| state.paused) == Some(true) {
                return Ok(handle.clone());
            }
            if observation.state.as_ref().and_then(|state| state.running) != Some(true) {
                if observation.state.as_ref().and_then(|state| state.status)
                    != Some(ContainerStateStatusEnum::CREATED)
                {
                    return Err(ApiError::new(
                        ErrorCode::InvalidState,
                        "an exited sandbox cannot be restarted by create retry",
                    ));
                }
                self.docker
                    .start_container(&handle.backend_ref, None)
                    .await
                    .map_err(backend)?;
            }
            for _ in 0..50 {
                if matches!(
                    self.bridge(handle, &AgentRequest::Ping).await,
                    Ok(AgentResponse::Pong { .. })
                ) {
                    return Ok(handle.clone());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(unavailable("sandbox agent did not become ready"))
        }
        .await;
        if outcome.is_err() {
            self.remove(handle).await?;
        }
        outcome
    }

    async fn bridge(
        &self,
        handle: &RuntimeHandle,
        request: &AgentRequest,
    ) -> Result<AgentResponse, ApiError> {
        self.bridge_reply(handle, request).await?.into_result()
    }

    async fn bridge_reply(
        &self,
        handle: &RuntimeHandle,
        request: &AgentRequest,
    ) -> Result<AgentReply, ApiError> {
        self.owned(handle)
            .await?
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "sandbox not found"))?;
        tokio::time::timeout(Duration::from_secs(15), async {
            let exec = self
                .docker
                .create_exec(
                    &handle.backend_ref,
                    ExecConfig {
                        attach_stdin: Some(true),
                        attach_stdout: Some(true),
                        attach_stderr: Some(true),
                        tty: Some(false),
                        user: Some("0:0".into()),
                        cmd: Some(vec![AGENT_PATH.into(), "rpc".into()]),
                        ..Default::default()
                    },
                )
                .await
                .map_err(backend)?;
            let StartExecResults::Attached {
                mut output,
                mut input,
            } = self
                .docker
                .start_exec(&exec.id, None)
                .await
                .map_err(backend)?
            else {
                return Err(unavailable("agent bridge did not attach"));
            };
            let mut bytes = serde_json::to_vec(request)
                .map_err(|_| unavailable("could not encode agent request"))?;
            if bytes.len() > MAX_REPLY {
                return Err(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "agent request exceeds limit",
                ));
            }
            bytes.push(b'\n');
            input
                .write_all(&bytes)
                .await
                .map_err(|_| unavailable("agent bridge input failed"))?;
            input
                .flush()
                .await
                .map_err(|_| unavailable("agent bridge flush failed"))?;
            let mut reply = Vec::new();
            while let Some(packet) = output.next().await {
                match packet.map_err(backend)? {
                    LogOutput::StdOut { message } => {
                        if reply.len() + message.len() > MAX_REPLY {
                            return Err(unavailable("agent reply exceeds limit"));
                        }
                        reply.extend_from_slice(&message);
                    }
                    LogOutput::StdErr { message } if !message.is_empty() => {
                        return Err(unavailable("agent bridge reported an error"));
                    }
                    _ => {}
                }
            }
            let result = self.docker.inspect_exec(&exec.id).await.map_err(backend)?;
            if result.running != Some(false) || result.exit_code != Some(0) {
                return Err(unavailable(
                    "agent bridge has no successful terminal result",
                ));
            }
            serde_json::from_slice::<AgentReply>(&reply)
                .map_err(|_| unavailable("invalid agent reply"))
        })
        .await
        .map_err(|_| unavailable("agent bridge timed out"))?
    }

    async fn smoke_test(&self) -> Result<ProbeSupport, ApiError> {
        let info = self.docker.info().await.map_err(backend)?;
        if info.os_type.as_deref() != Some("linux")
            || !matches!(info.architecture.as_deref(), Some("x86_64" | "amd64"))
        {
            return Err(unavailable("Docker execution host must be Linux x86_64"));
        }
        if !info
            .runtimes
            .as_ref()
            .is_some_and(|runtimes| runtimes.contains_key(self.config.profile.runtime()))
        {
            return Err(unavailable(
                "required Docker runtime is not installed; fallback is forbidden",
            ));
        }
        let request: CreateSandbox = serde_json::from_value(serde_json::json!({
            "profile": self.config.profile.id(), "image": self.config.agent_image,
            "resources": {"cpu_millis":1000,"memory_bytes":268435456,"pids":128}, "ttl_seconds":60,
        }))
        .map_err(|_| unavailable("invalid internal runtime probe"))?;
        let sandbox = Sandbox {
            id: Uuid::new_v4(),
            profile: request.profile.clone(),
            image: request.image.clone(),
            state: SandboxState::Starting,
            desired_state: DesiredState::Running,
            cleanup: CleanupState::Pending,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
            observed_at: None,
            resources: request.resources.clone(),
            metadata: Default::default(),
            reason: None,
        };
        let handle = self.provision(&sandbox, &request).await?;
        let outcome = async {
            let observed = self.owned(&handle).await?.ok_or_else(|| unavailable("probe sandbox is absent"))?;
            let host = observed.host_config.ok_or_else(|| unavailable("probe has no effective runtime config"))?;
            if host.network_mode.as_deref() != Some("none") || host.runtime.as_deref() != Some(self.config.profile.runtime())
                || host.readonly_rootfs != Some(true) || host.pids_limit != Some(128) || host.memory != Some(268435456)
            { return Err(unavailable("effective runtime restrictions do not match the profile")); }
            let id = Uuid::new_v4();
            let command = serde_json::from_value(serde_json::json!({"argv":["python3","-c",r#"import os,socket,errno
assert os.getuid()==1000
lines=open('/proc/self/status').read().splitlines()
assert int(next(v.split()[1] for v in lines if v.startswith('CapEff:')),16)==0
names=sorted(name for _,name in socket.if_nameindex())
assert names==['lo'],names
with socket.socket() as listener:
    listener.settimeout(1)
    listener.bind(('127.0.0.1',0))
    listener.listen(1)
    with socket.create_connection(listener.getsockname(),timeout=1) as connection:
        accepted,_=listener.accept()
        with accepted:
            connection.sendall(b'loopback')
            assert accepted.recv(8)==b'loopback'
for family,address in [(socket.AF_INET,('1.1.1.1',443)),(socket.AF_INET,('172.17.0.1',443)),(socket.AF_INET,('169.254.169.254',80)),(socket.AF_INET6,('2606:4700:4700::1111',443))]:
    for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
        try: sock=socket.socket(family,kind)
        except OSError as error:
            assert family==socket.AF_INET6 and error.errno in (errno.EAFNOSUPPORT,errno.EPROTONOSUPPORT)
            continue
        with sock:
            sock.settimeout(.5)
            assert sock.connect_ex(address)!=0,(family,kind,address)
"#],"timeout_seconds":5})).map_err(|_| unavailable("invalid probe command"))?;
            self.bridge(&handle, &AgentRequest::Start { id, command }).await?;
            let mut completed = false;
            for _ in 0..50 {
                if let AgentResponse::Execution(record) = self.bridge(&handle, &AgentRequest::Inspect { id }).await?
                    && record.state.is_terminal() {
                        if record.state != ExecutionState::Succeeded || record.cleanup != CleanupState::Complete { return Err(unavailable("runtime command smoke test failed")); }
                        completed = true; break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if !completed { return Err(unavailable("runtime command smoke test did not finish")); }
            let diagnostic_support = self.diagnostics(&handle).await.ok().and_then(|sample|sample.usage)
                .is_some_and(|usage| usage.cpu_time_ns.is_some() && usage.memory_bytes.is_some() && usage.host_tasks.is_some());
            let shell=self.probe_session(&handle,false).await?;
            let pty=if shell {self.probe_session(&handle,true).await?}else{false};
            self.docker.pause_container(&handle.backend_ref).await.map_err(backend)?;
            if self.inspect(&handle).await?.state != ObservedState::Paused { return Err(unavailable("runtime pause was not observed")); }
            self.docker.unpause_container(&handle.backend_ref).await.map_err(backend)?;
            self.bridge(&handle, &AgentRequest::Ping).await?;
            Ok(ProbeSupport {diagnostics:diagnostic_support,shell,pty})
        }.await;
        self.remove(&handle).await?;
        outcome
    }

    /// Independent host-worker deadline enforcement; paused guests are also removed.
    pub async fn reap_expired(&self) -> Result<Vec<Uuid>, ApiError> {
        let filters: HashMap<String, Vec<String>> = HashMap::from([(
            "label".into(),
            vec![
                format!("{INSTALL_LABEL}={}", self.config.installation_id),
                format!("{PROFILE_LABEL}={}", self.config.profile.id()),
                format!("{ROLE_LABEL}=bootstrap"),
            ],
        )]);
        let helpers = self
            .docker
            .list_containers(Some(
                ListContainersOptionsBuilder::default()
                    .all(true)
                    .filters(&filters)
                    .build(),
            ))
            .await
            .map_err(backend)?;
        for helper in helpers {
            let expiry = helper
                .labels
                .as_ref()
                .and_then(|labels| labels.get(EXPIRY_LABEL))
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .ok_or_else(|| unavailable("owned bootstrap expiry label is invalid"))?;
            if Utc::now() >= expiry {
                self.remove_helper(
                    &helper
                        .id
                        .ok_or_else(|| unavailable("bootstrap has no identity"))?,
                )
                .await?;
            }
        }
        let mut removed = Vec::new();
        for handle in self.discover().await? {
            let Some(observation) = self.owned(&handle).await? else {
                continue;
            };
            let expires_at = observation
                .config
                .as_ref()
                .and_then(|c| c.labels.as_ref())
                .and_then(|labels| labels.get(EXPIRY_LABEL))
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .ok_or_else(|| unavailable("owned sandbox expiry label is invalid"))?;
            if Utc::now() >= expires_at {
                self.remove(&handle).await?;
                removed.push(handle.sandbox_id);
            }
        }
        Ok(removed)
    }

    /// Explicit installation/test cleanup. Refuses while owned sandboxes remain.
    pub async fn remove_agent_bundle(&self) -> Result<(), ApiError> {
        if !self.discover().await?.is_empty() {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "sandboxes still use this installation",
            ));
        }
        let mut cached = self.bundle.lock().await;
        let filters: HashMap<String, Vec<String>> = HashMap::from([(
            "label".into(),
            vec![
                format!("{INSTALL_LABEL}={}", self.config.installation_id),
                format!("{PROFILE_LABEL}={}", self.config.profile.id()),
                format!("{ROLE_LABEL}=agent-bundle"),
            ],
        )]);
        let volumes = self
            .docker
            .list_volumes(Some(
                ListVolumesOptionsBuilder::default()
                    .filters(&filters)
                    .build(),
            ))
            .await
            .map_err(backend)?;
        for volume in volumes.volumes.unwrap_or_default() {
            if !self.owns(Some(&volume.labels), "agent-bundle") {
                return Err(ApiError::new(
                    ErrorCode::Forbidden,
                    "agent volume ownership mismatch",
                ));
            }
            self.docker
                .remove_volume(
                    &volume.name,
                    Some(RemoveVolumeOptionsBuilder::default().force(false).build()),
                )
                .await
                .map_err(backend)?;
            match self.docker.inspect_volume(&volume.name).await {
                Err(error) if missing(&error) => {}
                Err(error) => return Err(backend(error)),
                Ok(_) => return Err(unavailable("agent volume removal is not confirmed")),
            }
        }
        *cached = None;
        Ok(())
    }
}

#[async_trait]
impl RuntimeDriver for DockerDriver {
    async fn probe(&self) -> RuntimeProfile {
        let _probe = self.probes.lock().await;
        let result = if self.config.profile == DockerProfile::RuncDevelopment
            && !self.config.allow_runc_development
        {
            Err(unavailable(
                "ordinary containers require explicit development opt-in",
            ))
        } else {
            self.smoke_test().await
        };
        let mut profile = self.profile.write().await;
        profile.code_languages.clear();
        match result {
            Ok(support) => {
                profile.availability = Availability::Available;
                profile.capabilities = [
                    Capability::Commands,
                    Capability::Files,
                    Capability::Pause,
                    Capability::NetworkIsolation,
                ]
                .into_iter()
                .collect();
                if support.diagnostics {
                    profile.capabilities.insert(Capability::Diagnostics);
                }
                if support.shell {
                    profile.capabilities.insert(Capability::ShellSessions);
                }
                if support.pty {
                    profile.capabilities.insert(Capability::Pty);
                }
                profile.reason = None;
            }
            Err(error) => {
                profile.availability = Availability::Unavailable;
                profile.capabilities.clear();
                profile.reason = Some(error.message);
            }
        }
        profile.clone()
    }

    async fn create(
        &self,
        sandbox: &Sandbox,
        request: &CreateSandbox,
    ) -> Result<RuntimeHandle, ApiError> {
        validate_create(&*self.profile.read().await, request)?;
        if sandbox.profile != request.profile
            || sandbox.image != request.image
            || sandbox.resources != request.resources
            || expired(sandbox, Utc::now())
            || !valid_deadline(sandbox.created_at, sandbox.expires_at, request.ttl_seconds)
        {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "sandbox identity, limits or expiry do not match create request",
            ));
        }
        self.provision(sandbox, request).await
    }

    async fn inspect(&self, handle: &RuntimeHandle) -> Result<RuntimeObservation, ApiError> {
        let Some(observation) = self.owned(handle).await? else {
            return Ok(RuntimeObservation {
                state: ObservedState::Missing,
                exit_code: None,
                oom_killed: None,
                observed_at: Utc::now(),
            });
        };
        let value = observation.state.unwrap_or_default();
        let state = if value.paused == Some(true) {
            ObservedState::Paused
        } else if value.running == Some(true) {
            ObservedState::Running
        } else if matches!(
            value.status,
            Some(ContainerStateStatusEnum::CREATED | ContainerStateStatusEnum::RESTARTING)
        ) {
            ObservedState::Starting
        } else if matches!(
            value.status,
            Some(ContainerStateStatusEnum::EXITED | ContainerStateStatusEnum::DEAD)
        ) {
            ObservedState::Exited
        } else {
            ObservedState::Unknown
        };
        Ok(RuntimeObservation {
            state,
            exit_code: value.exit_code,
            oom_killed: value.oom_killed,
            observed_at: Utc::now(),
        })
    }

    async fn diagnostics(&self, handle: &RuntimeHandle) -> Result<RuntimeDiagnostics, ApiError> {
        let observed = self
            .owned(handle)
            .await?
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "owned runtime is absent"))?;
        let canonical = observed
            .id
            .ok_or_else(|| unavailable("runtime identity is absent"))?;
        let state = observed.state.unwrap_or_default();
        let mut sample = RuntimeDiagnostics {
            sandbox_id: handle.sandbox_id,
            observed_at: Utc::now(),
            running: state.running,
            paused: state.paused,
            exit_code: if matches!(
                state.status,
                Some(ContainerStateStatusEnum::EXITED | ContainerStateStatusEnum::DEAD)
            ) {
                state.exit_code
            } else {
                None
            },
            oom_killed: state.oom_killed,
            usage: None,
            usage_error: None,
        };
        if state.running != Some(true) || state.paused == Some(true) {
            return Ok(sample);
        }
        let fetch = async {
            let mut stats = self.docker.stats(
                &canonical,
                Some(
                    StatsOptionsBuilder::default()
                        .stream(false)
                        .one_shot(true)
                        .build(),
                ),
            );
            let stats = stats
                .next()
                .await
                .ok_or_else(|| unavailable("runtime metrics stream ended without a sample"))?
                .map_err(backend)?;
            if stats.id.as_deref() != Some(canonical.as_str()) {
                return Err(unavailable("runtime metrics identity mismatch"));
            }
            let sampled_at = stats
                .read
                .as_ref()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(&value.to_string()).ok())
                .filter(|time| time.timestamp() > 0)
                .ok_or_else(|| unavailable("runtime metrics timestamp is absent"))?
                .with_timezone(&Utc);
            Ok(ResourceUsage {
                sampled_at,
                cpu_time_ns: stats
                    .cpu_stats
                    .and_then(|cpu| cpu.cpu_usage)
                    .and_then(|usage| usage.total_usage),
                memory_bytes: stats.memory_stats.and_then(|memory| memory.usage),
                host_tasks: stats.pids_stats.and_then(|pids| pids.current),
            })
        };
        match tokio::time::timeout(Duration::from_secs(5), fetch).await {
            Ok(Ok(usage)) => sample.usage = Some(usage),
            Ok(Err(error)) => sample.usage_error = Some(error),
            Err(_) => {
                sample.usage_error =
                    Some(unavailable("runtime metrics request exceeded its deadline"))
            }
        }
        Ok(sample)
    }

    async fn remove(&self, handle: &RuntimeHandle) -> Result<(), ApiError> {
        let lock = {
            let mut locks = self.removals.lock().await;
            locks.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = locks.get(&handle.sandbox_id).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(Mutex::new(()));
                locks.insert(handle.sandbox_id, Arc::downgrade(&lock));
                lock
            }
        };
        let _guard = lock.lock().await;
        let mut canonical = handle.clone();
        for attempt in 0..4 {
            let Some(observed) = self.owned(&canonical).await? else {
                return Ok(());
            };
            // Never mutate by a reusable name after checking ownership.
            canonical.backend_ref = observed
                .id
                .ok_or_else(|| unavailable("owned container has no identity"))?;
            match self
                .docker
                .remove_container(
                    &canonical.backend_ref,
                    Some(
                        RemoveContainerOptionsBuilder::default()
                            .force(true)
                            .v(true)
                            .build(),
                    ),
                )
                .await
            {
                Ok(()) => {}
                Err(error) => {
                    let retry = matches!(
                        &error,
                        DockerError::DockerResponseServerError {
                            status_code: 404 | 409 | 500,
                            ..
                        }
                    );
                    let error = backend(error);
                    if !retry {
                        return Err(error);
                    }
                    eprintln!(
                        "{}",
                        serde_json::json!({"event":"owned_container_removal_retry","sandbox_id":handle.sandbox_id,"attempt":attempt+1,"code":error.code})
                    );
                }
            }
            if self.owned(&canonical).await?.is_none() {
                return Ok(());
            }
            if attempt < 3 {
                tokio::time::sleep(Duration::from_millis(100 * (1 << attempt))).await;
            }
        }
        Err(unavailable(
            "sandbox cleanup is not confirmed after bounded removal retries",
        ))
    }

    async fn discover(&self) -> Result<Vec<RuntimeHandle>, ApiError> {
        let filters: HashMap<String, Vec<String>> = HashMap::from([(
            "label".into(),
            vec![
                format!("{INSTALL_LABEL}={}", self.config.installation_id),
                format!("{PROFILE_LABEL}={}", self.config.profile.id()),
                format!("{ROLE_LABEL}=sandbox"),
            ],
        )]);
        self.docker
            .list_containers(Some(
                ListContainersOptionsBuilder::default()
                    .all(true)
                    .filters(&filters)
                    .build(),
            ))
            .await
            .map_err(backend)?
            .into_iter()
            .map(|container| {
                let labels = container.labels.as_ref();
                if !self.owns(labels, "sandbox") {
                    return Err(ApiError::new(
                        ErrorCode::Forbidden,
                        "discovery ownership mismatch",
                    ));
                }
                let id = labels
                    .and_then(|labels| labels.get(SANDBOX_LABEL))
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .ok_or_else(|| unavailable("owned sandbox has invalid identity"))?;
                Ok(RuntimeHandle {
                    sandbox_id: id,
                    profile: self.config.profile.id().into(),
                    backend_ref: container
                        .id
                        .ok_or_else(|| unavailable("container has no identity"))?,
                })
            })
            .collect()
    }

    async fn pause(&self, handle: &RuntimeHandle) -> Result<(), ApiError> {
        self.owned(handle)
            .await?
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "sandbox not found"))?;
        self.docker
            .pause_container(&handle.backend_ref)
            .await
            .map_err(backend)?;
        if self.inspect(handle).await?.state != ObservedState::Paused {
            return Err(unavailable("pause not observed"));
        }
        Ok(())
    }
    async fn resume(&self, handle: &RuntimeHandle) -> Result<(), ApiError> {
        self.owned(handle)
            .await?
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "sandbox not found"))?;
        self.docker
            .unpause_container(&handle.backend_ref)
            .await
            .map_err(backend)?;
        if self.inspect(handle).await?.state != ObservedState::Running {
            return Err(unavailable("resume not observed"));
        }
        Ok(())
    }
}

#[async_trait]
impl AgentTransport for DockerDriver {
    async fn rpc_reply(
        &self,
        handle: &RuntimeHandle,
        request: &AgentRequest,
    ) -> Result<AgentReply, ApiError> {
        self.bridge_reply(handle, request).await
    }
    async fn rpc(
        &self,
        handle: &RuntimeHandle,
        request: &AgentRequest,
    ) -> Result<AgentResponse, ApiError> {
        self.bridge(handle, request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clamped_child_deadline_is_valid_but_extension_and_invalid_lifetimes_are_refused() {
        let created = Utc::now();
        assert!(valid_deadline(
            created,
            created + chrono::Duration::seconds(60),
            60
        ));
        assert!(valid_deadline(
            created,
            created + chrono::Duration::milliseconds(1550),
            60
        ));
        assert!(!valid_deadline(
            created,
            created + chrono::Duration::milliseconds(60001),
            60
        ));
        assert!(!valid_deadline(created, created, 60));
        assert!(!valid_deadline(
            created,
            created - chrono::Duration::seconds(1),
            60
        ));
        assert!(!valid_deadline(
            created,
            created + chrono::Duration::seconds(1),
            0
        ));
        assert!(!valid_deadline(
            created,
            created + chrono::Duration::seconds(1),
            u64::MAX
        ));
    }
}
