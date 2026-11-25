//! Trusted host controller containers. No workload or policy capability is published.
use super::{EXPIRY_LABEL, INSTALL_LABEL, PROFILE_LABEL, ROLE_LABEL, SANDBOX_LABEL, backend};
use bollard::{Docker, container::LogOutput, models::*, query_parameters::*};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
pub use goldenhoop_egress::ControllerPlan;
use goldenhoop_egress::ControllerPurpose;
use goldenhoop_egress::{
    controller::{CallError, Client, MAX_FRAME, Reply, Request},
    native::NativeBridgePlan,
};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
    time::Instant,
};
use tokio_util::io::StreamReader;

const ROLE: &str = "egress-controller";
const PLAN: &str = "dev.goldenhoop.controller-plan";
const PATH: &str = "/usr/local/bin/goldenhoop-egress";
const ENV: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const MEMORY: i64 = 128 * 1024 * 1024;
mod inspection;
use inspection::{observe, request};
#[cfg(test)]
mod tests;

fn invalid() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidRequest,
        "invalid trusted controller dispatch",
    )
}
fn conflict() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "trusted controller identity, placement or state differs",
    )
}
fn unknown() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "trusted controller operation was not confirmed",
    )
}
fn id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn image_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(id)
}
async fn bounded<T>(
    future: impl Future<Output = Result<T, bollard::errors::Error>>,
) -> Result<T, ApiError> {
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .map_err(|_| unknown())?
        .map_err(backend)
}

/// Provider process observation only; no native packet or collection attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerObservation {
    pub container_id: String,
    pub image_id: String,
    pub status: String,
    pub running: bool,
    pub paused: bool,
    pub restarting: bool,
    pub dead: bool,
    pub exit_code: i64,
    pub observed_at: DateTime<Utc>,
}
#[derive(Debug, Serialize)]
pub struct ControllerRemoval {
    pub container_id: String,
    pub provider_absent: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct DockerControllerProvider {
    docker: Docker,
    image_id: String,
    image_labels: HashMap<String, String>,
    // A cancelled or failed create/start remains fenced in this provider. The
    // durable caller must also never redispatch it after a service restart.
    writes: Arc<Mutex<HashSet<String>>>,
}
impl DockerControllerProvider {
    /// Local daemon only, explicit immutable administrator-trusted image. Never
    /// resolves mutable tags, pulls images or chooses an alternate runtime.
    pub async fn connect(pinned_image: &str) -> Result<Self, ApiError> {
        if !image_id(pinned_image) {
            return Err(invalid());
        }
        let docker = Docker::connect_with_socket_defaults().map_err(backend)?;
        let docker = bounded(docker.negotiate_version()).await?;
        let version = bounded(docker.version()).await?;
        let api = version
            .api_version
            .as_deref()
            .and_then(|s| s.split_once('.'))
            .and_then(|(major, minor)| {
                Some((major.parse::<u16>().ok()?, minor.parse::<u16>().ok()?))
            });
        if version.os.as_deref() != Some("linux") || version.arch.as_deref() != Some("amd64") {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "controller requires a Linux x86_64 daemon",
            ));
        }
        if api.is_none_or(|v| v < (1, 53)) {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "controller requires Docker API 1.53 or newer",
            ));
        }
        let image = bounded(docker.inspect_image(pinned_image)).await?;
        let config = image.config.as_ref().ok_or_else(unknown)?;
        if image.id.as_deref() != Some(pinned_image)
            || image.os.as_deref() != Some("linux")
            || image.architecture.as_deref() != Some("amd64")
            || config.entrypoint.as_deref() != Some(&[PATH.to_owned()])
            || config.cmd.as_ref().is_some_and(|v| !v.is_empty())
            || config.volumes.as_ref().is_some_and(|v| !v.is_empty())
            || config.exposed_ports.as_ref().is_some_and(|v| !v.is_empty())
            || config.healthcheck.is_some()
            || config.on_build.as_ref().is_some_and(|v| !v.is_empty())
            || config.env.as_deref() != Some(&[ENV.to_owned()])
            || config
                .labels
                .as_ref()
                .and_then(|m| m.get("dev.goldenhoop.egress"))
                .map(String::as_str)
                != Some("host-netfilter")
        {
            return Err(conflict());
        }
        Ok(Self {
            docker,
            image_id: pinned_image.to_owned(),
            image_labels: config.labels.clone().ok_or_else(unknown)?,
            writes: Arc::new(Mutex::new(HashSet::new())),
        })
    }
    pub fn plan(
        &self,
        native: NativeBridgePlan,
        generation: uuid::Uuid,
    ) -> Result<ControllerPlan, ApiError> {
        let plan = ControllerPlan {
            native,
            image_id: self.image_id.clone(),
            controller_generation: Some(generation),
            purpose: ControllerPurpose::Enforce,
            collection_deadline: None,
        };
        self.check(&plan)?;
        Ok(plan)
    }
    fn check(&self, plan: &ControllerPlan) -> Result<(), ApiError> {
        plan.validate()?;
        if plan.image_id != self.image_id {
            return Err(conflict());
        }
        Ok(())
    }
    fn observe(
        &self,
        plan: &ControllerPlan,
        value: &ContainerInspectResponse,
    ) -> Result<ControllerObservation, ApiError> {
        observe(plan, value, &request(plan, &self.image_labels))
    }
    async fn inventory(&self, key: &str, value: &str) -> Result<Vec<ContainerSummary>, ApiError> {
        let rows = bounded(self.docker.list_containers(Some(ListContainersOptions {
            all: true,
            filters: Some(HashMap::from([(key.into(), vec![value.into()])])),
            ..Default::default()
        })))
        .await?;
        if rows.len() > 4096 {
            return Err(unknown());
        }
        Ok(rows)
    }
    /// Full positive inspection, including stopped containers; never creates or
    /// restarts a missing process and never treats a failed lookup as absence.
    pub async fn lookup(
        &self,
        plan: &ControllerPlan,
    ) -> Result<Option<ControllerObservation>, ApiError> {
        self.check(plan)?;
        let rows = self
            .inventory("name", &format!("^/{}$", plan.name()))
            .await?;
        if rows.len() > 1 {
            return Err(conflict());
        }
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let container = row.id.as_deref().filter(|v| id(v)).ok_or_else(unknown)?;
        let value = bounded(self.docker.inspect_container(container, None)).await?;
        let observed = self.observe(plan, &value)?;
        if observed.container_id != container {
            return Err(conflict());
        }
        Ok(Some(observed))
    }
    /// Only a newly committed dispatch may call this. Cancellation keeps a local
    /// fence; a lost response requires lookup, including across worker restarts.
    pub async fn create_fresh(
        &self,
        plan: &ControllerPlan,
    ) -> Result<ControllerObservation, ApiError> {
        self.check(plan)?;
        plan.validate_dispatch_at(Utc::now())?;
        let mut writes = self.writes.lock().await;
        let key = format!("create:{}", plan.name());
        if writes.contains(&key) || self.lookup(plan).await?.is_some() {
            return Err(conflict());
        }
        plan.validate_dispatch_at(Utc::now())?;
        writes.insert(key);
        let response = bounded(self.docker.create_container(
            Some(CreateContainerOptions {
                name: Some(plan.name()),
                ..Default::default()
            }),
            request(plan, &self.image_labels),
        ))
        .await?;
        if !id(&response.id) || !response.warnings.is_empty() {
            return Err(unknown());
        }
        let actual = self.lookup(plan).await?.ok_or_else(unknown)?;
        if actual.container_id != response.id || actual.status != "created" || actual.running {
            return Err(unknown());
        }
        Ok(actual)
    }
    /// Only starts a positively observed never-started container once. Existing
    /// running/exited controllers are recovery observations, never replay targets.
    pub async fn start_created(
        &self,
        plan: &ControllerPlan,
        expected_id: &str,
    ) -> Result<ControllerSession, ApiError> {
        self.check(plan)?;
        plan.validate_dispatch_at(Utc::now())?;
        if !id(expected_id) {
            return Err(invalid());
        }
        let mut writes = self.writes.lock().await;
        let key = format!("start:{expected_id}");
        let actual = self.lookup(plan).await?.ok_or_else(unknown)?;
        if writes.contains(&key)
            || actual.container_id != expected_id
            || actual.status != "created"
            || actual.running
        {
            return Err(conflict());
        }
        writes.insert(key);
        let attached = bounded(self.docker.attach_container(
            expected_id,
            Some(AttachContainerOptions {
                stdin: true,
                stdout: true,
                stderr: true,
                stream: true,
                logs: false,
                ..Default::default()
            }),
        ))
        .await?;
        plan.validate_dispatch_at(Utc::now())?;
        bounded(self.docker.start_container(expected_id, None)).await?;
        let observed = self.lookup(plan).await?.ok_or_else(unknown)?;
        if observed.container_id != expected_id || !observed.running || observed.status != "running"
        {
            return Err(unknown());
        }
        let output = attached.output.map(|packet| match packet {
            Ok(LogOutput::StdOut { message })
                if !message.is_empty() && message.len() as u64 <= MAX_FRAME =>
            {
                Ok(message)
            }
            _ => Err(io::Error::other("controller stream observation failed")),
        });
        let reader: Pin<Box<dyn AsyncRead + Send>> = Box::pin(StreamReader::new(output));
        Ok(ControllerSession {
            provider: self.clone(),
            plan: plan.clone(),
            container_id: expected_id.into(),
            client: Some(Client::new(reader, attached.input)),
        })
    }
    /// A positively observed ID is mandatory. An unacknowledged creation with no
    /// observed object remains unknown, even when a name inventory is empty.
    /// This settles the process only; native bridge/table absence is separate.
    pub async fn collect(
        &self,
        plan: &ControllerPlan,
        expected_id: &str,
    ) -> Result<ControllerRemoval, ApiError> {
        self.check(plan)?;
        if !id(expected_id) {
            return Err(invalid());
        }
        let _serial = self.writes.lock().await;
        if let Some(actual) = self.lookup(plan).await? {
            if actual.container_id != expected_id {
                return Err(conflict());
            }
            match bounded(self.docker.remove_container(
                expected_id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            ))
            .await
            {
                Ok(()) => {}
                Err(error) if error.code == ErrorCode::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        if self.lookup(plan).await?.is_some()
            || !self.inventory("id", expected_id).await?.is_empty()
        {
            return Err(unknown());
        }
        match bounded(self.docker.inspect_container(expected_id, None)).await {
            Err(error) if error.code == ErrorCode::NotFound => {}
            _ => return Err(unknown()),
        }
        Ok(ControllerRemoval {
            container_id: expected_id.into(),
            provider_absent: true,
            observed_at: Utc::now(),
        })
    }
}

type Channel = Client<Pin<Box<dyn AsyncRead + Send>>, Pin<Box<dyn AsyncWrite + Send>>>;
pub struct ControllerSession {
    provider: DockerControllerProvider,
    plan: ControllerPlan,
    container_id: String,
    client: Option<Channel>,
}
impl ControllerSession {
    /// Stop further dispatch after an untrusted/inconsistent mutation result.
    /// EOF does not attest process exit or native collection.
    pub(crate) fn fence(&mut self) {
        drop(self.client.take());
    }
    pub(crate) fn plan(&self) -> &ControllerPlan {
        &self.plan
    }
    pub fn is_uncertain(&self) -> bool {
        self.client.as_ref().is_none_or(Client::is_uncertain)
    }
    pub async fn call(&mut self, request: Request, deadline: Instant) -> Result<Reply, CallError> {
        if self.plan.purpose == ControllerPurpose::Collect
            && !matches!(
                &request,
                Request::Open { .. } | Request::Inspect {} | Request::Remove { .. }
            )
        {
            return Err(CallError::InvalidRequest);
        }
        match &request {
            Request::Open { allocation }
                if allocation.owner() != self.plan.native.allocation.owner() =>
            {
                return Err(CallError::InvalidRequest);
            }
            Request::BindNative { plan }
                if serde_json::to_value(plan).ok()
                    != serde_json::to_value(&self.plan.native).ok() =>
            {
                return Err(CallError::InvalidRequest);
            }
            _ => {}
        }
        let remaining = self
            .plan
            .dispatch_deadline()
            .map_err(|_| CallError::InvalidRequest)?
            .signed_duration_since(Utc::now())
            .to_std()
            .map_err(|_| CallError::ExpiredDeadline)?;
        let now = Instant::now();
        let bound = now + remaining.min(deadline.saturating_duration_since(now));
        self.client
            .as_mut()
            .ok_or(CallError::UncertainChannel)?
            .call(request, deadline.min(bound))
            .await
    }
    /// Closes the transport, then requires an actual successful process exit.
    /// It does not delete the container or attest native packet collection.
    pub async fn close(mut self) -> Result<ControllerObservation, ApiError> {
        drop(self.client.take());
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let actual = self
                    .provider
                    .lookup(&self.plan)
                    .await?
                    .ok_or_else(unknown)?;
                if actual.container_id != self.container_id {
                    return Err(conflict());
                }
                if !actual.running {
                    return if actual.status == "exited"
                        && actual.exit_code == 0
                        && !actual.paused
                        && !actual.restarting
                        && !actual.dead
                    {
                        Ok(actual)
                    } else {
                        Err(unknown())
                    };
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| unknown())?
    }
}
