//! Durable native ownership. A separate Rust supervisor owns each VMM so worker
//! death neither breaks its console pipes nor suspends absolute expiry.
pub(crate) mod cgroup;
mod descriptor;
mod driver;
mod image;
pub use image::PreparedImagePolicy;
pub use image::inherited_input;
mod manager;
mod metadata;
pub(crate) use metadata::atomic_json;
pub(crate) mod reaper;
pub(crate) mod recovery;
pub(crate) mod root;
mod supervisor;
#[cfg(test)]
mod tests;
pub use manager::{FirecrackerDriver, run_manager};
pub use supervisor::{run_supervisor, run_supervisor_with_input};

use crate::machine::{Artifact, BootInput, ProcessObservation, digest, trusted_file};
use chrono::{DateTime, Utc};
use goldenhoop_protocol::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub const PROFILE: &str = "local-firecracker";
pub(crate) const MIB: u64 = 1024 * 1024;
pub(crate) type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCapacity {
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub max_vms: u32,
}
impl Default for HostCapacity {
    fn default() -> Self {
        Self {
            cpu_millis: 4000,
            memory_bytes: 6 * 1024 * MIB,
            max_vms: 8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriverConfig {
    pub installation_id: Uuid,
    pub data_root: PathBuf,
    pub artifacts: BootInput,
    pub supervisor: Artifact,
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_images: Option<PreparedImagePolicy>,
    pub max_resources: ResourceLimits,
    #[serde(default)]
    pub capacity: HostCapacity,
    pub max_ttl_seconds: u64,
}
impl DriverConfig {
    pub fn read(path: &Path) -> Result<Self> {
        let cfg: Self = read_json(path)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.installation_id.is_nil()
            || !self.data_root.is_absolute()
            || self.data_root.components().any(|p| {
                matches!(
                    p,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || self.image != format!("sha256:{}", self.artifacts.rootfs.sha256)
            || self.max_resources.cpu_millis == 0
            || self.max_resources.cpu_millis > 8000
            || self.max_resources.memory_bytes < 128 * MIB
            || self.max_resources.memory_bytes > 16 * 1024 * MIB
            || !self.max_resources.memory_bytes.is_multiple_of(MIB)
            || !(16..=65535).contains(&self.max_resources.pids)
            || self.max_ttl_seconds == 0
            || self.max_ttl_seconds > 86400
            || self.capacity.cpu_millis == 0
            || self.capacity.memory_bytes < 384 * MIB + manager::MANAGER_MEMORY
            || self.capacity.max_vms == 0
            || self.capacity.max_vms > 128
        {
            return Err(invalid("invalid native driver configuration").into());
        }
        self.paths(Uuid::new_v4())?;
        if let Some(policy) = &self.prepared_images {
            policy.validate()?;
            if policy.disk_budget_bytes < self.artifacts.rootfs.size {
                return Err(invalid("native disk budget is smaller than its fixed image").into());
            }
        }
        Ok(())
    }
    pub(crate) fn paths(&self, generation: Uuid) -> Result<VmPaths> {
        let root = self
            .data_root
            .join("vm")
            .join(&generation.simple().to_string()[..12]);
        let jail = root
            .join("j/firecracker")
            .join(generation.to_string())
            .join("root");
        for path in [
            jail.join("api.sock"),
            jail.join("vsock.sock"),
            root.join("control.sock"),
        ] {
            std::os::unix::net::SocketAddr::from_pathname(&path)
                .map_err(|_| invalid("native data root exceeds Unix socket path limit"))?;
        }
        let suffix = format!("{}-{}", self.installation_id.simple(), generation.simple());
        Ok(VmPaths {
            root,
            jail,
            vm_cgroup: Path::new("/sys/fs/cgroup").join(format!("ghv-{suffix}")),
            supervisor_cgroup: Path::new("/sys/fs/cgroup").join(format!("ghs-{suffix}")),
        })
    }
    pub(crate) fn record_path(&self, id: Uuid) -> PathBuf {
        self.data_root.join("records").join(format!("{id}.json"))
    }
}

pub(crate) struct VmPaths {
    pub root: PathBuf,
    pub jail: PathBuf,
    pub vm_cgroup: PathBuf,
    pub supervisor_cgroup: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessIdentity {
    pub pid: u32,
    pub start_ticks: u64,
    pub boot_id: String,
    pub executable_sha256: String,
    pub uid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct VmOwner {
    pub installation_id: Uuid,
    pub sandbox_id: Uuid,
    pub generation: Uuid,
    pub request_sha256: String,
    pub expires_at: DateTime<Utc>,
    pub host_boot_id: String,
    pub boot_deadline_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VmJournal {
    pub format: u32,
    pub owner: VmOwner,
    pub artifacts: BootInput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_image: Option<goldenhoop_images::ReadyImageInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_probe_context_sha256: Option<String>,
    pub resources: ResourceLimits,
    pub supervisor: Option<ProcessIdentity>,
    #[serde(default)]
    pub supervisor_cgroup_identity: Option<recovery::PathIdentity>,
    #[serde(default)]
    pub vm_cgroup_identity: Option<recovery::PathIdentity>,
    #[serde(default)]
    pub vm_root: Option<root::Receipt>,
    #[serde(default)]
    pub root_collection_started: bool,
    pub supervisor_artifact: Artifact,
    pub original_cgroup: PathBuf,
    pub process: Option<ProcessObservation>,
    pub phase: String,
    pub ever_ready: bool,
    pub error: Option<String>,
    #[serde(default)]
    pub console_tail: String,
    #[serde(default)]
    pub supervisor_stderr_tail: String,
    #[serde(default)]
    pub supervisor_cgroup_events: std::collections::BTreeMap<String, String>,
}

impl VmJournal {
    pub fn expired(&self) -> Result<bool> {
        Ok(self.owner.host_boot_id != boot_id()?
            || self.owner.expires_at <= Utc::now()
            || self.owner.boot_deadline_ns <= boottime_ns()?)
    }
    pub fn validate(&self, cfg: &DriverConfig, id: Uuid) -> Result<()> {
        if self.format != 1
            || self.owner.installation_id != cfg.installation_id
            || self.owner.sandbox_id != id
            || self.owner.generation.is_nil()
            || self.owner.request_sha256.len() != 64
            || self.root_collection_started && self.vm_root.is_none()
            || self
                .profile_probe_context_sha256
                .as_ref()
                .is_some_and(|sha| {
                    sha.len() != 64
                        || !sha
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        || self.phase != "collected"
                        || !self.ever_ready
                        || self.process.is_none()
                        || self.error.is_some()
                })
            || ![
                "reserved",
                "preparing",
                "launch_intent",
                "tracked",
                "running",
                "paused",
                "collecting",
                "vm_collected",
                "collected",
                "unknown",
            ]
            .contains(&self.phase.as_str())
        {
            return Err(invalid("native ownership journal mismatch").into());
        }
        validate_resources(
            &self.resources,
            &ResourceLimits {
                cpu_millis: 8000,
                memory_bytes: 16 * 1024 * MIB,
                pids: 65535,
            },
        )?;
        cfg.paths(self.owner.generation)?;
        cfg.validate_journal_image(self)?;
        Ok(())
    }
}

pub(crate) fn validate_resources(value: &ResourceLimits, max: &ResourceLimits) -> Result<()> {
    if value.cpu_millis == 0
        || value.cpu_millis > max.cpu_millis
        || value.memory_bytes < 128 * MIB
        || value.memory_bytes > max.memory_bytes
        || !value.memory_bytes.is_multiple_of(MIB)
        || !(16..=max.pids).contains(&value.pids)
    {
        return Err(
            invalid("native resources exceed configured bounds or memory MiB granularity").into(),
        );
    }
    Ok(())
}

pub(crate) fn boot_id() -> io::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into())
}
pub(crate) fn boottime_ns() -> io::Result<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    (value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| invalid("host clock overflow"))
}
pub(crate) fn process_identity(pid: u32) -> Result<ProcessIdentity> {
    if pid <= 1 || pid > i32::MAX as u32 {
        return Err(invalid("invalid process identity").into());
    }
    let root = Path::new("/proc").join(pid.to_string());
    let stat = std::fs::read_to_string(root.join("stat"))?;
    let ticks = stat
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .ok_or_else(|| invalid("invalid process stat"))?
        .parse()?;
    let status = std::fs::read_to_string(root.join("status"))?;
    let ids: Vec<_> = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or_else(|| invalid("missing process UIDs"))?
        .split_whitespace()
        .collect();
    if ids.len() != 4 || ids.iter().any(|id| *id != ids[0]) {
        return Err(invalid("process UIDs differ").into());
    }
    let identity = ProcessIdentity {
        pid,
        start_ticks: ticks,
        boot_id: boot_id()?,
        executable_sha256: digest(File::open(root.join("exe"))?)?.0,
        uid: ids[0].parse()?,
    };
    let after = std::fs::read_to_string(root.join("stat"))?;
    if after
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .and_then(|v| v.parse::<u64>().ok())
        != Some(ticks)
    {
        return Err(invalid("process changed during authentication").into());
    }
    Ok(identity)
}
pub(crate) fn track_process(expected: &ProcessIdentity) -> Result<OwnedFd> {
    if expected.boot_id != boot_id()? {
        return Err(invalid("process belongs to another host boot").into());
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, expected.pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    if process_identity(expected.pid)? != *expected {
        return Err(invalid("tracked process identity mismatch").into());
    }
    Ok(fd)
}
pub(crate) fn pidfd_exited(fd: &OwnedFd) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut p, 1, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result > 0 && p.revents & libc::POLLIN != 0)
}

pub(crate) fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = trusted_file(path)?;
    if file.metadata()?.len() > 65536 {
        return Err(invalid("private metadata exceeds limit").into());
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(invalid("private metadata exceeds limit").into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn private_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("missing private directory parent"))?;
    let mut ancestor = Some(parent);
    while let Some(path) = ancestor {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(invalid("untrusted private directory ancestor").into());
        }
        ancestor = path.parent();
    }
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(invalid("private directory ownership mismatch").into());
    }
    Ok(())
}

pub(crate) fn request_digest(value: &CreateSandbox) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SupervisorOperation {
    Status,
    Pause,
    Resume,
    Stop,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SupervisorCall {
    pub owner: VmOwner,
    pub operation: SupervisorOperation,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SupervisorReply {
    pub generation: Uuid,
    pub state: goldenhoop_runtime::ObservedState,
    pub error: Option<ApiError>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum DriverCall {
    Probe,
    Create {
        sandbox: Sandbox,
        request: CreateSandbox,
    },
    Inspect {
        handle: goldenhoop_runtime::RuntimeHandle,
    },
    Remove {
        handle: goldenhoop_runtime::RuntimeHandle,
    },
    Discover,
    Pause {
        handle: goldenhoop_runtime::RuntimeHandle,
    },
    Resume {
        handle: goldenhoop_runtime::RuntimeHandle,
    },
    Rpc {
        handle: goldenhoop_runtime::RuntimeHandle,
        request: AgentRequest,
    },
    Reap,
}

/// Operator/test CLI for the actual RuntimeDriver and AgentTransport traits.
/// Public worker registration remains a separate integration step.
pub async fn run_driver_call(config: PathBuf, request: PathBuf) -> Result<serde_json::Value> {
    use goldenhoop_runtime::{AgentTransport, RuntimeDriver};
    let cfg: DriverConfig = read_json(&config)?;
    let request: DriverCall = read_json(&request)?;
    let driver = FirecrackerDriver::connect(cfg)?;
    let operation = async {
        Ok::<_, ApiError>(match request {
            DriverCall::Probe => serde_json::to_value(driver.probe().await)
                .map_err(|_| ApiError::new(ErrorCode::Internal, "cannot encode native profile"))?,
            DriverCall::Create { sandbox, request } => {
                serde_json::to_value(driver.create(&sandbox, &request).await?).unwrap()
            }
            DriverCall::Inspect { handle } => {
                serde_json::to_value(driver.inspect(&handle).await?).unwrap()
            }
            DriverCall::Remove { handle } => {
                driver.remove(&handle).await?;
                serde_json::Value::Null
            }
            DriverCall::Discover => serde_json::to_value(driver.discover().await?).unwrap(),
            DriverCall::Pause { handle } => {
                driver.pause(&handle).await?;
                serde_json::Value::Null
            }
            DriverCall::Resume { handle } => {
                driver.resume(&handle).await?;
                serde_json::Value::Null
            }
            DriverCall::Rpc { handle, request } => {
                serde_json::to_value(driver.rpc_reply(&handle, &request).await?).unwrap()
            }
            DriverCall::Reap => serde_json::to_value(driver.reap_expired().await?).unwrap(),
        })
    };
    Ok(match operation.await {
        Ok(data) => serde_json::json!({"ok":true,"data":data}),
        Err(error) => serde_json::json!({"ok":false,"error":error}),
    })
}
