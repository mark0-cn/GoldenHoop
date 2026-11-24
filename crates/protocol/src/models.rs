use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Commands,
    Files,
    ShellSessions,
    Pty,
    CodeContexts,
    IsolatedSessions,
    Pause,
    RootfsSnapshot,
    VolumeSnapshot,
    MemorySnapshot,
    NetworkIsolation,
    NetworkPolicy,
    SecretInjection,
    Gpu,
    Artifacts,
    Diagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Placement {
    Local,
    Kubernetes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    Oci,
    Gvisor,
    Kata,
    Firecracker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Unavailable,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub pids: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_millis: 1_000,
            memory_bytes: 1_073_741_824,
            pids: 256,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RuntimeProfile {
    pub id: String,
    pub placement: Placement,
    pub isolation: Isolation,
    pub availability: Availability,
    pub capabilities: BTreeSet<Capability>,
    pub max_resources: ResourceLimits,
    pub max_ttl_seconds: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAction {
    Deny,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    pub destination: String,
    pub ports: Vec<u16>,
    pub action: NetworkAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub default_action: NetworkAction,
    #[serde(default)]
    pub rules: Vec<NetworkRule>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            default_action: NetworkAction::Deny,
            rules: Vec::new(),
        }
    }
}

fn default_ttl() -> u64 {
    1_800
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateSandbox {
    pub profile: String,
    pub image: String,
    #[serde(default)]
    pub resources: ResourceLimits,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
    #[serde(default)]
    pub required_capabilities: BTreeSet<Capability>,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl CreateSandbox {
    pub fn new(profile: impl Into<String>, image: impl Into<String>) -> Self {
        Self {
            profile: profile.into(),
            image: image.into(),
            resources: ResourceLimits::default(),
            ttl_seconds: default_ttl(),
            required_capabilities: BTreeSet::new(),
            network: NetworkPolicy::default(),
            metadata: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    Pending,
    Starting,
    Running,
    Pausing,
    Paused,
    Resuming,
    Stopping,
    Terminated,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    NotRequired,
    Pending,
    Complete,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Sandbox {
    pub id: Uuid,
    pub profile: String,
    pub image: String,
    pub state: SandboxState,
    #[serde(default)]
    pub desired_state: DesiredState,
    pub cleanup: CleanupState,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub observed_at: Option<DateTime<Utc>>,
    pub resources: ResourceLimits,
    pub metadata: BTreeMap<String, String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DesiredState {
    #[default]
    Running,
    Paused,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SandboxCreated {
    pub sandbox: Sandbox,
    pub operation: Operation,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SandboxPage {
    pub items: Vec<Sandbox>,
    pub next_cursor: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteFile {
    pub path: String,
    pub data_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FileData {
    pub data_base64: String,
}

/// Host cgroup accounting, including runtime/supervisor overhead.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResourceUsage {
    pub sampled_at: DateTime<Utc>,
    pub cpu_time_ns: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub host_tasks: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RuntimeDiagnostics {
    pub sandbox_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub running: Option<bool>,
    pub paused: Option<bool>,
    pub exit_code: Option<i64>,
    pub oom_killed: Option<bool>,
    pub usage: Option<ResourceUsage>,
    pub usage_error: Option<crate::ApiError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SandboxDiagnostics {
    pub sandbox: Sandbox,
    /// None means the worker confirmed no owned runtime exists, not a zero sample.
    pub runtime: Option<RuntimeDiagnostics>,
}

fn default_cwd() -> String {
    "/workspace".into()
}
fn default_command_timeout() -> u64 {
    300
}
fn default_output_limit() -> u64 {
    4 * 1024 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub argv: Vec<String>,
    #[serde(default = "default_cwd")]
    pub cwd: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default = "default_command_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_output_limit")]
    pub max_output_bytes: u64,
}

impl CommandSpec {
    pub fn new(argv: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            cwd: default_cwd(),
            env: BTreeMap::new(),
            timeout_seconds: default_command_timeout(),
            max_output_bytes: default_output_limit(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Unknown,
}

impl ExecutionState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Execution {
    pub id: Uuid,
    pub sandbox_id: Uuid,
    pub state: ExecutionState,
    pub exit_code: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub output_truncated: bool,
    pub cleanup: CleanupState,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Started,
    Stdout,
    Stderr,
    OutputTruncated,
    Completed,
    Diagnostic,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExecutionEvent {
    pub sequence: u64,
    pub execution_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub kind: EventKind,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    Rootfs,
    Volumes,
    MemoryAndDisk,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SnapshotManifest {
    pub format_version: u32,
    pub id: Uuid,
    pub source_sandbox_id: Uuid,
    pub kind: SnapshotKind,
    pub driver: String,
    pub architecture: String,
    pub image_digest: String,
    pub objects: BTreeMap<String, String>,
    pub runtime_version: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Operation {
    pub id: Uuid,
    pub resource_id: Uuid,
    pub state: OperationState,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error: Option<crate::ApiError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl OperationState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}
