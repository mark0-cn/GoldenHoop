use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::CleanupState;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeLanguage {
    #[default]
    Python,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeContextSpec {
    #[serde(default)]
    pub language: CodeLanguage,
    #[serde(default = "cwd")]
    pub cwd: String,
}
fn cwd() -> String {
    "/workspace".into()
}
impl Default for CodeContextSpec {
    fn default() -> Self {
        Self {
            language: CodeLanguage::Python,
            cwd: cwd(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeContextState {
    Starting,
    Ready,
    Closing,
    Closed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CodeContext {
    pub id: Uuid,
    pub sandbox_id: Uuid,
    pub spec: CodeContextSpec,
    pub state: CodeContextState,
    pub cleanup: CleanupState,
    pub created_at: DateTime<Utc>,
    pub ready_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub kernel_info: Option<serde_json::Value>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunSpec {
    pub code: String,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "output_limit")]
    pub max_output_bytes: u64,
}
fn timeout() -> u64 {
    60
}
fn output_limit() -> u64 {
    1024 * 1024
}
impl CodeRunSpec {
    pub fn new(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            timeout_seconds: timeout(),
            max_output_bytes: output_limit(),
        }
    }
}

/// These are kernel observations, with no OS process-exit or correctness claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeRunState {
    Pending,
    Running,
    KernelSucceeded,
    KernelFailed,
    Cancelled,
    TimedOut,
    Unknown,
}
impl CodeRunState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::KernelSucceeded | Self::KernelFailed | Self::Cancelled | Self::TimedOut
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CodeRun {
    pub id: Uuid,
    pub context_id: Uuid,
    pub state: CodeRunState,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub output_truncated: bool,
    /// Matching execute-reply plus IOPub idle, not an OS exit code.
    pub kernel_status: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CodeContextEventKind {
    Ready,
    RunStarted,
    Stdout,
    Stderr,
    Result,
    Display,
    KernelError,
    OutputTruncated,
    RunCompleted,
    Diagnostic,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CodeContextEvent {
    pub sequence: u64,
    pub context_id: Uuid,
    pub run_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub kind: CodeContextEventKind,
    pub data: serde_json::Value,
}
