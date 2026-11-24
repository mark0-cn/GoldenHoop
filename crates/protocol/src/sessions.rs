use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{ApiError, CommandSpec, Execution};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Session {
    pub execution: Execution,
    pub spec: SessionSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SessionPage {
    pub items: Vec<Session>,
    pub next_after: Option<Uuid>,
}

/// An actual long-lived process. A terminal merges stdout and stderr.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionSpec {
    pub command: CommandSpec,
    #[serde(default)]
    pub terminal: Option<TerminalSize>,
}

impl SessionSpec {
    pub fn shell() -> Self {
        Self {
            command: CommandSpec::new(["/bin/sh"]),
            terminal: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TerminalSize {
    pub rows: u16,
    pub columns: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionControl {
    pub sequence: u64,
    pub action: SessionAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionAction {
    Write { data_base64: String },
    CloseInput,
    Resize { size: TerminalSize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionControlState {
    Pending,
    Applied,
    Rejected,
    Unknown,
}

/// Applied acknowledges delivery to the process/terminal, not code success.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SessionControlReceipt {
    pub execution_id: Uuid,
    pub sequence: u64,
    pub state: SessionControlState,
    pub observed_at: DateTime<Utc>,
    pub error: Option<ApiError>,
}
