//! Public snapshot resources; backend references remain private worker state.
use crate::{
    ApiError, CleanupState, CreateSandbox, Execution, Operation, Sandbox, SnapshotKind,
    SnapshotManifest,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateSnapshot {
    pub kind: SnapshotKind,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotState {
    Pending,
    Capturing,
    Ready,
    Failed,
    Unknown,
    Collecting,
    Collected,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Snapshot {
    pub id: Uuid,
    pub source_sandbox_id: Uuid,
    pub kind: SnapshotKind,
    pub state: SnapshotState,
    pub cleanup: CleanupState,
    pub created_at: DateTime<Utc>,
    pub observed_at: Option<DateTime<Utc>>,
    pub manifest: Option<SnapshotManifest>,
    pub error: Option<ApiError>,
}
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SnapshotCreated {
    pub snapshot: Snapshot,
    pub operation: Operation,
}
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SnapshotPage {
    pub items: Vec<Snapshot>,
    pub next_cursor: Option<Uuid>,
}

/// A memory continuation creates one new sandbox. It never reuses source authority.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RestoreSnapshot {
    pub target: CreateSandbox,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RestoredExecution {
    pub source_execution_id: Uuid,
    pub execution: Execution,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SnapshotRestored {
    pub snapshot_id: Uuid,
    pub sandbox: Sandbox,
    pub operation: Operation,
    /// New public IDs explicitly bound to retained agent executions, never Start.
    pub executions: Vec<RestoredExecution>,
}
