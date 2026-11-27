//! Public snapshot resources; backend references remain private worker state.
use crate::{ApiError, CleanupState, Operation, SnapshotKind, SnapshotManifest};
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
