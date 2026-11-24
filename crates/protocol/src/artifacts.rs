use crate::{ApiError, CleanupState, Operation};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

fn default_name() -> String {
    "artifact.bin".into()
}
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateArtifact {
    pub path: String,
    #[serde(default = "default_name")]
    pub name: String,
}
impl CreateArtifact {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            name: default_name(),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactState {
    Pending,
    Uploading,
    Available,
    Failed,
    Deleting,
    Deleted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactDesiredState {
    Available,
    Deleted,
}
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Artifact {
    pub id: Uuid,
    pub sandbox_id: Uuid,
    pub name: String,
    pub source_path: String,
    pub state: ArtifactState,
    pub desired_state: ArtifactDesiredState,
    pub cleanup: CleanupState,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub created_at: DateTime<Utc>,
    pub observed_at: Option<DateTime<Utc>>,
    pub error: Option<ApiError>,
}
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ArtifactCreated {
    pub artifact: Artifact,
    pub operation: Operation,
}
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ArtifactPage {
    pub items: Vec<Artifact>,
    pub next_cursor: Option<Uuid>,
}
