//! Public security metadata. Verification digests and provider secrets are private.
use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPermission {
    Read,
    Write,
    Execute,
    Network,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyResources {
    All,
    Sandboxes(BTreeSet<Uuid>),
}

impl KeyResources {
    pub fn permits(&self, sandbox: Uuid) -> bool {
        match self {
            Self::All => true,
            Self::Sandboxes(ids) => ids.contains(&sandbox),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKey {
    pub permissions: BTreeSet<KeyPermission>,
    pub resources: KeyResources,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub permissions: BTreeSet<KeyPermission>,
    pub resources: KeyResources,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// The bearer token is returned once. No Debug implementation may print it.
#[derive(Serialize, Deserialize)]
pub struct ApiKeyIssued {
    pub key: ApiKey,
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditActor {
    Bootstrap,
    ApiKey,
    Anonymous,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Read,
    Write,
    Execute,
    Network,
    KeyCreate,
    KeyRevoke,
    AuditRead,
    Unknown,
    Sandbox,
    Operation,
    Execution,
    Context,
    CodeRun,
    Artifact,
    Credential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
    RequestStarted,
    AuthorizationDenied,
    HttpReturned,
    Observed,
    Created,
    Revoked,
    StreamRevoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub actor: AuditActor,
    pub key_id: Option<Uuid>,
    pub request_id: Option<Uuid>,
    pub target_id: Option<Uuid>,
    pub sandbox_id: Option<Uuid>,
    pub action: AuditAction,
    pub phase: AuditPhase,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    #[serde(flatten)]
    pub event: AuditEvent,
    /// Only trusted lifecycle enums and revision numbers, never error text.
    pub observation: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPage {
    pub items: Vec<AuditRecord>,
    pub next_after: Option<u64>,
    /// Freeze this bound on subsequent pages, including audit-read events.
    pub through_sequence: u64,
}
