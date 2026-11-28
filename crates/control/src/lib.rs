//! Authenticated public API and separately supervised runtime worker.
pub mod api;
pub mod host_process;
pub mod http;
pub mod security;
pub mod worker;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalFileCall {
    pub sandbox_id: uuid::Uuid,
    pub request: goldenhoop_protocol::AgentRequest,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalSandboxCall {
    pub sandbox_id: uuid::Uuid,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalSnapshotCall {
    pub sandbox_id: uuid::Uuid,
    pub request: goldenhoop_protocol::CreateSnapshot,
    pub idempotency_key: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalRestoreCall {
    pub snapshot_id: uuid::Uuid,
    pub request: goldenhoop_protocol::RestoreSnapshot,
    pub idempotency_key: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalArtifactCall {
    pub artifact_id: uuid::Uuid,
}
