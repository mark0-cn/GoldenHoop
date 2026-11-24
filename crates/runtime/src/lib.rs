//! Provisioning boundary. Command/file behavior is shared through the sandbox agent.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use goldenhoop_protocol::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeHandle {
    pub sandbox_id: Uuid,
    pub profile: String,
    pub backend_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedState {
    Starting,
    Running,
    Paused,
    Exited,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeObservation {
    pub state: ObservedState,
    pub exit_code: Option<i64>,
    pub observed_at: DateTime<Utc>,
}

#[async_trait]
pub trait RuntimeDriver: Send + Sync {
    /// Inspect actual runtime and host; do not report configured intent as support.
    async fn probe(&self) -> RuntimeProfile;
    async fn create(
        &self,
        sandbox: &Sandbox,
        request: &CreateSandbox,
    ) -> Result<RuntimeHandle, ApiError>;
    async fn inspect(&self, handle: &RuntimeHandle) -> Result<RuntimeObservation, ApiError>;
    /// Return only after the runtime confirms the owned resource is absent.
    async fn remove(&self, handle: &RuntimeHandle) -> Result<(), ApiError>;
    /// Recover only resources bearing this installation's ownership label.
    async fn discover(&self) -> Result<Vec<RuntimeHandle>, ApiError>;

    async fn pause(&self, _handle: &RuntimeHandle) -> Result<(), ApiError> {
        Err(ApiError::new(
            ErrorCode::UnsupportedCapability,
            "pause is not implemented by this driver",
        ))
    }
    async fn resume(&self, _handle: &RuntimeHandle) -> Result<(), ApiError> {
        Err(ApiError::new(
            ErrorCode::UnsupportedCapability,
            "resume is not implemented by this driver",
        ))
    }
}

/// The worker's private transport, never a public workload-controlled endpoint.
#[async_trait]
pub trait AgentTransport: Send + Sync {
    async fn rpc(
        &self,
        handle: &RuntimeHandle,
        request: &AgentRequest,
    ) -> Result<AgentResponse, ApiError>;
}

pub trait SandboxRuntime: RuntimeDriver + AgentTransport {}
impl<T: RuntimeDriver + AgentTransport> SandboxRuntime for T {}
