//! Private worker/backend observations. These types are not public API payloads.
use crate::RuntimeHandle;
use chrono::{DateTime, Utc};
use goldenhoop_protocol::{ApiError, ErrorCode, Sandbox, SnapshotManifest};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct MemoryCaptureRequest {
    pub id: Uuid,
    pub source: Sandbox,
    pub handle: RuntimeHandle,
    pub created_at: DateTime<Utc>,
}
impl MemoryCaptureRequest {
    pub fn validate_identity(&self) -> Result<(), ApiError> {
        if self.id.is_nil()
            || self.source.id.is_nil()
            || self.source.id != self.handle.sandbox_id
            || self.source.profile != self.handle.profile
            || self.handle.backend_ref.is_empty()
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "memory capture request differs from its original source identity",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MemoryCaptureObservation {
    pub id: Uuid,
    pub source: RuntimeHandle,
    pub state: MemoryCaptureState,
}

#[derive(Debug, Clone)]
pub enum MemoryCaptureState {
    Pending,
    Ready {
        manifest: Box<SnapshotManifest>,
        reference: serde_json::Value,
    },
    /// A durable backend capture failed. This is not a collection receipt.
    Failed(ApiError),
    /// Positive backend object/quota collection, bound to the original source.
    Collected,
}
