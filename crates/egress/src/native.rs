//! Native bridge identity carried over the trusted worker/controller channel.
use crate::{Allocation, NetworkIdentity, error};
use chrono::{DateTime, Utc};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The caller must first persist and validate the matching native checkpoint.
/// This value identifies a dispatch; it does not authenticate a journal by itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBridgePlan {
    pub identity: NetworkIdentity,
    pub allocation: Allocation,
    pub provisioning_token: Uuid,
    pub expires_at: DateTime<Utc>,
}

impl NativeBridgePlan {
    /// Identity checks also used while collecting an expired dispatch.
    pub fn validate(&self) -> Result<(), ApiError> {
        self.identity.validate()?;
        self.allocation.validate()?;
        if self.provisioning_token.is_nil()
            || self.allocation.installation_id != self.identity.installation_id
            || self.allocation.sandbox_id != self.identity.sandbox_id
            || self.allocation.generation != self.identity.generation
            || self.allocation.bridge != self.identity.bridge_name()
        {
            return Err(error(
                ErrorCode::InvalidRequest,
                "native bridge plan identity differs",
            ));
        }
        Ok(())
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), ApiError> {
        self.validate()?;
        if self.expires_at <= now {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "native bridge dispatch expired",
            ));
        }
        Ok(())
    }
}

/// Actual alias observation only; no packet, endpoint, DNS or lease attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBridgeObservation {
    pub identity_sha256: String,
    pub allocation: Allocation,
    pub provisioning_token: Uuid,
    pub alias: String,
    pub changed: bool,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::bind;
