//! Portable identity for a trusted controller process, separate from its network.
use crate::{error, native::NativeBridgePlan};
use chrono::{DateTime, Utc};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerPurpose {
    #[default]
    Enforce,
    Collect,
}
impl ControllerPurpose {
    pub fn is_enforcement(&self) -> bool {
        *self == Self::Enforce
    }
}
pub const COLLECTION_SECONDS: i64 = 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerPlan {
    pub native: NativeBridgePlan,
    pub image_id: String,
    /// Missing only in historical metadata, which is accepted for collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_generation: Option<Uuid>,
    #[serde(default, skip_serializing_if = "ControllerPurpose::is_enforcement")]
    pub purpose: ControllerPurpose,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_deadline: Option<DateTime<Utc>>,
}
impl ControllerPlan {
    pub fn validate(&self) -> Result<(), ApiError> {
        self.native.validate()?;
        if self.controller_generation.is_some_and(|g| g.is_nil())
            || (self.purpose == ControllerPurpose::Collect) != (self.collection_deadline.is_some())
            || (self.purpose == ControllerPurpose::Collect && self.controller_generation.is_none())
            || !self.image_id.strip_prefix("sha256:").is_some_and(|id| {
                id.len() == 64
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(error(
                ErrorCode::InvalidRequest,
                "invalid controller process identity",
            ));
        }
        Ok(())
    }
    pub fn validate_dispatch_at(&self, now: DateTime<Utc>) -> Result<(), ApiError> {
        self.validate()?;
        if self.controller_generation.is_none() {
            return Err(error(
                ErrorCode::InvalidState,
                "historical controller metadata permits collection only",
            ));
        }
        let remaining = self.dispatch_deadline()?.signed_duration_since(now);
        if remaining <= chrono::Duration::zero()
            || (self.purpose == ControllerPurpose::Collect
                && remaining > chrono::Duration::seconds(COLLECTION_SECONDS))
        {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "controller dispatch deadline is unavailable",
            ));
        }
        Ok(())
    }
    pub fn dispatch_deadline(&self) -> Result<DateTime<Utc>, ApiError> {
        match self.purpose {
            ControllerPurpose::Enforce => Ok(self.native.expires_at),
            ControllerPurpose::Collect => self
                .collection_deadline
                .ok_or_else(|| error(ErrorCode::InvalidRequest, "collection deadline is required")),
        }
    }
    pub fn name(&self) -> String {
        let base = format!(
            "goldenhoop-egress-{}",
            self.native.identity.generation.simple()
        );
        match self.controller_generation {
            Some(g) => format!("{base}-{}", g.simple()),
            None => base,
        }
    }
}
