//! Read-only host discovery plans, distinct from a positive native controller.
use crate::{
    Allocation, COLLECTION_SECONDS, ControllerPlan, ControllerPurpose, NetworkIdentity, error,
};
use chrono::{DateTime, Utc};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbePurpose {
    Discover,
    ObserveAbsence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPurpose {
    Enforce,
    Collect,
    Discover,
    ObserveAbsence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbePlan {
    pub purpose: ProbePurpose,
    pub identity: NetworkIdentity,
    pub network_id: Option<String>,
    pub provisioning_token: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub image_id: String,
    pub controller_generation: Uuid,
    pub collection_deadline: Option<DateTime<Utc>>,
}
fn physical_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
impl ProbePlan {
    pub fn validate(&self) -> Result<(), ApiError> {
        self.identity.validate()?;
        if self.controller_generation.is_nil()
            || !self
                .image_id
                .strip_prefix("sha256:")
                .is_some_and(physical_id)
            || self
                .network_id
                .as_deref()
                .is_some_and(|id| !physical_id(id))
            || self.provisioning_token.is_some_and(|id| id.is_nil())
            || (self.purpose == ProbePurpose::Discover
                && (self.network_id.is_none() || self.provisioning_token.is_none()))
            || (self.purpose == ProbePurpose::ObserveAbsence) != self.collection_deadline.is_some()
        {
            return Err(error(
                ErrorCode::InvalidRequest,
                "invalid native probe plan",
            ));
        }
        Ok(())
    }
    pub fn dispatch_deadline(&self) -> DateTime<Utc> {
        self.collection_deadline.unwrap_or(self.expires_at)
    }
    pub fn validate_dispatch_at(&self, now: DateTime<Utc>) -> Result<(), ApiError> {
        self.validate()?;
        let remaining = self.dispatch_deadline().signed_duration_since(now);
        if remaining <= chrono::Duration::zero()
            || (self.purpose == ProbePurpose::ObserveAbsence
                && remaining > chrono::Duration::seconds(COLLECTION_SECONDS))
        {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "native probe dispatch expired",
            ));
        }
        Ok(())
    }
    pub fn name(&self) -> String {
        format!(
            "goldenhoop-probe-{}-{}",
            self.identity.generation.simple(),
            self.controller_generation.simple()
        )
    }
    pub fn digest(&self) -> String {
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).expect("probe plan"))
        )
    }
}

/// Untagged native serialization preserves historical journal bytes. Probe
/// plans cannot be interpreted as controllers with a missing/fake ifindex.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HostProcessPlan {
    Controller(ControllerPlan),
    Probe(ProbePlan),
}
impl From<ControllerPlan> for HostProcessPlan {
    fn from(plan: ControllerPlan) -> Self {
        Self::Controller(plan)
    }
}
impl From<ProbePlan> for HostProcessPlan {
    fn from(plan: ProbePlan) -> Self {
        Self::Probe(plan)
    }
}
impl HostProcessPlan {
    pub fn name(&self) -> String {
        match self {
            Self::Controller(p) => p.name(),
            Self::Probe(p) => p.name(),
        }
    }
    pub fn controller(&self) -> Result<&ControllerPlan, ApiError> {
        match self {
            Self::Controller(p) => Ok(p),
            Self::Probe(_) => Err(error(
                ErrorCode::InvalidState,
                "a native probe is not an enforcement controller",
            )),
        }
    }
    pub fn identity(&self) -> &NetworkIdentity {
        match self {
            Self::Controller(p) => &p.native.identity,
            Self::Probe(p) => &p.identity,
        }
    }
    pub fn image_id(&self) -> &str {
        match self {
            Self::Controller(p) => &p.image_id,
            Self::Probe(p) => &p.image_id,
        }
    }
    pub fn generation(&self) -> Option<Uuid> {
        match self {
            Self::Controller(p) => p.controller_generation,
            Self::Probe(p) => Some(p.controller_generation),
        }
    }
    pub fn expires_at(&self) -> DateTime<Utc> {
        match self {
            Self::Controller(p) => p.native.expires_at,
            Self::Probe(p) => p.expires_at,
        }
    }
    pub fn purpose(&self) -> HostPurpose {
        match self {
            Self::Controller(p) => match p.purpose {
                ControllerPurpose::Enforce => HostPurpose::Enforce,
                ControllerPurpose::Collect => HostPurpose::Collect,
            },
            Self::Probe(p) => match p.purpose {
                ProbePurpose::Discover => HostPurpose::Discover,
                ProbePurpose::ObserveAbsence => HostPurpose::ObserveAbsence,
            },
        }
    }
    pub fn validate(&self) -> Result<(), ApiError> {
        match self {
            Self::Controller(p) => p.validate(),
            Self::Probe(p) => p.validate(),
        }
    }
    pub fn validate_dispatch_at(&self, now: DateTime<Utc>) -> Result<(), ApiError> {
        match self {
            Self::Controller(p) => p.validate_dispatch_at(now),
            Self::Probe(p) => p.validate_dispatch_at(now),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProbe {
    pub plan_sha256: String,
    pub allocation: Allocation,
    pub ipv4_gateway: std::net::Ipv4Addr,
    pub ipv6_gateway: std::net::Ipv6Addr,
    pub alias: String,
    pub observed_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeAbsence {
    pub plan_sha256: String,
    pub bridge_absent: bool,
    pub owned_tables_absent: bool,
    pub observed_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "observation",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProbeObservation {
    Native(NativeProbe),
    Absence(ProbeAbsence),
}
impl ProbeObservation {
    pub fn validate(&self, plan: &ProbePlan) -> Result<(), ApiError> {
        plan.validate()?;
        match (self, plan.purpose) {
            (Self::Native(v), ProbePurpose::Discover) => {
                v.allocation.validate()?;
                if v.plan_sha256 != plan.digest()
                    || v.allocation.installation_id != plan.identity.installation_id
                    || v.allocation.sandbox_id != plan.identity.sandbox_id
                    || v.allocation.generation != plan.identity.generation
                    || v.allocation.bridge != plan.identity.bridge_name()
                    || (!v.alias.is_empty() && v.alias != v.allocation.owner())
                    || v.ipv4_gateway.is_unspecified()
                    || v.ipv4_gateway.is_loopback()
                    || v.ipv4_gateway.is_multicast()
                    || v.ipv4_gateway.is_broadcast()
                    || v.ipv6_gateway.is_unspecified()
                    || v.ipv6_gateway.is_loopback()
                    || v.ipv6_gateway.is_multicast()
                    || v.ipv6_gateway.is_unicast_link_local()
                    || v.ipv6_gateway.to_ipv4_mapped().is_some()
                {
                    return Err(error(
                        ErrorCode::Conflict,
                        "native probe observation differs",
                    ));
                }
            }
            (Self::Absence(v), ProbePurpose::ObserveAbsence) if v.plan_sha256 == plan.digest() => {}
            _ => return Err(error(ErrorCode::Conflict, "native probe purpose differs")),
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::observe_probe;
