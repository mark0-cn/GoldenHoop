use crate::{Capability, NetworkPolicy, Operation, ResourceLimits, Sandbox};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateIsolatedSession {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default)]
    pub resources: ResourceLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default)]
    pub required_capabilities: BTreeSet<Capability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_budget: Option<ResourceLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feature_limit: Option<BTreeSet<Capability>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkPolicy>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SandboxScope {
    pub sandbox_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub root_id: Uuid,
    pub depth: u8,
    pub child_budget: Option<ResourceLimits>,
    /// Immutable workload resources plus additional child reservation.
    pub envelope: ResourceLimits,
    /// Logical allocations held by uncollected children, not measured runtime use.
    pub allocated_to_children: ResourceLimits,
    pub feature_limit: Option<BTreeSet<Capability>>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IsolatedSessionCreated {
    pub sandbox: Sandbox,
    pub scope: SandboxScope,
    pub operation: Operation,
}
