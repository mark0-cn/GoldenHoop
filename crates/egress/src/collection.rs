//! Actual host collection result, distinct from a policy or lease observation.
use crate::Allocation;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionReceipt {
    pub allocation: Allocation,
    pub bridge_absent: bool,
    pub owned_tables_absent: bool,
    pub observed_at: DateTime<Utc>,
}
