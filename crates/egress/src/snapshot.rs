//! Select the four owned tables from one bounded native ruleset observation.
//! Foreign tables confer no authority and are never included in a receipt.
use crate::{Allocation, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
pub struct ScopedKernelSnapshot {
    tables: BTreeMap<String, Value>,
}

impl ScopedKernelSnapshot {
    pub fn parse(allocation: &Allocation, bytes: &[u8]) -> Result<Self, ApiError> {
        Self::parse_inner(allocation, bytes, true)
    }
    /// Attachment/collection may legitimately have absent tables. This path
    /// proves absence only from a successful complete native inventory; it
    /// does not relax the fully protected snapshot contract above.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn inventory(allocation: &Allocation, bytes: &[u8]) -> Result<Self, ApiError> {
        Self::parse_inner(allocation, bytes, false)
    }
    fn parse_inner(
        allocation: &Allocation,
        bytes: &[u8],
        complete: bool,
    ) -> Result<Self, ApiError> {
        allocation.validate()?;
        let bad = || {
            error(
                ErrorCode::Conflict,
                "scoped native snapshot is incomplete or ambiguous",
            )
        };
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "native ruleset observation exceeds limit",
            ));
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|_| bad())?;
        let entries = value
            .as_object()
            .filter(|v| v.len() == 1)
            .and_then(|v| v.get("nftables"))
            .and_then(Value::as_array)
            .ok_or_else(bad)?;
        let required = BTreeMap::from([
            (allocation.table(), "inet"),
            (allocation.ethernet_table(), "bridge"),
            (allocation.source_table(), "bridge"),
            (allocation.destination_table(), "inet"),
        ]);
        let mut expected = required.clone();
        expected.insert(allocation.credential_table(), "inet");
        let mut tables: BTreeMap<String, Vec<Value>> = expected
            .keys()
            .map(|name| (name.clone(), Vec::new()))
            .collect();
        let mut counts = BTreeMap::<String, u32>::new();
        for entry in entries {
            let object = entry.as_object().filter(|v| v.len() == 1).ok_or_else(bad)?;
            let (kind, body) = object.iter().next().ok_or_else(bad)?;
            if kind == "metainfo" {
                continue;
            }
            let family = body.get("family").and_then(Value::as_str).ok_or_else(bad)?;
            let name = body
                .get(if kind == "table" { "name" } else { "table" })
                .and_then(Value::as_str)
                .ok_or_else(bad)?;
            let Some(required_family) = expected.get(name) else {
                continue;
            };
            if family != *required_family {
                return Err(bad());
            }
            if kind == "table" {
                *counts.entry(name.to_owned()).or_default() += 1;
            }
            tables.get_mut(name).ok_or_else(bad)?.push(entry.clone());
        }
        if (complete && required.keys().any(|name| counts.get(name) != Some(&1)))
            || tables
                .iter()
                .any(|(name, entries)| !entries.is_empty() && counts.get(name) != Some(&1))
            || counts.values().any(|count| *count != 1)
        {
            return Err(bad());
        }
        Ok(Self {
            tables: tables
                .into_iter()
                .filter(|(_, entries)| !entries.is_empty())
                .map(|(name, entries)| (name, json!({"nftables":entries})))
                .collect(),
        })
    }
    pub fn table(&self, name: &str) -> Result<&Value, ApiError> {
        self.tables
            .get(name)
            .ok_or_else(|| error(ErrorCode::Conflict, "required scoped table is absent"))
    }
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn observed_table(&self, name: &str) -> Option<&Value> {
        self.tables.get(name)
    }
}

#[cfg(test)]
mod inventory_tests {
    use super::*;

    fn allocation() -> Allocation {
        Allocation {
            installation_id: uuid::Uuid::new_v4(),
            sandbox_id: uuid::Uuid::new_v4(),
            generation: uuid::Uuid::new_v4(),
            bridge: "ghsnapshot".into(),
            ifindex: 1,
        }
    }

    #[test]
    fn successful_foreign_inventory_proves_only_owned_absence() {
        let a = allocation();
        let bytes =
            serde_json::to_vec(&json!({"nftables":[{"table":{"family":"inet","name":"foreign"}}]}))
                .unwrap();
        let observed = ScopedKernelSnapshot::inventory(&a, &bytes).unwrap();
        assert!(observed.observed_table(&a.table()).is_none());
        assert!(ScopedKernelSnapshot::parse(&a, &bytes).is_err());
        assert!(ScopedKernelSnapshot::inventory(&a, b"{}").is_err());
    }

    #[test]
    fn partial_attachment_inventory_is_never_a_protected_snapshot() {
        let a = allocation();
        let bytes =
            serde_json::to_vec(&json!({"nftables":[{"table":{"family":"inet","name":a.table()}}]}))
                .unwrap();
        let observed = ScopedKernelSnapshot::inventory(&a, &bytes).unwrap();
        assert!(observed.observed_table(&a.table()).is_some());
        assert!(observed.observed_table(&a.source_table()).is_none());
        assert!(ScopedKernelSnapshot::parse(&a, &bytes).is_err());
    }

    #[test]
    fn ambiguous_or_unanchored_inventory_cannot_confirm_absence() {
        let a = allocation();
        for entries in [
            json!([{"table":{"family":"inet","name":a.table()}},{"table":{"family":"inet","name":a.table()}}]),
            json!([{"chain":{"family":"inet","table":a.table(),"name":"orphan"}}]),
            json!([{"table":{"family":"bridge","name":a.table()}}]),
        ] {
            assert!(
                ScopedKernelSnapshot::inventory(
                    &a,
                    &serde_json::to_vec(&json!({"nftables":entries})).unwrap()
                )
                .is_err()
            );
        }
    }
}
