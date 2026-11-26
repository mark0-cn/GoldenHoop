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
        if required.keys().any(|name| counts.get(name) != Some(&1))
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
}
