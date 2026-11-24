//! Immutable route-only Ethernet floor for one trusted bridge allocation.
//! A workload cannot bypass the routed policy through another bridge port.
use crate::{Allocation, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const PRIORITY: i64 = -300;
const VERSION: &str = "guard_version_1";

impl Allocation {
    pub fn ethernet_table(&self) -> String {
        format!("gh_l_{}", self.generation.simple())
    }
}

pub struct EthernetPlan {
    batch: String,
}
impl EthernetPlan {
    pub fn new(allocation: &Allocation) -> Result<Self, ApiError> {
        allocation.validate()?;
        let table = allocation.ethernet_table();
        let owner = allocation.owner_chain();
        let bridge = &allocation.bridge;
        Ok(Self {
            batch: format!(
                "add table bridge {table}\n\
                 add chain bridge {table} {owner}\n\
                 add chain bridge {table} {VERSION}\n\
                 add chain bridge {table} input {{ type filter hook input priority {PRIORITY}; policy accept; }}\n\
                 add chain bridge {table} forward {{ type filter hook forward priority {PRIORITY}; policy accept; }}\n\
                 add rule bridge {table} input meta ibrname \"{bridge}\" ether type != {{ arp, ip, ip6 }} counter drop\n\
                 add rule bridge {table} forward meta ibrname \"{bridge}\" counter drop\n"
            ),
        })
    }

    pub fn script(&self) -> &str {
        &self.batch
    }

    /// Validate the actual scoped kernel table, including its complete rule
    /// shape. Handles and counters are observations, never policy identity.
    pub fn verify(allocation: &Allocation, observed: &Value) -> Result<(), ApiError> {
        allocation.validate()?;
        let bad = || error(ErrorCode::Conflict, "Ethernet guard observation differs");
        let entries = observed["nftables"].as_array().ok_or_else(bad)?;
        let table = allocation.ethernet_table();
        let owner = allocation.owner_chain();
        let mut tables = 0;
        let mut chains = BTreeSet::new();
        let mut rules = BTreeSet::new();
        for entry in entries {
            let object = entry.as_object().filter(|e| e.len() == 1).ok_or_else(bad)?;
            let (kind, value) = object.iter().next().ok_or_else(bad)?;
            if kind == "metainfo" {
                continue;
            }
            if value["family"] != "bridge" {
                return Err(bad());
            }
            if kind == "table" {
                if value["name"] != table {
                    return Err(bad());
                }
                tables += 1;
                continue;
            }
            if value["table"] != table {
                return Err(bad());
            }
            match kind.as_str() {
                "chain" => {
                    let name = value["name"].as_str().ok_or_else(bad)?;
                    if !chains.insert(name.to_owned()) {
                        return Err(bad());
                    }
                    if matches!(name, "input" | "forward") {
                        if value["type"] != "filter"
                            || value["hook"] != name
                            || value["prio"] != PRIORITY
                            || value["policy"] != "accept"
                        {
                            return Err(bad());
                        }
                    } else if (name != owner && name != VERSION)
                        || value.get("hook").is_some()
                        || value.get("type").is_some()
                    {
                        return Err(bad());
                    }
                }
                "rule" => {
                    let chain = value["chain"].as_str().ok_or_else(bad)?;
                    if !matches!(chain, "input" | "forward") || !rules.insert(chain.to_owned()) {
                        return Err(bad());
                    }
                    let mut expr = value["expr"].as_array().ok_or_else(bad)?.clone();
                    let counters = expr
                        .iter()
                        .filter_map(|e| e.get("counter"))
                        .collect::<Vec<_>>();
                    if counters.len() != 1
                        || counters[0]["packets"].as_u64().is_none()
                        || counters[0]["bytes"].as_u64().is_none()
                    {
                        return Err(bad());
                    }
                    // The counter is exactly the penultimate statement; extra
                    // verdicts/matches, including a hidden accept, must refuse.
                    if expr.len() < 2 || expr[expr.len() - 2].get("counter").is_none() {
                        return Err(bad());
                    }
                    if expr[expr.len() - 2]
                        .as_object()
                        .is_none_or(|e| e.len() != 1)
                    {
                        return Err(bad());
                    }
                    expr.remove(expr.len() - 2);
                    let mut expected = vec![
                        json!({"match":{"op":"==","left":{"meta":{"key":"ibrname"}},"right":allocation.bridge}}),
                    ];
                    if chain == "input" {
                        let types = expr
                            .get_mut(1)
                            .and_then(|e| e.get_mut("match"))
                            .and_then(|e| e.get_mut("right"))
                            .and_then(|e| e.get_mut("set"))
                            .and_then(Value::as_array_mut)
                            .ok_or_else(bad)?;
                        let mut normalized = Vec::new();
                        for kind in types.iter() {
                            normalized.push(match kind.as_str() {
                                Some("arp") => "arp",
                                Some("ip") => "ip",
                                Some("ip6") => "ip6",
                                _ => match kind.as_u64() {
                                    Some(2054) => "arp",
                                    Some(2048) => "ip",
                                    Some(34525) => "ip6",
                                    _ => return Err(bad()),
                                },
                            });
                        }
                        normalized.sort_unstable();
                        *types = normalized.into_iter().map(Value::from).collect();
                        expected.push(json!({"match":{"op":"!=","left":{"payload":{"protocol":"ether","field":"type"}},"right":{"set":["arp","ip","ip6"]}}}));
                    }
                    expected.push(json!({"drop":null}));
                    if expr != expected {
                        return Err(bad());
                    }
                }
                _ => return Err(bad()),
            }
        }
        if tables != 1
            || chains != BTreeSet::from([owner, VERSION.into(), "input".into(), "forward".into()])
            || rules != BTreeSet::from(["input".into(), "forward".into()])
        {
            return Err(bad());
        }
        Ok(())
    }
}
