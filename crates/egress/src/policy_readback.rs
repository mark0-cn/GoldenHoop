//! Exact policy structure readback. Timed DNS authority and precise remaining
//! lease time require the separate native-duration observation as well.
use crate::{Allocation, Config, DnsBindings, LEASE_SECONDS, dns::SetNames, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
mod lease;
mod rules;
pub use lease::verify_native_lease;

fn bad() -> ApiError {
    error(ErrorCode::Conflict, "native effective policy differs")
}
struct Shape {
    chains: BTreeMap<String, Value>,
    rules: BTreeMap<String, Vec<Vec<Value>>>,
}
impl Shape {
    fn chain(&mut self, name: &str, attributes: Value) {
        self.chains.insert(name.to_owned(), attributes);
    }
    fn rule(&mut self, chain: &str, expressions: Vec<Value>) {
        self.rules
            .entry(chain.into())
            .or_default()
            .push(expressions);
    }
}

/// Reconstruct every chain, ordered expression, set declaration and named-set
/// reference from the administrator's configuration. No table hash or revision
/// marker alone can establish that the actual native policy matches.
pub fn verify_structure(
    allocation: &Allocation,
    revision: u64,
    config: &Config,
    bindings: Option<&DnsBindings>,
    dns: Option<&SetNames>,
    native: &Value,
) -> Result<(), ApiError> {
    allocation.validate()?;
    config.model()?;
    let mut wanted = rules::expected(allocation, revision, config, bindings, dns)?;
    for expressions in wanted.rules.values_mut().flatten() {
        normalize(allocation, expressions)?;
    }
    let mut chains = BTreeMap::new();
    let mut rules: BTreeMap<String, Vec<Vec<Value>>> = BTreeMap::new();
    let mut tables = 0;
    let mut sets = BTreeSet::new();
    let table = allocation.table();
    let dns_sets = dns
        .map(|d| {
            d.entries()
                .map(|(n, _, v4)| (n.to_owned(), v4))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    for row in native["nftables"].as_array().ok_or_else(bad)? {
        let row = row.as_object().filter(|o| o.len() == 1).ok_or_else(bad)?;
        let (kind, value) = row.iter().next().ok_or_else(bad)?;
        if kind == "metainfo" {
            continue;
        }
        let allowed: &[&str] = match kind.as_str() {
            "table" => &["family", "name", "handle"],
            "chain" => &[
                "family", "table", "name", "handle", "type", "hook", "prio", "policy",
            ],
            "set" => &[
                "family",
                "table",
                "name",
                "handle",
                "type",
                "flags",
                "timeout",
                "gc-interval",
                "size",
                "elem",
            ],
            "rule" => &["family", "table", "chain", "handle", "expr", "comment"],
            _ => return Err(bad()),
        };
        let object = value
            .as_object()
            .filter(|o| o.keys().all(|k| allowed.contains(&k.as_str())))
            .ok_or_else(bad)?;
        if value["family"] != "inet" {
            return Err(bad());
        }
        if kind == "table" {
            if value["name"] != table || tables != 0 {
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
                let attributes = object
                    .iter()
                    .filter(|(k, _)| !matches!(k.as_str(), "family" | "table" | "name" | "handle"))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<serde_json::Map<_, _>>();
                if chains
                    .insert(name.to_owned(), Value::Object(attributes))
                    .is_some()
                {
                    return Err(bad());
                }
            }
            "rule" => {
                let chain = value["chain"].as_str().ok_or_else(bad)?;
                let mut expressions = value["expr"].as_array().ok_or_else(bad)?.clone();
                normalize(allocation, &mut expressions)?;
                rules.entry(chain.into()).or_default().push(expressions);
            }
            "set" => {
                let name = value["name"].as_str().ok_or_else(bad)?;
                if !sets.insert(name.to_owned()) || value["flags"] != json!(["timeout"]) {
                    return Err(bad());
                }
                if name == "live" {
                    if value["type"] != "ifname" || value["timeout"] != LEASE_SECONDS {
                        return Err(bad());
                    }
                    let members = value["elem"]
                        .as_array()
                        .filter(|v| v.len() == 1)
                        .ok_or_else(bad)?;
                    timed_element(&members[0], &json!(allocation.bridge), LEASE_SECONDS, true)?;
                } else {
                    let v4 = *dns_sets.get(name).ok_or_else(bad)?;
                    if value["type"] != if v4 { "ipv4_addr" } else { "ipv6_addr" }
                        || value.get("timeout").is_some()
                    {
                        return Err(bad());
                    }
                    if let Some(elements) = value.get("elem") {
                        let mut seen = BTreeSet::new();
                        for element in elements.as_array().ok_or_else(bad)? {
                            let ip = element["elem"]["val"]
                                .as_str()
                                .ok_or_else(bad)?
                                .parse::<std::net::IpAddr>()
                                .map_err(|_| bad())?;
                            if ip.is_ipv4() != v4 || !seen.insert(ip) {
                                return Err(bad());
                            }
                            timed_element(element, &json!(ip), 300, false)?;
                        }
                    }
                }
            }
            _ => return Err(bad()),
        }
    }
    let expected_sets = std::iter::once("live".to_owned())
        .chain(dns_sets.into_keys())
        .collect::<BTreeSet<_>>();
    if tables != 1 || chains != wanted.chains || rules != wanted.rules || sets != expected_sets {
        return Err(bad());
    }
    Ok(())
}

fn timed_element(
    value: &Value,
    expected: &Value,
    maximum: u32,
    default_timeout: bool,
) -> Result<(), ApiError> {
    let outer = value.as_object().filter(|o| o.len() == 1).ok_or_else(bad)?;
    let elem = outer
        .get("elem")
        .and_then(Value::as_object)
        .ok_or_else(bad)?;
    if elem
        .keys()
        .any(|k| !matches!(k.as_str(), "val" | "timeout" | "expires"))
        || elem.get("val") != Some(expected)
    {
        return Err(bad());
    }
    let timeout = elem
        .get("timeout")
        .map(|v| v.as_u64().ok_or_else(bad))
        .transpose()?
        .or(default_timeout.then_some(u64::from(maximum)))
        .ok_or_else(bad)?;
    let expires = elem
        .get("expires")
        .and_then(Value::as_u64)
        .ok_or_else(bad)?;
    // JSON truncates sub-second durations; precise native text must separately
    // establish a positive, finite expiry before any live receipt is returned.
    if timeout > u64::from(maximum) || expires > timeout {
        return Err(bad());
    }
    Ok(())
}

fn normalize(allocation: &Allocation, expressions: &mut Vec<Value>) -> Result<(), ApiError> {
    if let Some(index) = expressions.iter().position(|v| v.get("counter").is_some()) {
        let counter = expressions[index]["counter"].as_object().ok_or_else(bad)?;
        if index + 2 != expressions.len()
            || expressions[index].as_object().is_none_or(|o| o.len() != 1)
            || counter.len() != 2
            || counter.get("packets").and_then(Value::as_u64).is_none()
            || counter.get("bytes").and_then(Value::as_u64).is_none()
        {
            return Err(bad());
        }
        expressions.remove(index);
    }
    for expression in expressions.iter_mut() {
        if expression["match"]["left"] == json!({"meta":{"key":"iif"}})
            && expression["match"]["right"] == allocation.bridge
        {
            expression["match"]["right"] = json!(allocation.ifindex);
        }
        let key = expression["match"]["left"]["meta"]["key"]
            .as_str()
            .unwrap_or("");
        let number = match (key, expression["match"]["right"].as_str()) {
            ("l4proto", Some("tcp")) => Some(6),
            ("l4proto", Some("udp")) => Some(17),
            ("nfproto", Some("ipv4")) => Some(2),
            ("nfproto", Some("ipv6")) => Some(10),
            _ => None,
        };
        if let Some(number) = number {
            expression["match"]["right"] = json!(number);
        }
        if expression["match"]["left"] == json!({"payload":{"protocol":"icmpv6","field":"type"}})
            && let Some(values) = expression
                .pointer_mut("/match/right/set")
                .and_then(Value::as_array_mut)
        {
            for value in values {
                if value == "nd-neighbor-solicit" {
                    *value = json!(135);
                } else if value == "nd-neighbor-advert" {
                    *value = json!(136);
                }
            }
        }
        if let Some(values) = expression
            .pointer_mut("/match/right/set")
            .and_then(Value::as_array_mut)
        {
            values.sort_by_key(Value::to_string);
            if values.len() == 1 {
                expression["match"]["right"] = values[0].clone();
            }
        }
        let prefix = &expression["match"]["right"]["prefix"];
        if matches!(prefix["len"].as_u64(), Some(32 | 128)) {
            let ip = prefix["addr"]
                .as_str()
                .and_then(|v| v.parse::<std::net::IpAddr>().ok())
                .ok_or_else(bad)?;
            if prefix["len"].as_u64() == Some(if ip.is_ipv4() { 32 } else { 128 }) {
                expression["match"]["right"] = json!(ip);
            }
        }
    }
    // nft decompiles a TCP payload match with its implicit protocol dependency,
    // omitting the redundant explicit `meta l4proto tcp` from numeric JSON.
    let mut index = 0;
    while index + 1 < expressions.len() {
        if expressions[index]
            == json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":6}})
            && expressions[index + 1]["match"]["left"]
                == json!({"payload":{"protocol":"tcp","field":"dport"}})
        {
            expressions.remove(index);
        } else {
            index += 1;
        }
    }
    Ok(())
}
