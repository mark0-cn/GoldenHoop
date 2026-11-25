//! Exact readback of the deny table used before any policy or live lease.
use crate::{Allocation, DnsBindings, LEASE_SECONDS, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn bad() -> ApiError {
    error(ErrorCode::Conflict, "native quarantine rules differ")
}

pub fn verify(
    allocation: &Allocation,
    revision: u64,
    bindings: &DnsBindings,
    native: &Value,
) -> Result<(), ApiError> {
    allocation.validate()?;
    let table = allocation.table();
    let owner = allocation.owner_chain();
    let version = format!("revision_{revision}");
    let mut tables = 0;
    let mut chains = BTreeSet::new();
    let mut sets = 0;
    let mut rules: BTreeMap<String, Vec<Vec<Value>>> = BTreeMap::new();
    for row in native["nftables"].as_array().ok_or_else(bad)? {
        let row = row.as_object().filter(|v| v.len() == 1).ok_or_else(bad)?;
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
        if value
            .as_object()
            .is_none_or(|fields| fields.keys().any(|key| !allowed.contains(&key.as_str())))
        {
            return Err(bad());
        }
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
                if !chains.insert(name.to_owned()) {
                    return Err(bad());
                }
                if matches!(name, "input" | "forward") {
                    if value["type"] != "filter"
                        || value["hook"] != name
                        || value["prio"] != -190
                        || value["policy"] != "accept"
                    {
                        return Err(bad());
                    }
                } else if (name != owner && name != version && name != "guard")
                    || value.get("hook").is_some()
                    || value.get("type").is_some()
                    || value.get("policy").is_some()
                {
                    return Err(bad());
                }
            }
            "set" => {
                if sets != 0
                    || value["name"] != "live"
                    || value["type"] != "ifname"
                    || value["flags"] != json!(["timeout"])
                    || value["timeout"] != LEASE_SECONDS
                    || value
                        .get("elem")
                        .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
                {
                    return Err(bad());
                }
                sets += 1;
            }
            "rule" => {
                let chain = value["chain"].as_str().ok_or_else(bad)?;
                if !matches!(chain, "input" | "forward" | "guard") {
                    return Err(bad());
                }
                let mut expressions = value["expr"].as_array().ok_or_else(bad)?.clone();
                if let Some(position) = expressions.iter().position(|v| v.get("counter").is_some())
                {
                    if position + 2 != expressions.len()
                        || expressions[position]
                            .as_object()
                            .is_none_or(|v| v.len() != 1)
                        || expressions[position]["counter"]["packets"]
                            .as_u64()
                            .is_none()
                        || expressions[position]["counter"]["bytes"].as_u64().is_none()
                    {
                        return Err(bad());
                    }
                    expressions.remove(position);
                }
                for expression in &mut expressions {
                    // nft JSON can render a meta-iif index as its current name,
                    // even with --numeric. Manager checks the frozen native
                    // bridge index both before and after this readback.
                    if expression["match"]["left"] == json!({"meta":{"key":"iif"}})
                        && expression["match"]["right"] == allocation.bridge
                    {
                        expression["match"]["right"] = json!(allocation.ifindex);
                    }
                    if expression["match"]["left"]
                        == json!({"payload":{"protocol":"icmpv6","field":"type"}})
                    {
                        let values = expression["match"]["right"]["set"]
                            .as_array_mut()
                            .ok_or_else(bad)?;
                        for value in values.iter_mut() {
                            *value = match value.as_str() {
                                Some("nd-neighbor-solicit") => json!(135),
                                Some("nd-neighbor-advert") => json!(136),
                                _ => value.clone(),
                            };
                        }
                        values.sort_by_key(Value::as_u64);
                    }
                }
                rules.entry(chain.into()).or_default().push(expressions);
            }
            _ => return Err(bad()),
        }
    }
    let matched =
        |left: Value, right: Value| json!({"match":{"op":"==","left":left,"right":right}});
    let iif = matched(json!({"meta":{"key":"iif"}}), json!(allocation.ifindex));
    let mut input = vec![vec![
        iif.clone(),
        matched(
            json!({"payload":{"protocol":"ip6","field":"hoplimit"}}),
            json!(255),
        ),
        matched(
            json!({"payload":{"protocol":"icmpv6","field":"type"}}),
            json!({"set":[135,136]}),
        ),
        matched(
            json!({"payload":{"protocol":"icmpv6","field":"code"}}),
            json!(0),
        ),
        json!({"accept":null}),
    ]];
    for binding in bindings.iter() {
        let family = if binding.address().is_ipv4() {
            "ip"
        } else {
            "ip6"
        };
        for protocol in ["udp", "tcp"] {
            input.push(vec![
                matched(
                    json!({"payload":{"protocol":family,"field":"daddr"}}),
                    json!(binding.address()),
                ),
                matched(
                    json!({"payload":{"protocol":protocol,"field":"dport"}}),
                    json!(binding.port()),
                ),
                json!({"drop":null}),
            ]);
        }
    }
    input.push(vec![iif.clone(), json!({"drop":null})]);
    let expected = BTreeMap::from([
        ("input".into(), input),
        (
            "forward".into(),
            vec![vec![
                iif,
                matched(json!({"meta":{"key":"iifname"}}), json!(allocation.bridge)),
                json!({"jump":{"target":"guard"}}),
            ]],
        ),
        ("guard".into(), vec![vec![json!({"drop":null})]]),
    ]);
    if tables != 1
        || sets != 1
        || chains
            != BTreeSet::from([
                owner,
                version,
                "input".into(),
                "forward".into(),
                "guard".into(),
            ])
        || rules != expected
    {
        return Err(bad());
    }
    Ok(())
}
