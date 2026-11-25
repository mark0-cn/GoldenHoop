//! Allocation-owned destination floor. Both original and post-DNAT targets
//! are checked; only exact trusted DNS listener tuples bypass this floor.
use crate::{Allocation, DestinationScope, DnsBinding, ProtectedDestinations, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::IpAddr};

const VERSION: &str = "destination_version_1";
const MAX_DESCRIPTOR: usize = 16384;
const CHUNK: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationListener {
    pub address: IpAddr,
    pub port: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationDefinition {
    pub scope: DestinationScope,
    /// Trusted bound DNS sockets only. The workload cannot choose exemptions.
    pub dns: Vec<DestinationListener>,
}
impl DestinationDefinition {
    pub fn canonical(&self) -> Result<Self, ApiError> {
        let floor = ProtectedDestinations::new(self.scope.clone())?;
        if self.dns.len() > 2 {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "too many destination DNS exemptions",
            ));
        }
        let mut dns = self.dns.clone();
        dns.sort_by_key(|v| (v.address, v.port));
        for (index, listener) in dns.iter().enumerate() {
            DnsBinding::new(listener.address, listener.port)?;
            if !floor.scope().host_addresses.contains(&listener.address)
                || dns[..index]
                    .iter()
                    .any(|old| old.address.is_ipv4() == listener.address.is_ipv4())
            {
                return Err(error(
                    ErrorCode::InvalidRequest,
                    "DNS exemption is not a unique owned host endpoint",
                ));
            }
        }
        Ok(Self {
            scope: floor.scope().clone(),
            dns,
        })
    }
    pub fn digest(&self) -> String {
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).expect("destination definition"))
        )
    }
}
impl Allocation {
    pub fn destination_table(&self) -> String {
        format!("gh_d_{}", self.generation.simple())
    }
}

pub struct DestinationPlan {
    definition: DestinationDefinition,
    script: String,
    rules: Vec<(String, Vec<Value>)>,
}
impl DestinationPlan {
    pub fn new(
        allocation: &Allocation,
        definition: &DestinationDefinition,
    ) -> Result<Self, ApiError> {
        allocation.validate()?;
        let definition = definition.canonical()?;
        let descriptor = serde_json::to_vec(&definition).expect("destination definition");
        if descriptor.len() > MAX_DESCRIPTOR {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "destination descriptor exceeds limit",
            ));
        }
        let table = allocation.destination_table();
        let mut p = Self {
            definition,
            script: format!("add table inet {table}\n"),
            rules: Vec::new(),
        };
        p.line(allocation, "add chain", &allocation.owner_chain());
        p.line(allocation, "add chain", VERSION);
        p.line(
            allocation,
            "add chain",
            &format!("binding_{}", p.definition.digest()),
        );
        for (index, bytes) in descriptor.chunks(CHUNK).enumerate() {
            p.line(
                allocation,
                "add chain",
                &format!(
                    "cfg_{index:03}_{}",
                    bytes.iter().map(|v| format!("{v:02x}")).collect::<String>()
                ),
            );
        }
        // NAT base-chain priorities order the NAT lookup list, not separate
        // packet hooks around which an inet filter can safely be interposed.
        // Check the original destination before conntrack/NAT, and the final
        // destination at both local-input and routed-forward hooks.
        for chain in ["prerouting", "input", "forward"] {
            p.line(
                allocation,
                "add chain",
                &format!("{chain} {{ type filter hook {chain} priority -210; policy accept; }}"),
            );
        }
        p.line(allocation, "add chain", "decision");
        for chain in ["prerouting", "input", "forward"] {
            p.rule(allocation,chain,vec![(format!("iifname != \"{}\"",allocation.bridge),json!({"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":allocation.bridge}}))],"return");
            p.rule(allocation,chain,vec![(format!("meta iif != {}",allocation.ifindex),json!({"match":{"op":"!=","left":{"meta":{"key":"iif"}},"right":allocation.ifindex}}))],"drop");
            if chain != "forward" {
                // Link-neighbor transport only. The mandatory source floor
                // validates the original ND sender, target and option bytes.
                p.rule(allocation,chain,vec![
                    ("ip6 nexthdr 58".into(),json!({"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"nexthdr"}},"right":58}})),
                    ("ip6 hoplimit 255".into(),json!({"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"hoplimit"}},"right":255}})),
                    ("icmpv6 type { 135, 136 }".into(),json!({"match":{"op":"==","left":{"payload":{"protocol":"icmpv6","field":"type"}},"right":{"set":[135,136]}}})),
                    ("icmpv6 code 0".into(),json!({"match":{"op":"==","left":{"payload":{"protocol":"icmpv6","field":"code"}},"right":0}})),
                ],"return");
            }
            if chain == "prerouting" {
                // Only the owned gateway's original DNS endpoint may pass a
                // host/private restriction before its protected redirect.
                for listener in p.definition.dns.clone() {
                    for protocol in ["tcp", "udp"] {
                        p.rule(allocation,chain,vec![address(listener.address),
                            (format!("{protocol} dport 53"),json!({"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":"dport"}},"right":53}}))
                        ],"return");
                    }
                }
            }
            p.rule(allocation, chain, Vec::new(), "goto decision");
        }
        let floor = ProtectedDestinations::new(p.definition.scope.clone())?;
        for listener in p.definition.dns.clone() {
            for (protocol, number) in [("tcp", 6), ("udp", 17)] {
                let mut conditions = vec![address(listener.address)];
                conditions.push((
                    format!("meta l4proto {protocol}"),
                    json!({"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":number}}),
                ));
                conditions.push((format!("{protocol} dport {}",listener.port),json!({"match":{"op":"==","left":{"payload":{"protocol":protocol,"field":"dport"}},"right":listener.port}})));
                p.rule(allocation, "decision", conditions, "return");
            }
        }
        for net in floor.hard_networks() {
            p.rule(allocation, "decision", vec![network(net)], "drop");
        }
        for ip in floor.pinned_addresses() {
            p.rule(allocation, "decision", vec![address(*ip)], "drop");
        }
        for net in floor.private_exceptions() {
            p.rule(allocation, "decision", vec![network(net)], "return");
        }
        for net in floor.private_networks() {
            p.rule(allocation, "decision", vec![network(net)], "drop");
        }
        p.rule(allocation, "decision", Vec::new(), "return");
        Ok(p)
    }
    fn line(&mut self, a: &Allocation, operation: &str, tail: &str) {
        self.script.push_str(&format!(
            "{operation} inet {} {tail}\n",
            a.destination_table()
        ));
    }
    fn rule(
        &mut self,
        a: &Allocation,
        chain: &str,
        conditions: Vec<(String, Value)>,
        verdict: &str,
    ) {
        let native = conditions
            .iter()
            .map(|(s, _)| s.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        self.line(
            a,
            "add rule",
            &format!("{chain} {native} counter {verdict}"),
        );
        let mut expr = conditions.into_iter().map(|(_, v)| v).collect::<Vec<_>>();
        expr.push(if let Some(target) = verdict.strip_prefix("goto ") {
            json!({"goto":{"target":target}})
        } else {
            json!({verdict:null})
        });
        self.rules.push((chain.into(), expr));
    }
    pub fn script(&self) -> &str {
        &self.script
    }
    pub fn definition(&self) -> &DestinationDefinition {
        &self.definition
    }

    /// Descriptor validation remains usable for owned collection even when
    /// actual rule semantics are unknown. It never confirms enforcement.
    pub fn descriptor(a: &Allocation, value: &Value) -> Result<DestinationDefinition, ApiError> {
        a.validate()?;
        let bad = || error(ErrorCode::Conflict, "destination table identity differs");
        let entries = value["nftables"].as_array().ok_or_else(bad)?;
        let mut tables = 0;
        let mut owners = Vec::new();
        let mut versions = 0;
        let mut bindings = Vec::new();
        let mut chunks = BTreeMap::new();
        for entry in entries {
            if let Some(t) = entry.get("table") {
                if t["family"] != "inet" || t["name"] != a.destination_table() {
                    return Err(bad());
                }
                tables += 1;
            }
            if let Some(c) = entry.get("chain") {
                if c["family"] != "inet" || c["table"] != a.destination_table() {
                    return Err(bad());
                }
                let name = c["name"].as_str().ok_or_else(bad)?;
                if name.starts_with("goldenhoop_") {
                    owners.push(name);
                }
                if name == VERSION {
                    versions += 1;
                }
                if let Some(d) = name.strip_prefix("binding_") {
                    bindings.push(d);
                }
                if let Some(chunk) = name.strip_prefix("cfg_") {
                    let (index, bytes) = chunk.split_once('_').ok_or_else(bad)?;
                    let n = index.parse::<usize>().map_err(|_| bad())?;
                    if index != format!("{n:03}")
                        || n >= MAX_DESCRIPTOR / CHUNK
                        || bytes.is_empty()
                        || bytes.len() > CHUNK * 2
                        || bytes.len() % 2 != 0
                        || !bytes
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        || chunks.insert(n, bytes).is_some()
                    {
                        return Err(bad());
                    }
                }
            }
        }
        if tables != 1
            || owners != [a.owner_chain()]
            || versions != 1
            || bindings.len() != 1
            || chunks.is_empty()
        {
            return Err(bad());
        }
        let mut bytes = Vec::new();
        for (expected, (index, text)) in chunks.into_iter().enumerate() {
            if expected != index {
                return Err(bad());
            }
            for offset in (0..text.len()).step_by(2) {
                bytes.push(u8::from_str_radix(&text[offset..offset + 2], 16).map_err(|_| bad())?);
            }
        }
        let raw: DestinationDefinition = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        let definition = raw.canonical().map_err(|_| bad())?;
        if definition != raw || bindings[0] != definition.digest() {
            return Err(bad());
        }
        Ok(definition)
    }
    pub fn verify(&self, a: &Allocation, value: &Value) -> Result<(), ApiError> {
        let bad = || error(ErrorCode::Conflict, "destination rule observation differs");
        if Self::descriptor(a, value)? != self.definition {
            return Err(bad());
        }
        let mut chains = Vec::new();
        let mut actual = Vec::new();
        for entry in value["nftables"].as_array().ok_or_else(bad)? {
            if let Some(t) = entry.get("table")
                && t.get("flags")
                    .is_some_and(|f| f.as_array().is_none_or(|a| !a.is_empty()))
            {
                return Err(bad());
            }
            if let Some(c) = entry.get("chain") {
                let name = c["name"].as_str().ok_or_else(bad)?;
                if let Some(priority) = match name {
                    "prerouting" | "input" | "forward" => Some(-210),
                    _ => None,
                } {
                    if c["type"] != "filter"
                        || c["hook"] != name
                        || c["prio"] != priority
                        || c["policy"] != "accept"
                    {
                        return Err(bad());
                    }
                } else if c.get("hook").is_some() || c.get("type").is_some() {
                    return Err(bad());
                }
                chains.push(name.to_string());
            } else if let Some(r) = entry.get("rule") {
                if r["family"] != "inet" || r["table"] != a.destination_table() {
                    return Err(bad());
                }
                let chain = r["chain"].as_str().ok_or_else(bad)?.to_string();
                let mut expr = r["expr"].as_array().ok_or_else(bad)?.clone();
                let n = expr.len();
                if n < 2
                    || expr[n - 2].as_object().is_none_or(|v| v.len() != 1)
                    || expr[n - 2]["counter"]["packets"].as_u64().is_none()
                    || expr[n - 2]["counter"]["bytes"].as_u64().is_none()
                {
                    return Err(bad());
                }
                expr.remove(n - 2);
                canonical(a, &mut expr)?;
                actual.push((chain, expr));
            } else if entry.get("table").is_none() && entry.get("metainfo").is_none() {
                return Err(bad());
            }
        }
        let mut expected = self.rules.clone();
        for (_, expr) in &mut expected {
            canonical(a, expr)?;
        }
        if actual != expected {
            return Err(bad());
        }
        let mut expected_chains = self
            .script
            .lines()
            .filter_map(|s| {
                s.strip_prefix(&format!("add chain inet {} ", a.destination_table()))
                    .map(|s| s.split_whitespace().next().expect("chain").to_string())
            })
            .collect::<Vec<_>>();
        chains.sort();
        expected_chains.sort();
        if chains != expected_chains {
            return Err(bad());
        }
        Ok(())
    }
}
fn address(ip: IpAddr) -> (String, Value) {
    let p = if ip.is_ipv4() { "ip" } else { "ip6" };
    (
        format!("{p} daddr {ip}"),
        json!({"match":{"op":"==","left":{"payload":{"protocol":p,"field":"daddr"}},"right":ip}}),
    )
}
fn network(net: &IpNet) -> (String, Value) {
    let ip = net.network();
    let p = if ip.is_ipv4() { "ip" } else { "ip6" };
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    let value = if net.prefix_len() == bits {
        json!(ip)
    } else {
        json!({"prefix":{"addr":ip,"len":net.prefix_len()}})
    };
    (
        format!("{p} daddr {net}"),
        json!({"match":{"op":"==","left":{"payload":{"protocol":p,"field":"daddr"}},"right":value}}),
    )
}
fn canonical(a: &Allocation, expr: &mut Vec<Value>) -> Result<(), ApiError> {
    let bad = || error(ErrorCode::Conflict, "destination predicate differs");
    let verdict = expr.pop().ok_or_else(bad)?;
    if expr.iter().any(|v| {
        v.as_object()
            .is_none_or(|v| v.len() != 1 || !v.contains_key("match"))
    }) {
        return Err(bad());
    }
    for v in expr.iter_mut() {
        normalize(v);
        let m = &mut v["match"];
        if m["left"] == json!({"meta":{"key":"iif"}}) && m["right"] == a.bridge {
            m["right"] = json!(a.ifindex);
        }
        if m["left"] == json!({"meta":{"key":"l4proto"}}) {
            if m["right"] == "tcp" {
                m["right"] = json!(6);
            } else if m["right"] == "udp" {
                m["right"] = json!(17);
            }
        }
        let payload = &m["left"]["payload"];
        if payload["protocol"] == "ip6"
            && payload["field"] == "nexthdr"
            && m["right"] == "ipv6-icmp"
        {
            m["right"] = json!(58);
        } else if payload["protocol"] == "icmpv6"
            && payload["field"] == "code"
            && m["right"] == "no-route"
        {
            m["right"] = json!(0);
        } else if payload["protocol"] == "icmpv6"
            && payload["field"] == "type"
            && let Some(types) = m["right"].get_mut("set").and_then(Value::as_array_mut)
        {
            for kind in types {
                if *kind == "nd-neighbor-solicit" {
                    *kind = json!(135);
                } else if *kind == "nd-neighbor-advert" {
                    *kind = json!(136);
                }
            }
        }
    }
    let has = |p: &str| {
        expr.iter()
            .any(|v| v["match"]["left"]["payload"]["protocol"] == p)
    };
    let tcp = has("tcp");
    let udp = has("udp");
    expr.retain(|v| {
        let m = &v["match"];
        !(m["op"] == "=="
            && m["left"] == json!({"meta":{"key":"l4proto"}})
            && ((tcp && m["right"] == 6) || (udp && m["right"] == 17)))
    });
    expr.sort_by_key(Value::to_string);
    expr.push(verdict);
    Ok(())
}
fn normalize(value: &mut Value) {
    match value {
        Value::String(s) => {
            if let Ok(ip) = s.parse::<IpAddr>() {
                *s = ip.to_string();
            }
        }
        Value::Array(a) => {
            for v in a {
                normalize(v);
            }
        }
        Value::Object(o) => {
            for v in o.values_mut() {
                normalize(v);
            }
            if let Some(p) = o.get("prefix")
                && o.len() == 1
                && let Some(ip) = p["addr"].as_str().and_then(|s| s.parse::<IpAddr>().ok())
                && p["len"] == if ip.is_ipv4() { 32 } else { 128 }
            {
                *value = json!(ip);
            }
        }
        _ => {}
    }
}
