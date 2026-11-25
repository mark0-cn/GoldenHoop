//! Immutable host-owned endpoint source constraints. No workload supplies this
//! descriptor; the trusted allocator binds it to provider/kernel observations.
use crate::{Allocation, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

const VERSION: &str = "source_version_1";
const CHUNK: usize = 64;
const MAX_DESCRIPTOR: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mac([u8; 6]);
impl FromStr for Mac {
    type Err = ApiError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bad = || error(ErrorCode::InvalidRequest, "invalid endpoint MAC");
        if text.len() != 17 {
            return Err(bad());
        }
        let mut bytes = [0; 6];
        let parts = text.split(':').collect::<Vec<_>>();
        if parts.len() != 6 {
            return Err(bad());
        }
        for (dest, part) in bytes.iter_mut().zip(parts) {
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(bad());
            }
            *dest = u8::from_str_radix(part, 16).map_err(|_| bad())?;
        }
        if bytes == [0; 6] || bytes[0] & 1 != 0 {
            return Err(bad());
        }
        Ok(Self(bytes))
    }
}
impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}
impl Serialize for Mac {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for Mac {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(|_| serde::de::Error::custom("invalid endpoint MAC"))
    }
}
impl Mac {
    pub fn link_local(self) -> Ipv6Addr {
        Ipv6Addr::from([
            0xfe,
            0x80,
            0,
            0,
            0,
            0,
            0,
            0,
            self.0[0] ^ 2,
            self.0[1],
            self.0[2],
            0xff,
            0xfe,
            self.0[3],
            self.0[4],
            self.0[5],
        ])
    }
    fn number(self) -> u64 {
        self.0.into_iter().fold(0, |a, b| (a << 8) | u64::from(b))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub port: String,
    pub ifindex: u32,
    pub mac: Mac,
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceScope {
    pub endpoint: Endpoint,
    pub gateway_mac: Mac,
    pub gateway4: Ipv4Addr,
    pub gateway6: Option<Ipv6Addr>,
}
impl SourceScope {
    pub fn validate(&self, allocation: &Allocation) -> Result<(), ApiError> {
        allocation.validate()?;
        let ep = &self.endpoint;
        let v4ok = |ip: Ipv4Addr| {
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
        };
        let v6ok = |ip: Ipv6Addr| {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unicast_link_local()
                && ip.to_ipv4_mapped().is_none()
        };
        if ep.port.len() < 2
            || ep.port.len() > 15
            || ep.port == allocation.bridge
            || !ep
                .port
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
            || !(1..=i32::MAX as u32).contains(&ep.ifindex)
            || ep.ifindex == allocation.ifindex
            || !v4ok(ep.ipv4)
            || !v4ok(self.gateway4)
            || ep.ipv4 == self.gateway4
            || ep.mac == self.gateway_mac
            || ep.ipv6.is_some() != self.gateway6.is_some()
            || ep.ipv6.is_some_and(|ip| !v6ok(ip))
            || self.gateway6.is_some_and(|ip| !v6ok(ip))
            || (ep.ipv6.is_some() && ep.ipv6 == self.gateway6)
        {
            return Err(error(
                ErrorCode::InvalidRequest,
                "invalid allocated endpoint source scope",
            ));
        }
        Ok(())
    }
    pub fn digest(&self) -> String {
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).expect("source scope"))
        )
    }
}

impl Allocation {
    pub fn source_table(&self) -> String {
        format!("gh_s_{}", self.generation.simple())
    }
}

struct Match {
    native: String,
    value: Value,
}
fn field(protocol: &str, field: &str, op: &str, value: Value) -> Match {
    if protocol == "icmpv6" && field == "taddr" {
        let convert = |v: &Value| {
            Value::String(format!(
                "0x{:x}",
                v.as_str()
                    .expect("typed IPv6 target")
                    .parse::<Ipv6Addr>()
                    .expect("IPv6 target")
                    .to_bits()
            ))
        };
        let target = if let Some(values) = value.get("set").and_then(Value::as_array) {
            set(values.iter().map(convert))
        } else {
            convert(&value)
        };
        return Match {
            native: format!("@th,64,128 {op} {}", literal(&target)),
            value: json!({"match":{"op":op,"left":{"payload":{"base":"th","offset":64,"len":128}},"right":target}}),
        };
    }
    Match {
        native: format!("{protocol} {field} {op} {}", literal(&value)),
        value: json!({"match":{"op":op,"left":{"payload":{"protocol":protocol,"field":field}},"right":value}}),
    }
}
fn meta(field: &str, op: &str, value: Value) -> Match {
    let native = if matches!(field, "iifname" | "ibrname") {
        value.to_string()
    } else {
        literal(&value)
    };
    Match {
        native: format!("meta {field} {op} {native}"),
        value: json!({"match":{"op":op,"left":{"meta":{"key":field}},"right":value}}),
    }
}
fn raw(offset: u32, len: u32, mask: Option<u64>, value: u64) -> Match {
    let left = json!({"payload":{"base":"th","offset":offset,"len":len}});
    Match {
        native: format!(
            "@th,{offset},{len}{} == 0x{value:x}",
            mask.map(|m| format!(" & 0x{m:x}")).unwrap_or_default()
        ),
        value: json!({"match":{"op":"==","left":mask.map(|m|json!({"&":[left.clone(),m]})).unwrap_or(left),"right":value}}),
    }
}
fn literal(value: &Value) -> String {
    if let Some(values) = value.get("set").and_then(Value::as_array) {
        return format!(
            "{{ {} }}",
            values.iter().map(literal).collect::<Vec<_>>().join(", ")
        );
    }
    match value {
        Value::String(s) => s.clone(),
        _ => value.to_string(),
    }
}
fn set(values: impl IntoIterator<Item = Value>) -> Value {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.len() == 1 {
        values[0].clone()
    } else {
        json!({"set":values})
    }
}

pub struct SourcePlan {
    batch: String,
    rules: Vec<(String, Vec<Value>)>,
    scope: SourceScope,
}
impl SourcePlan {
    pub fn new(allocation: &Allocation, scope: &SourceScope) -> Result<Self, ApiError> {
        scope.validate(allocation)?;
        let table = allocation.source_table();
        let mut p = Self {
            batch: format!("add table bridge {table}\n"),
            rules: Vec::new(),
            scope: scope.clone(),
        };
        p.line(allocation, "add chain", &allocation.owner_chain());
        p.line(allocation, "add chain", VERSION);
        p.line(
            allocation,
            "add chain",
            &format!("binding_{}", scope.digest()),
        );
        let descriptor = serde_json::to_vec(scope).expect("source scope");
        if descriptor.len() > MAX_DESCRIPTOR {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "source descriptor exceeds limit",
            ));
        }
        for (index, bytes) in descriptor.chunks(CHUNK).enumerate() {
            p.line(
                allocation,
                "add chain",
                &format!(
                    "cfg_{index:02}_{}",
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                ),
            );
        }
        p.line(
            allocation,
            "add chain",
            "prerouting { type filter hook prerouting priority -310; policy accept; }",
        );
        for name in ["arp_source", "ipv6_source", "neighbor_source"] {
            p.line(allocation, "add chain", name);
        }
        let ep = &scope.endpoint;
        p.rule(
            allocation,
            "prerouting",
            vec![meta("ibrname", "!=", json!(allocation.bridge))],
            "return",
        );
        p.rule(
            allocation,
            "prerouting",
            vec![meta("iifname", "!=", json!(ep.port))],
            "drop",
        );
        p.rule(
            allocation,
            "prerouting",
            vec![field("ether", "saddr", "!=", json!(ep.mac.to_string()))],
            "drop",
        );
        // A valid subchain return must finish this base chain. A jump would
        // resume in prerouting and reach its final unknown-frame drop.
        p.rule(
            allocation,
            "prerouting",
            vec![field("ether", "type", "==", json!("arp"))],
            "goto arp_source",
        );
        p.rule(
            allocation,
            "prerouting",
            vec![
                field("ether", "type", "==", json!("ip")),
                field("ip", "saddr", "==", json!(ep.ipv4)),
            ],
            "return",
        );
        p.rule(
            allocation,
            "prerouting",
            vec![field("ether", "type", "==", json!("ip6"))],
            "goto ipv6_source",
        );
        p.rule(allocation, "prerouting", vec![], "drop");
        p.rule(
            allocation,
            "arp_source",
            vec![field("arp", "saddr ether", "!=", json!(ep.mac.to_string()))],
            "drop",
        );
        for (name, value) in [("htype", 1), ("ptype", 2048), ("hlen", 6), ("plen", 4)] {
            p.rule(
                allocation,
                "arp_source",
                vec![field("arp", name, "!=", json!(value))],
                "drop",
            );
        }
        p.rule(
            allocation,
            "arp_source",
            vec![
                field("arp", "operation", "==", json!("request")),
                field("arp", "saddr ip", "==", json!(ep.ipv4)),
                field(
                    "arp",
                    "daddr ip",
                    "==",
                    set([json!(scope.gateway4), json!(ep.ipv4)]),
                ),
            ],
            "return",
        );
        p.rule(
            allocation,
            "arp_source",
            vec![
                field("arp", "operation", "==", json!("reply")),
                field("arp", "saddr ip", "==", json!(ep.ipv4)),
                field("arp", "daddr ip", "==", json!(scope.gateway4)),
                field(
                    "arp",
                    "daddr ether",
                    "==",
                    json!(scope.gateway_mac.to_string()),
                ),
            ],
            "return",
        );
        p.rule(
            allocation,
            "arp_source",
            vec![
                field("arp", "operation", "==", json!("request")),
                field("arp", "saddr ip", "==", json!(Ipv4Addr::UNSPECIFIED)),
                field("arp", "daddr ip", "==", json!(ep.ipv4)),
            ],
            "return",
        );
        p.rule(allocation, "arp_source", vec![], "drop");
        let nd_types = set([json!(135), json!(136)]);
        p.rule(
            allocation,
            "ipv6_source",
            vec![
                meta("l4proto", "==", json!(58)),
                field("icmpv6", "type", "==", nd_types),
            ],
            "goto neighbor_source",
        );
        // Source admission precedes bridge conntrack (-200). Reading ct state
        // here would classify an ordinary, not-yet-tracked packet as invalid.
        // Inspect the original per-frame addresses and ND headers instead.
        if let Some(v6) = ep.ipv6 {
            p.rule(
                allocation,
                "ipv6_source",
                vec![field("ip6", "saddr", "==", json!(v6))],
                "return",
            );
        }
        p.rule(allocation, "ipv6_source", vec![], "drop");
        p.rule(
            allocation,
            "neighbor_source",
            vec![field("ip6", "nexthdr", "!=", json!(58))],
            "drop",
        );
        p.rule(
            allocation,
            "neighbor_source",
            vec![field("ip6", "hoplimit", "!=", json!(255))],
            "drop",
        );
        p.rule(
            allocation,
            "neighbor_source",
            vec![field("icmpv6", "code", "!=", json!(0))],
            "drop",
        );
        let own = set(std::iter::once(json!(ep.mac.link_local())).chain(ep.ipv6.map(|v| json!(v))));
        let gateways = set(std::iter::once(json!(scope.gateway_mac.link_local()))
            .chain(scope.gateway6.map(|v| json!(v))));
        let nd = |kind, len, source: Value, target: Value| {
            vec![
                field("icmpv6", "type", "==", json!(kind)),
                field("ip6", "length", "==", json!(len)),
                field("ip6", "saddr", "==", source),
                field("icmpv6", "taddr", "==", target),
            ]
        };
        p.rule(
            allocation,
            "neighbor_source",
            nd(135, 24, json!(Ipv6Addr::UNSPECIFIED), own.clone()),
            "return",
        );
        p.rule(
            allocation,
            "neighbor_source",
            nd(135, 24, own.clone(), gateways.clone()),
            "return",
        );
        let mut ns = nd(135, 32, own.clone(), gateways);
        ns.push(raw(192, 64, None, (0x0101_u64 << 48) | ep.mac.number()));
        p.rule(allocation, "neighbor_source", ns, "return");
        for length in [24, 32] {
            let mut na = nd(136, length, own.clone(), own.clone());
            na.push(raw(32, 32, Some(0x9fff_ffff), 0));
            if length == 32 {
                na.push(raw(192, 64, None, (0x0201_u64 << 48) | ep.mac.number()));
            }
            p.rule(allocation, "neighbor_source", na, "return");
        }
        p.rule(allocation, "neighbor_source", vec![], "drop");
        Ok(p)
    }
    fn line(&mut self, a: &Allocation, operation: &str, tail: &str) {
        self.batch
            .push_str(&format!("{operation} bridge {} {tail}\n", a.source_table()));
    }
    fn rule(&mut self, a: &Allocation, chain: &str, mut conditions: Vec<Match>, verdict: &str) {
        if chain == "arp_source" {
            conditions.insert(0, field("ether", "type", "==", json!("arp")));
        }
        if matches!(chain, "ipv6_source" | "neighbor_source") {
            conditions.insert(0, field("ether", "type", "==", json!("ip6")));
        }
        if chain == "neighbor_source" {
            conditions.insert(1, meta("l4proto", "==", json!(58)));
        }
        let native = conditions
            .iter()
            .map(|m| m.native.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        self.line(
            a,
            "add rule",
            &format!("{chain} {native} counter {verdict}"),
        );
        let mut values = conditions.into_iter().map(|m| m.value).collect::<Vec<_>>();
        values.push(if let Some(target) = verdict.strip_prefix("goto ") {
            json!({"goto":{"target":target}})
        } else {
            json!({verdict:null})
        });
        self.rules.push((chain.into(), values));
    }
    pub fn script(&self) -> &str {
        &self.batch
    }
    pub fn scope(&self) -> &SourceScope {
        &self.scope
    }

    /// Ownership and bounded immutable descriptor are checked even when the
    /// rule shape is unknown, allowing collection only after bridge removal.
    pub fn descriptor(a: &Allocation, value: &Value) -> Result<SourceScope, ApiError> {
        a.validate()?;
        let bad = || error(ErrorCode::Conflict, "source guard identity differs");
        let entries = value["nftables"].as_array().ok_or_else(bad)?;
        let table = a.source_table();
        let mut owners = Vec::new();
        let mut versions = 0;
        let mut bindings = Vec::new();
        let mut chunks = BTreeMap::new();
        let mut tables = 0;
        for entry in entries {
            if let Some(t) = entry.get("table") {
                if t["family"] != "bridge" || t["name"] != table {
                    return Err(bad());
                }
                tables += 1;
            }
            if let Some(c) = entry.get("chain") {
                if c["family"] != "bridge" || c["table"] != table {
                    return Err(bad());
                }
                let name = c["name"].as_str().ok_or_else(bad)?;
                if name.starts_with("goldenhoop_") {
                    owners.push(name);
                }
                if name == VERSION {
                    versions += 1;
                }
                if let Some(digest) = name.strip_prefix("binding_") {
                    bindings.push(digest);
                }
                if let Some(chunk) = name.strip_prefix("cfg_") {
                    let (index, bytes) = chunk.split_once('_').ok_or_else(bad)?;
                    let number = index.parse::<usize>().map_err(|_| bad())?;
                    if index != format!("{number:02}")
                        || number >= MAX_DESCRIPTOR / CHUNK
                        || bytes.is_empty()
                        || bytes.len() > CHUNK * 2
                        || bytes.len() % 2 != 0
                        || !bytes
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        || chunks.insert(number, bytes).is_some()
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
        let mut data = Vec::new();
        for (expected, (index, text)) in chunks.into_iter().enumerate() {
            if index != expected {
                return Err(bad());
            }
            for offset in (0..text.len()).step_by(2) {
                data.push(u8::from_str_radix(&text[offset..offset + 2], 16).map_err(|_| bad())?);
            }
        }
        let scope: SourceScope = serde_json::from_slice(&data).map_err(|_| bad())?;
        scope.validate(a).map_err(|_| bad())?;
        if bindings[0] != scope.digest() {
            return Err(bad());
        }
        Ok(scope)
    }

    pub fn verify(&self, a: &Allocation, value: &Value) -> Result<(), ApiError> {
        let bad = || error(ErrorCode::Conflict, "source guard rule observation differs");
        if Self::descriptor(a, value)? != self.scope {
            return Err(bad());
        }
        let entries = value["nftables"].as_array().ok_or_else(bad)?;
        let mut actual = Vec::new();
        let mut chains = Vec::new();
        for e in entries {
            if let Some(table) = e.get("table")
                && table
                    .get("flags")
                    .is_some_and(|flags| flags.as_array().is_none_or(|flags| !flags.is_empty()))
            {
                return Err(bad());
            }
            if let Some(c) = e.get("chain") {
                let name = c["name"].as_str().ok_or_else(bad)?;
                if name == "prerouting" {
                    if c["type"] != "filter"
                        || c["hook"] != "prerouting"
                        || c["prio"] != -310
                        || c["policy"] != "accept"
                    {
                        return Err(bad());
                    }
                } else if c.get("hook").is_some() || c.get("type").is_some() {
                    return Err(bad());
                }
                chains.push(name.to_string());
            } else if let Some(r) = e.get("rule") {
                if r["family"] != "bridge" || r["table"] != a.source_table() {
                    return Err(bad());
                }
                let chain = r["chain"].as_str().ok_or_else(bad)?.to_string();
                let mut expr = r["expr"].as_array().ok_or_else(bad)?.clone();
                let n = expr.len();
                if n < 2
                    || expr[n - 2].as_object().is_none_or(|e| e.len() != 1)
                    || expr[n - 2]["counter"]["packets"].as_u64().is_none()
                    || expr[n - 2]["counter"]["bytes"].as_u64().is_none()
                {
                    return Err(bad());
                }
                expr.remove(n - 2);
                canonical_rule(&chain, &mut expr)?;
                actual.push((chain, expr));
            } else if e.get("table").is_none() && e.get("metainfo").is_none() {
                return Err(bad());
            }
        }
        let mut expected = self.rules.clone();
        for (chain, expr) in &mut expected {
            canonical_rule(chain, expr)?;
        }
        if actual != expected {
            return Err(bad());
        }
        let rebuilt = Self::new(a, &self.scope)?;
        let mut expected_chains = rebuilt
            .batch
            .lines()
            .filter_map(|line| {
                line.strip_prefix(&format!("add chain bridge {} ", a.source_table()))
                    .map(|t| t.split_whitespace().next().expect("chain").to_string())
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

/// NFT omits protocol dependencies in its decompilation and may reorder pure
/// predicates while merging adjacent payload loads. Subchain protocol context
/// is established by the fully verified prerouting/ND dispatch rules. Only
/// exact redundant dependencies are removed; rule order and verdicts remain.
fn canonical_rule(chain: &str, expr: &mut Vec<Value>) -> Result<(), ApiError> {
    let bad = || {
        error(
            ErrorCode::Conflict,
            "source guard predicate observation differs",
        )
    };
    let Some(verdict) = expr.pop() else {
        return Err(bad());
    };
    if expr.iter().any(|v| {
        v.as_object()
            .is_none_or(|o| o.len() != 1 || !o.contains_key("match"))
    }) {
        return Err(bad());
    }
    for part in expr.iter_mut() {
        normalize(part);
    }
    let has_payload = |protocol| {
        expr.iter()
            .any(|v| v["match"]["left"]["payload"]["protocol"] == protocol)
    };
    let ip4 = chain == "prerouting" && has_payload("ip");
    let icmp6 = chain == "ipv6_source" && has_payload("icmpv6");
    expr.retain(|v| {
        let m = &v["match"];
        if m["op"] != "==" {
            return true;
        }
        if m["left"] == json!({"payload":{"protocol":"ether","field":"type"}}) {
            return !((ip4 && m["right"] == 2048)
                || (chain == "arp_source" && m["right"] == 2054)
                || (matches!(chain, "ipv6_source" | "neighbor_source") && m["right"] == 34525));
        }
        !(m["left"] == json!({"meta":{"key":"l4proto"}})
            && m["right"] == 58
            && (chain == "neighbor_source" || icmp6))
    });
    expr.sort_by_key(Value::to_string);
    expr.push(verdict);
    Ok(())
}

fn normalize(v: &mut Value) {
    match v {
        Value::Array(a) => {
            for x in a {
                normalize(x);
            }
        }
        Value::Object(o) => {
            for value in o.values_mut() {
                normalize(value);
            }
            if let Some(values) = o.get_mut("set").and_then(Value::as_array_mut) {
                values.sort_by_key(Value::to_string);
            }
            if let Some(m) = o.get_mut("match") {
                if m["left"]["payload"]["protocol"] == "icmpv6"
                    && m["left"]["payload"]["field"] == "taddr"
                {
                    m["left"] = json!({"payload":{"base":"th","offset":64,"len":128}});
                }
                let p = m["left"]["payload"]["protocol"].as_str().unwrap_or("");
                let f = m["left"]["payload"]["field"].as_str().unwrap_or("");
                let meta = m["left"]["meta"]["key"].as_str().unwrap_or("");
                let convert = |v: &mut Value| {
                    let number = match (p, f, meta, v.as_str()) {
                        ("ether", "type", _, Some("ip")) => Some(2048),
                        ("ether", "type", _, Some("arp")) => Some(2054),
                        ("ether", "type", _, Some("ip6")) => Some(34525),
                        ("arp", "ptype", _, Some("ip")) => Some(2048),
                        ("arp", "operation", _, Some("request")) => Some(1),
                        ("arp", "operation", _, Some("reply")) => Some(2),
                        ("icmpv6", "type", _, Some("nd-neighbor-solicit")) => Some(135),
                        ("icmpv6", "type", _, Some("nd-neighbor-advert")) => Some(136),
                        ("icmpv6", "code", _, Some("no-route")) => Some(0),
                        ("ip6", "nexthdr", _, Some("ipv6-icmp"))
                        | (_, _, "l4proto", Some("ipv6-icmp")) => Some(58),
                        _ => v
                            .as_str()
                            .and_then(|s| s.strip_prefix("0x"))
                            .and_then(|s| u64::from_str_radix(s, 16).ok()),
                    };
                    if let Some(n) = number {
                        *v = json!(n);
                    }
                };
                let mut right = m["right"].clone();
                if m["left"]["payload"]["len"] == 128 && m["left"]["payload"]["offset"] == 64 {
                    let address = |value: &mut Value| {
                        if let Some(ip) = value.as_str().and_then(|s| s.parse::<Ipv6Addr>().ok()) {
                            *value = json!(format!("0x{:x}", ip.to_bits()));
                        }
                    };
                    if let Some(values) = right.get_mut("set").and_then(Value::as_array_mut) {
                        for value in values {
                            address(value);
                        }
                    } else {
                        address(&mut right);
                    }
                }
                if let Some(values) = right.get_mut("set").and_then(Value::as_array_mut) {
                    for v in values.iter_mut() {
                        convert(v);
                    }
                    values.sort_by_key(Value::to_string);
                } else {
                    convert(&mut right);
                }
                m["right"] = right;
            }
        }
        Value::String(s) => {
            if let Some(n) = s
                .strip_prefix("0x")
                .and_then(|s| u64::from_str_radix(s, 16).ok())
            {
                *v = json!(n);
            } else if let Some(n) = s
                .strip_prefix("0x")
                .and_then(|s| u128::from_str_radix(s, 16).ok())
            {
                *s = format!("0x{n:x}");
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod kernel_readback_tests {
    use super::*;

    struct Capture {
        allocation: Allocation,
        plan: SourcePlan,
        observation: Value,
    }
    fn captures() -> Vec<Capture> {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/source-kernel-rules.json"))
                .unwrap();
        fixture["captures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let allocation = serde_json::from_value(v["allocation"].clone()).unwrap();
                let scope = serde_json::from_value(v["scope"].clone()).unwrap();
                let plan = SourcePlan::new(&allocation, &scope).unwrap();
                Capture {
                    allocation,
                    plan,
                    observation: v["observation"].clone(),
                }
            })
            .collect()
    }

    #[test]
    fn accepted_native_source_tables_match_full_ownership_scope_and_rule_semantics() {
        let captures = captures();
        assert_eq!(captures.len(), 2);
        for Capture {
            allocation,
            plan,
            mut observation,
        } in captures
        {
            plan.verify(&allocation, &observation).unwrap();
            assert_eq!(
                SourcePlan::descriptor(&allocation, &observation).unwrap(),
                *plan.scope()
            );
            for entry in observation["nftables"].as_array_mut().unwrap() {
                if let Some(rule) = entry.get_mut("rule") {
                    rule["handle"] = json!(9999);
                    for part in rule["expr"].as_array_mut().unwrap() {
                        if let Some(counter) = part.get_mut("counter") {
                            counter["packets"] = json!(1234);
                            counter["bytes"] = json!(987654);
                        }
                    }
                }
            }
            plan.verify(&allocation, &observation).unwrap();
        }
    }

    #[test]
    fn native_source_table_mutations_refuse_widening_or_unknown_observations() {
        for Capture {
            allocation,
            plan,
            observation,
        } in captures()
        {
            let entries = observation["nftables"].as_array().unwrap();
            let rule_indices = entries
                .iter()
                .enumerate()
                .filter_map(|(i, v)| v.get("rule").map(|_| i))
                .collect::<Vec<_>>();
            let mut candidates = Vec::new();
            let mut missing = observation.clone();
            missing["nftables"]
                .as_array_mut()
                .unwrap()
                .remove(rule_indices[0]);
            candidates.push(missing);
            let mut order = observation.clone();
            order["nftables"]
                .as_array_mut()
                .unwrap()
                .swap(rule_indices[0], rule_indices[1]);
            candidates.push(order);
            let mut side_effect = observation.clone();
            side_effect["nftables"][rule_indices[0]]["rule"]["expr"]
                .as_array_mut()
                .unwrap()
                .insert(0, json!({"notrack":null}));
            candidates.push(side_effect);
            let mut bad_counter = observation.clone();
            let expr = bad_counter["nftables"][rule_indices[0]]["rule"]["expr"]
                .as_array_mut()
                .unwrap();
            expr.remove(expr.len() - 2);
            candidates.push(bad_counter);
            let mut extra = observation.clone();
            extra["nftables"].as_array_mut().unwrap().push(json!({"chain":{"family":"bridge","table":allocation.source_table(),"name":"extra"}}));
            candidates.push(extra);
            let mut dormant = observation.clone();
            dormant["nftables"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find_map(|v| v.get_mut("table"))
                .unwrap()["flags"] = json!(["dormant"]);
            candidates.push(dormant);
            let mut wrong_owner = observation.clone();
            wrong_owner["nftables"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .filter_map(|v| v.get_mut("chain"))
                .find(|c| {
                    c["name"]
                        .as_str()
                        .is_some_and(|n| n.starts_with("goldenhoop_"))
                })
                .unwrap()["name"] = json!("goldenhoop_foreign");
            candidates.push(wrong_owner);
            let mut missing_descriptor = observation.clone();
            let rows = missing_descriptor["nftables"].as_array_mut().unwrap();
            let index = rows
                .iter()
                .position(|v| {
                    v["chain"]["name"]
                        .as_str()
                        .is_some_and(|n| n.starts_with("cfg_"))
                })
                .unwrap();
            rows.remove(index);
            candidates.push(missing_descriptor);
            for kind in 0..6 {
                let mut changed = observation.clone();
                let mut found = false;
                'rules: for entry in changed["nftables"].as_array_mut().unwrap() {
                    let Some(rule) = entry.get_mut("rule") else {
                        continue;
                    };
                    for part in rule["expr"].as_array_mut().unwrap() {
                        if kind == 4
                            && let Some(target) = part.get("goto").cloned()
                        {
                            *part = json!({"jump":target});
                            found = true;
                            break 'rules;
                        }
                        if kind == 5 && part.get("drop").is_some() {
                            *part = json!({"accept":null});
                            found = true;
                            break 'rules;
                        }
                        let Some(m) = part.get_mut("match") else {
                            continue;
                        };
                        let left = &m["left"];
                        if kind == 0
                            && left["payload"]["protocol"] == "ether"
                            && left["payload"]["field"] == "saddr"
                        {
                            m["right"] = json!("02:00:00:00:00:02");
                        } else if kind == 1
                            && left["payload"]["offset"] == 192
                            && left["payload"]["len"] == 64
                        {
                            m["right"] = json!(m["right"].as_u64().unwrap() ^ 1);
                        } else if kind == 2 && left.get("&").is_some() {
                            m["left"]["&"][1] = json!(0x1fff_ffff_u64);
                        } else if kind == 3
                            && left["payload"]["protocol"] == "icmpv6"
                            && left["payload"]["field"] == "code"
                        {
                            m["right"] = json!(1);
                        } else {
                            continue;
                        }
                        found = true;
                        break 'rules;
                    }
                }
                assert!(found);
                candidates.push(changed);
            }
            for candidate in candidates {
                assert!(plan.verify(&allocation, &candidate).is_err());
            }
        }
    }
}
