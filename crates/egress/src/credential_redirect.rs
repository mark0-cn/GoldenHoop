//! Allocation-owned transparent TCP ingress. Reuses the existing exact trusted
//! DNS TCP endpoint, without adding a host/private destination exemption.
use crate::{Allocation, DnsBinding, DnsBindings, error};
use goldenhoop_credentials::Scheme;
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledCredentials {
    pub epoch: Uuid,
    pub bindings: BTreeMap<Uuid, u64>,
    pub public_ca_sha256: String,
    pub redirect: CredentialRedirect,
    pub observed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRedirect {
    pub v4: DnsBinding,
    pub v6: Option<DnsBinding>,
    /// A port has one wire protocol. Mixed HTTP/TLS bindings on a single port
    /// cannot be distinguished safely before the first authenticated request.
    pub ports: BTreeMap<u16, Scheme>,
}
impl CredentialRedirect {
    pub fn bindings(&self) -> Result<DnsBindings, ApiError> {
        if self.ports.is_empty()
            || self.ports.len() > 256
            || self.ports.contains_key(&0)
            || self.ports.contains_key(&53)
        {
            return Err(error(
                ErrorCode::InvalidRequest,
                "invalid credential redirect ports",
            ));
        }
        DnsBindings::new(self.v4.clone(), self.v6.clone())
    }
    pub fn digest(&self) -> String {
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).expect("redirect definition"))
        )
    }
}
impl Allocation {
    pub fn credential_table(&self) -> String {
        format!("gh_c_{}", self.generation.simple())
    }
}
pub struct CredentialRedirectPlan {
    definition: CredentialRedirect,
    script: String,
    rules: Vec<Vec<Value>>,
}
fn bad() -> ApiError {
    error(ErrorCode::Conflict, "native credential redirect differs")
}

impl CredentialRedirectPlan {
    pub fn new(a: &Allocation, definition: CredentialRedirect) -> Result<Self, ApiError> {
        a.validate()?;
        let bindings = definition.bindings()?;
        let table = a.credential_table();
        let mut script = format!(
            "add table inet {table}\nadd chain inet {table} {}\nadd chain inet {table} credential_redirect_1\nadd chain inet {table} binding_{}\n",
            a.owner_chain(),
            definition.digest()
        );
        let descriptor = serde_json::to_vec(&definition).expect("redirect descriptor");
        for (index, bytes) in descriptor.chunks(64).enumerate() {
            let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            script.push_str(&format!("add chain inet {table} cfg_{index:03}_{hex}\n"));
        }
        script.push_str(&format!("add chain inet {table} prerouting {{ type nat hook prerouting priority -105; policy accept; }}\n"));
        let mut rules = Vec::new();
        // The original destination floor (-210) has already run. Only this
        // allocation's verified ingress is redirected; SO_ORIGINAL_DST and
        // exact source ownership are checked again before opening upstream.
        for listener in bindings.iter() {
            let (family, number, endpoint) = if listener.address().is_ipv4() {
                (
                    "ip",
                    2,
                    format!("{}:{}", listener.address(), listener.port()),
                )
            } else {
                (
                    "ip6",
                    10,
                    format!("[{}]:{}", listener.address(), listener.port()),
                )
            };
            for port in definition.ports.keys() {
                script.push_str(&format!("add rule inet {table} prerouting iifname \"{}\" meta iif {} meta nfproto {number} tcp dport {port} counter dnat {family} to {endpoint}\n",a.bridge,a.ifindex));
                rules.push(vec![
                    json!({"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":a.bridge}}),
                    json!({"match":{"op":"==","left":{"meta":{"key":"iif"}},"right":a.ifindex}}),
                    json!({"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":number}}),
                    json!({"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":port}}),
                    json!({"dnat":{"family":family,"addr":listener.address(),"port":listener.port()}}),
                ]);
            }
        }
        Ok(Self {
            definition,
            script,
            rules,
        })
    }
    pub fn script(&self) -> &str {
        &self.script
    }
    pub fn definition(&self) -> &CredentialRedirect {
        &self.definition
    }

    /// Ownership/descriptor recovery supports cleanup of a damaged rule set;
    /// only verify() can attest the live forwarding path.
    pub fn descriptor(a: &Allocation, value: &Value) -> Result<CredentialRedirect, ApiError> {
        let rows = value["nftables"].as_array().ok_or_else(bad)?;
        let mut owners = Vec::new();
        let mut chunks = BTreeMap::new();
        let mut versions = 0;
        let mut bindings = Vec::new();
        let mut tables = 0;
        for row in rows {
            if let Some(t) = row.get("table") {
                if t["family"] != "inet" || t["name"] != a.credential_table() {
                    return Err(bad());
                }
                tables += 1;
            }
            if let Some(c) = row.get("chain") {
                if c["family"] != "inet" || c["table"] != a.credential_table() {
                    return Err(bad());
                }
                let name = c["name"].as_str().ok_or_else(bad)?;
                if name.starts_with("goldenhoop_") {
                    owners.push(name.to_owned());
                }
                if name == "credential_redirect_1" {
                    versions += 1;
                }
                if let Some(d) = name.strip_prefix("binding_") {
                    bindings.push(d.to_owned());
                }
                if let Some(chunk) = name.strip_prefix("cfg_") {
                    let (index, hex) = chunk.split_once('_').ok_or_else(bad)?;
                    let index = index.parse::<usize>().map_err(|_| bad())?;
                    if hex.len() > 128
                        || hex.len() % 2 != 0
                        || chunks.insert(index, hex.to_owned()).is_some()
                    {
                        return Err(bad());
                    }
                }
            }
        }
        if tables != 1 || owners != [a.owner_chain()] || versions != 1 || chunks.len() > 160 {
            return Err(bad());
        }
        let mut bytes = Vec::new();
        for (expected, (index, hex)) in chunks.into_iter().enumerate() {
            if expected != index {
                return Err(bad());
            }
            for part in hex.as_bytes().as_chunks::<2>().0 {
                let part = std::str::from_utf8(part).map_err(|_| bad())?;
                bytes.push(u8::from_str_radix(part, 16).map_err(|_| bad())?);
            }
        }
        let definition: CredentialRedirect = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        definition.bindings()?;
        if bindings != [definition.digest()] {
            return Err(bad());
        }
        Ok(definition)
    }
    pub fn verify(&self, a: &Allocation, value: &Value) -> Result<(), ApiError> {
        if Self::descriptor(a, value)?.digest() != self.definition.digest() {
            return Err(bad());
        }
        let mut chains = BTreeMap::new();
        let mut rules = Vec::new();
        for row in value["nftables"].as_array().ok_or_else(bad)? {
            let object = row.as_object().filter(|v| v.len() == 1).ok_or_else(bad)?;
            let (kind, value) = object.iter().next().ok_or_else(bad)?;
            if kind == "metainfo" {
                continue;
            }
            let allowed: &[&str] = match kind.as_str() {
                "table" => &["family", "name", "handle"],
                "chain" => &[
                    "family", "table", "name", "handle", "type", "hook", "prio", "policy",
                ],
                "rule" => &["family", "table", "chain", "handle", "expr"],
                _ => return Err(bad()),
            };
            let attrs = value
                .as_object()
                .filter(|v| v.keys().all(|k| allowed.contains(&k.as_str())))
                .ok_or_else(bad)?;
            if value["family"] != "inet"
                || (kind != "table" && value["table"] != a.credential_table())
            {
                return Err(bad());
            }
            if kind == "chain" {
                let name = value["name"].as_str().ok_or_else(bad)?.to_owned();
                let shape = Value::Object(
                    attrs
                        .iter()
                        .filter(|(k, _)| {
                            !matches!(k.as_str(), "family" | "table" | "name" | "handle")
                        })
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                );
                if chains.insert(name, shape).is_some() {
                    return Err(bad());
                }
            } else if kind == "rule" {
                if value["chain"] != "prerouting" {
                    return Err(bad());
                }
                let mut expr = value["expr"].as_array().ok_or_else(bad)?.clone();
                crate::policy_readback::normalize(a, &mut expr)?;
                rules.push(expr);
            }
        }
        let expected = Self::new(a, self.definition.clone())?;
        let descriptor = serde_json::to_vec(&self.definition).expect("descriptor");
        let mut wanted = BTreeMap::from([
            (a.owner_chain(), json!({})),
            ("credential_redirect_1".into(), json!({})),
            (format!("binding_{}", self.definition.digest()), json!({})),
            (
                "prerouting".into(),
                json!({"type":"nat","hook":"prerouting","prio":-105,"policy":"accept"}),
            ),
        ]);
        for (i, bytes) in descriptor.chunks(64).enumerate() {
            wanted.insert(
                format!(
                    "cfg_{i:03}_{}",
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                ),
                json!({}),
            );
        }
        if chains != wanted || rules != expected.rules {
            return Err(bad());
        }
        Ok(())
    }
}
