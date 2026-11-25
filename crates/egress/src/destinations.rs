//! Immutable trusted destination-floor model. This does not install packet
//! rules, grant DNS answers or publish a runtime capability.
use crate::error;
use goldenhoop_protocol::{ApiError, ErrorCode};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, net::IpAddr};

const MAX_HOST_ADDRESSES: usize = 128;
const MAX_CONTROL_ADDRESSES: usize = 64;
const MAX_PRIVATE_EXCEPTIONS: usize = 32;
const VERSION: &str = "destination_floor_1";

// These are native destination addresses, not authority/URL identities.
// Metadata, platform, loopback, link-local and non-unicast ranges are never
// exempted. Standard translation prefixes remain refused until a deployment's
// translation path has its own enforcement contract.
const HARD: &[&str] = &[
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "100.100.100.200/32",
    "168.63.129.16/32",
    "::/96",
    "::ffff:0:0/96",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
    "fd00:ec2::254/128",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
];
const PRIVATE: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
];

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationScope {
    /// Must come from a trusted kernel inventory; this value alone is no proof
    /// that the current host still has these addresses.
    pub host_addresses: Vec<IpAddr>,
    /// Additional trusted control-service addresses, including virtual service
    /// addresses which do not appear on a host interface.
    pub control_addresses: Vec<IpAddr>,
    /// Administrator-owned private reachability exceptions. Never user policy.
    pub private_exceptions: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationClass {
    Protected,
    PrivateDenied,
    /// Exempts this floor's private restriction; grants no user permission.
    PrivateException,
    /// Outside this floor's lists; not a public-routability or permission claim.
    Other,
}
impl DestinationClass {
    pub fn blocked(self) -> bool {
        matches!(self, Self::Protected | Self::PrivateDenied)
    }
}

#[derive(Clone, Debug)]
pub struct ProtectedDestinations {
    scope: DestinationScope,
    pinned: BTreeSet<IpAddr>,
    hard: Vec<IpNet>,
    private: Vec<IpNet>,
    exceptions: Vec<IpNet>,
}
impl ProtectedDestinations {
    pub fn new(mut scope: DestinationScope) -> Result<Self, ApiError> {
        if scope.host_addresses.len() > MAX_HOST_ADDRESSES
            || scope.control_addresses.len() > MAX_CONTROL_ADDRESSES
            || scope.private_exceptions.len() > MAX_PRIVATE_EXCEPTIONS
            || scope.private_exceptions.iter().any(|s| s.len() > 64)
        {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "destination scope exceeds limits",
            ));
        }
        if scope
            .host_addresses
            .iter()
            .chain(&scope.control_addresses)
            .any(|ip| ip.to_canonical() != *ip)
        {
            return Err(error(
                ErrorCode::InvalidRequest,
                "destination scope requires native address families",
            ));
        }
        let hard = networks(HARD);
        let private = networks(PRIVATE);
        let mut exceptions = Vec::new();
        for text in &scope.private_exceptions {
            let invalid = || {
                error(
                    ErrorCode::InvalidRequest,
                    "private exception requires a canonical private subnet",
                )
            };
            let net = text.parse::<IpNet>().map_err(|_| invalid())?;
            if net.to_string() != *text
                || net != net.trunc()
                || !private.iter().any(|base| {
                    base.addr().is_ipv4() == net.addr().is_ipv4()
                        && base.prefix_len() <= net.prefix_len()
                        && base.contains(&net.addr())
                })
            {
                return Err(invalid());
            }
            exceptions.push(net);
        }
        exceptions.sort_by_key(ToString::to_string);
        exceptions.dedup();
        scope.private_exceptions = exceptions.iter().map(ToString::to_string).collect();
        scope.host_addresses.sort();
        scope.host_addresses.dedup();
        scope.control_addresses.sort();
        scope.control_addresses.dedup();
        let pinned = scope
            .host_addresses
            .iter()
            .chain(&scope.control_addresses)
            .copied()
            .collect();
        Ok(Self {
            scope,
            pinned,
            hard,
            private,
            exceptions,
        })
    }

    pub fn scope(&self) -> &DestinationScope {
        &self.scope
    }
    pub fn digest(&self) -> String {
        let descriptor = serde_json::json!({"version":VERSION,"scope":self.scope});
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&descriptor).expect("destination scope"))
        )
    }
    pub fn hard_networks(&self) -> &[IpNet] {
        &self.hard
    }
    pub fn private_networks(&self) -> &[IpNet] {
        &self.private
    }
    pub fn private_exceptions(&self) -> &[IpNet] {
        &self.exceptions
    }
    pub fn pinned_addresses(&self) -> &BTreeSet<IpAddr> {
        &self.pinned
    }

    /// Inspect the native packet/DNS-record family. Mapped IPv6 records stay
    /// protected rather than silently becoming a different-family exception.
    pub fn classify(&self, address: IpAddr) -> DestinationClass {
        if self.pinned.contains(&address) || contains(&self.hard, address) {
            DestinationClass::Protected
        } else if contains(&self.private, address) {
            if contains(&self.exceptions, address) {
                DestinationClass::PrivateException
            } else {
                DestinationClass::PrivateDenied
            }
        } else {
            DestinationClass::Other
        }
    }
}

fn networks(values: &[&str]) -> Vec<IpNet> {
    values
        .iter()
        .map(|s| s.parse().expect("built-in destination prefix"))
        .collect()
}
fn contains(networks: &[IpNet], address: IpAddr) -> bool {
    networks.iter().any(|net| net.contains(&address))
}
