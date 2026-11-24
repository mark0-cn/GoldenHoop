//! Bounded network policy syntax and canonical targets. This performs no DNS,
//! packet admission, credential lookup or runtime capability advertisement.
use goldenhoop_protocol::{ApiError, ErrorCode, NetworkAction, NetworkPolicy};
use ipnet::IpNet;
use std::{collections::BTreeSet, net::IpAddr};

pub const MAX_RULES: usize = 256;
pub const MAX_PORTS_PER_RULE: usize = 256;
const MAX_TARGET_BYTES: usize = 1024;

mod decision;
pub use decision::{Decision, DecisionOrigin, Model, Overlays, Packet, Transport};

fn invalid(message: &'static str) -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest, message)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Domain(String);

impl Domain {
    pub fn parse(value: &str) -> Result<Self, ApiError> {
        if value.is_empty()
            || value.len() > MAX_TARGET_BYTES
            || value
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err(invalid("invalid network domain length"));
        }
        // UTS46 mapping plus explicit DNS/LDH bounds. Hyphens in positions 3/4
        // remain valid for real CDN/GitHub names; underscores and URI syntax do
        // not become hostnames. A single canonical root dot is permitted.
        let ascii = idna::domain_to_ascii_cow(value.as_bytes(), idna::AsciiDenyList::STD3)
            .map_err(|_| invalid("invalid network domain"))?;
        let ascii = ascii.strip_suffix('.').unwrap_or(&ascii);
        if ascii.is_empty() || ascii.len() > 253 {
            return Err(invalid("invalid network domain length"));
        }
        for label in ascii.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(invalid("invalid network domain label"));
            }
        }
        let last = ascii.rsplit('.').next().expect("nonempty domain");
        // URL/libc resolvers can interpret shortened, integer, hexadecimal or
        // zero-prefixed numeric hosts as IPv4. They must never fall through to
        // a name rule and evade an address restriction.
        if last.bytes().all(|byte| byte.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .is_some_and(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(invalid("numeric address syntax is not a network domain"));
        }
        Ok(Self(ascii.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// DNS label-boundary matching only; this establishes no name/address trust.
    pub fn is_subdomain_of(&self, base: &Self) -> bool {
        self.0
            .strip_suffix(&base.0)
            .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    Any,
    Address(IpAddr),
    Network(IpNet),
    Domain(Domain),
    Subdomains(Domain),
}

impl Destination {
    pub fn parse(value: &str) -> Result<Self, ApiError> {
        if value.is_empty()
            || value.len() > MAX_TARGET_BYTES
            || value
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err(invalid("invalid network target"));
        }
        if value == "*" {
            return Ok(Self::Any);
        }
        if let Some(base) = value.strip_prefix("*.") {
            return Ok(Self::Subdomains(Domain::parse(base)?));
        }
        if value.contains('/') {
            let network: IpNet = value.parse().map_err(|_| invalid("invalid network CIDR"))?;
            if network.addr() != network.network() {
                return Err(invalid("network CIDR contains host bits"));
            }
            let network = match network {
                IpNet::V6(ipv6) if ipv6.addr().to_ipv4_mapped().is_some() => {
                    let prefix = ipv6
                        .prefix_len()
                        .checked_sub(96)
                        .ok_or_else(|| invalid("ambiguous IPv4-mapped network prefix"))?;
                    IpNet::new(
                        IpAddr::V4(ipv6.addr().to_ipv4_mapped().expect("mapped address")),
                        prefix,
                    )
                    .map_err(|_| invalid("invalid IPv4-mapped network prefix"))?
                }
                network => network,
            };
            return Ok(Self::Network(network));
        }
        let without_root_dot = value.strip_suffix('.').unwrap_or(value);
        if let Ok(address) = without_root_dot.parse::<IpAddr>() {
            return Ok(Self::Address(address.to_canonical()));
        }
        Ok(Self::Domain(Domain::parse(value)?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    destination: Destination,
    /// A nonempty set qualifies TCP only. Empty means unqualified transport.
    ports: BTreeSet<u16>,
    action: NetworkAction,
}

impl Rule {
    pub fn destination(&self) -> &Destination {
        &self.destination
    }
    pub fn ports(&self) -> &BTreeSet<u16> {
        &self.ports
    }
    pub fn action(&self) -> NetworkAction {
        self.action
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    default_action: NetworkAction,
    rules: Vec<Rule>,
}

impl Policy {
    pub fn compile(value: &NetworkPolicy) -> Result<Self, ApiError> {
        if value.rules.len() > MAX_RULES {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "too many network rules",
            ));
        }
        let mut rules = Vec::with_capacity(value.rules.len());
        for rule in &value.rules {
            if rule.ports.len() > MAX_PORTS_PER_RULE {
                return Err(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "too many network rule ports",
                ));
            }
            if rule.ports.contains(&0) {
                return Err(invalid("network port zero is invalid"));
            }
            let destination = Destination::parse(&rule.destination)?;
            if !rule.ports.is_empty()
                && matches!(
                    destination,
                    Destination::Domain(_) | Destination::Subdomains(_)
                )
            {
                return Err(invalid(
                    "network ports qualify only IP, CIDR or wildcard targets",
                ));
            }
            rules.push(Rule {
                destination,
                ports: rule.ports.iter().copied().collect(),
                action: rule.action,
            });
        }
        Ok(Self {
            default_action: value.default_action,
            rules,
        })
    }

    pub fn default_action(&self) -> NetworkAction {
        self.default_action
    }
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}
