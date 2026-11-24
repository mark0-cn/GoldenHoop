//! Candidate decisions only. DNS answers, leased grants, kernel installation,
//! credentials and capability publication require independent trusted checks.
use super::*;
use goldenhoop_protocol::NetworkRule;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    address: IpAddr,
    transport: Transport,
    port: Option<u16>,
}

impl Packet {
    pub fn new(address: IpAddr, transport: Transport, port: Option<u16>) -> Result<Self, ApiError> {
        if matches!(transport, Transport::Tcp | Transport::Udp) != port.is_some() || port == Some(0)
        {
            return Err(invalid("invalid candidate transport or port"));
        }
        Ok(Self {
            address: address.to_canonical(),
            transport,
            port,
        })
    }
    pub fn address(&self) -> IpAddr {
        self.address
    }
    pub fn transport(&self) -> Transport {
        self.transport
    }
    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionOrigin {
    PortFloor,
    DenyAlways(usize),
    AllowAlways(usize),
    UserDeny { level: usize, rule: Option<usize> },
    UserAgreement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub action: NetworkAction,
    pub origin: DecisionOrigin,
}

#[derive(Debug, Clone, Default)]
pub struct Overlays {
    deny: Vec<Rule>,
    allow: Vec<Rule>,
    tcp_cap: Option<BTreeSet<u16>>,
}

impl Overlays {
    /// Operator-owned lists, not caller-controlled user policy. Empty/missing
    /// TCP caps mean no floor, matching the pinned platform file semantics.
    pub fn compile(
        deny: &[NetworkRule],
        allow: &[NetworkRule],
        tcp_cap: Option<&[u16]>,
    ) -> Result<Self, ApiError> {
        fn compile_list(
            rules: &[NetworkRule],
            action: NetworkAction,
        ) -> Result<Vec<Rule>, ApiError> {
            if rules.len() > MAX_RULES {
                return Err(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "too many operator network rules",
                ));
            }
            for rule in rules {
                if rule.action != action {
                    return Err(invalid("operator overlay action does not match its role"));
                }
                if rule.destination.len() > MAX_TARGET_BYTES
                    || rule.ports.len() > MAX_PORTS_PER_RULE
                {
                    return Err(ApiError::new(
                        ErrorCode::QuotaExceeded,
                        "operator network rule exceeds limits",
                    ));
                }
            }
            Ok(Policy::compile(&NetworkPolicy {
                default_action: NetworkAction::Deny,
                rules: rules.to_vec(),
            })?
            .rules)
        }
        let tcp_cap = match tcp_cap.filter(|ports| !ports.is_empty()) {
            Some(ports) => {
                if ports.len() > 65535 {
                    return Err(ApiError::new(
                        ErrorCode::QuotaExceeded,
                        "operator port cap exceeds limits",
                    ));
                }
                if ports.contains(&0) {
                    return Err(invalid("operator port cap contains port zero"));
                }
                Some(ports.iter().copied().collect())
            }
            None => None,
        };
        Ok(Self {
            deny: compile_list(deny, NetworkAction::Deny)?,
            allow: compile_list(allow, NetworkAction::Allow)?,
            tcp_cap,
        })
    }
}

/// A bounded hierarchy of user policy layers, plus higher-authority overlays.
/// An allow decision is a proposal, never an installed or usable network grant.
pub struct Model {
    policies: Vec<Policy>,
    overlays: Overlays,
}

impl Model {
    pub fn new(policies: Vec<Policy>, overlays: Overlays) -> Result<Self, ApiError> {
        if policies.is_empty() || policies.len() > 5 {
            return Err(invalid(
                "network policy hierarchy must contain one to five levels",
            ));
        }
        Ok(Self { policies, overlays })
    }

    pub fn dns_candidate(&self, name: &Domain) -> Decision {
        self.decide(|rule| rule.matches_name(name))
    }

    pub fn address_candidate(&self, packet: &Packet) -> Decision {
        if packet.transport == Transport::Tcp
            && self
                .overlays
                .tcp_cap
                .as_ref()
                .is_some_and(|cap| !cap.contains(&packet.port.expect("validated TCP port")))
        {
            return Decision {
                action: NetworkAction::Deny,
                origin: DecisionOrigin::PortFloor,
            };
        }
        self.decide(|rule| rule.matches_address(packet))
    }

    fn decide(&self, matches: impl Fn(&Rule) -> bool) -> Decision {
        if let Some(index) = self.overlays.deny.iter().position(&matches) {
            return Decision {
                action: NetworkAction::Deny,
                origin: DecisionOrigin::DenyAlways(index),
            };
        }
        if let Some(index) = self.overlays.allow.iter().position(&matches) {
            return Decision {
                action: NetworkAction::Allow,
                origin: DecisionOrigin::AllowAlways(index),
            };
        }
        for (level, policy) in self.policies.iter().enumerate() {
            let mut allowed = false;
            for (index, rule) in policy
                .rules
                .iter()
                .enumerate()
                .filter(|(_, rule)| matches(rule))
            {
                if rule.action == NetworkAction::Deny {
                    return Decision {
                        action: NetworkAction::Deny,
                        origin: DecisionOrigin::UserDeny {
                            level,
                            rule: Some(index),
                        },
                    };
                }
                allowed = true;
            }
            if !allowed && policy.default_action == NetworkAction::Deny {
                return Decision {
                    action: NetworkAction::Deny,
                    origin: DecisionOrigin::UserDeny { level, rule: None },
                };
            }
        }
        Decision {
            action: NetworkAction::Allow,
            origin: DecisionOrigin::UserAgreement,
        }
    }
}

impl Rule {
    fn matches_name(&self, name: &Domain) -> bool {
        if !self.ports.is_empty() {
            return false;
        }
        match &self.destination {
            Destination::Any => true,
            Destination::Domain(domain) => domain == name,
            Destination::Subdomains(base) => name.is_subdomain_of(base),
            Destination::Address(_) | Destination::Network(_) => false,
        }
    }

    fn matches_address(&self, packet: &Packet) -> bool {
        if !self.ports.is_empty()
            && (packet.transport != Transport::Tcp
                || !self
                    .ports
                    .contains(&packet.port.expect("validated TCP port")))
        {
            return false;
        }
        match &self.destination {
            Destination::Any => true,
            Destination::Address(address) => *address == packet.address,
            Destination::Network(network) => network.contains(&packet.address),
            // A name rule is not an address permission. The real data plane
            // must validate and install a bounded DNS-source lease separately.
            Destination::Domain(_) | Destination::Subdomains(_) => false,
        }
    }
}
