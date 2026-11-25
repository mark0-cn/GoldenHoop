use crate::{dns::SetNames, error};
use goldenhoop_policy::{Destination, Overlays, Policy, Rule};
use goldenhoop_protocol::{ApiError, ErrorCode, NetworkAction, NetworkPolicy, NetworkRule};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const LEASE_SECONDS: u32 = 10;
const MAX_BATCH: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    pub installation_id: Uuid,
    pub sandbox_id: Uuid,
    pub generation: Uuid,
    pub bridge: String,
    pub ifindex: u32,
}

impl Allocation {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.installation_id.is_nil()
            || self.sandbox_id.is_nil()
            || self.generation.is_nil()
            || !(1..=i32::MAX as u32).contains(&self.ifindex)
            || !self.bridge.starts_with("gh")
            || !(3..=15).contains(&self.bridge.len())
            || !self
                .bridge
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return Err(error(
                ErrorCode::InvalidRequest,
                "invalid egress allocation",
            ));
        }
        Ok(())
    }

    pub fn table(&self) -> String {
        format!("gh_e_{}", self.generation.simple())
    }

    /// The trusted allocator must label its owned Linux bridge with this alias
    /// before a workload starts. This is an allocation binding, not a secret.
    pub fn owner(&self) -> String {
        let digest = Sha256::digest(serde_json::to_vec(self).expect("serializable allocation"));
        format!("goldenhoop:{digest:x}")
    }

    pub fn owner_chain(&self) -> String {
        self.owner().replace(':', "_")
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub policies: Vec<NetworkPolicy>,
    #[serde(default)]
    pub deny_always: Vec<NetworkRule>,
    #[serde(default)]
    pub allow_always: Vec<NetworkRule>,
    #[serde(default)]
    pub tcp_cap: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsBinding {
    pub(crate) address: std::net::IpAddr,
    pub(crate) port: u16,
}
impl DnsBinding {
    pub fn new(address: impl Into<std::net::IpAddr>, port: u16) -> Result<Self, ApiError> {
        let address = address.into();
        if address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || address.to_canonical() != address
            || matches!(address, std::net::IpAddr::V4(ip) if ip.is_broadcast())
            || matches!(address, std::net::IpAddr::V6(ip) if ip.is_unicast_link_local())
            || port < 1024
        {
            return Err(error(
                ErrorCode::InvalidRequest,
                "invalid owned DNS listener endpoint",
            ));
        }
        Ok(Self { address, port })
    }
    pub fn address(&self) -> std::net::IpAddr {
        self.address
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Debug, Clone)]
pub struct DnsBindings {
    pub(crate) v4: DnsBinding,
    pub(crate) v6: Option<DnsBinding>,
}
impl DnsBindings {
    pub fn new(v4: DnsBinding, v6: Option<DnsBinding>) -> Result<Self, ApiError> {
        if !v4.address.is_ipv4() || v6.as_ref().is_some_and(|b| !b.address.is_ipv6()) {
            return Err(error(
                ErrorCode::InvalidRequest,
                "DNS listener families differ",
            ));
        }
        Ok(Self { v4, v6 })
    }
    pub fn iter(&self) -> impl Iterator<Item = &DnsBinding> {
        std::iter::once(&self.v4).chain(self.v6.iter())
    }
}

impl Config {
    pub fn digest(&self) -> Result<String, ApiError> {
        self.model()?;
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).expect("serializable configuration"))
        ))
    }
    pub fn model(&self) -> Result<goldenhoop_policy::Model, ApiError> {
        if self.policies.is_empty() || self.policies.len() > 5 {
            return Err(error(
                ErrorCode::InvalidRequest,
                "egress requires one to five policy levels",
            ));
        }
        goldenhoop_policy::Model::new(
            self.policies
                .iter()
                .map(Policy::compile)
                .collect::<Result<Vec<_>, _>>()?,
            Overlays::compile(
                &self.deny_always,
                &self.allow_always,
                self.tcp_cap.as_deref(),
            )?,
        )
    }
}

pub struct Plan {
    pub(crate) allocation: Allocation,
    pub(crate) revision: u64,
    pub(crate) batch: String,
}

impl Plan {
    pub fn quarantine(allocation: Allocation, revision: u64) -> Result<Self, ApiError> {
        Self::quarantine_with_binding(allocation, revision, None)
    }

    pub fn quarantine_with_binding(
        allocation: Allocation,
        revision: u64,
        binding: Option<&DnsBindings>,
    ) -> Result<Self, ApiError> {
        allocation.validate()?;
        let mut p = Self {
            allocation,
            revision,
            batch: String::new(),
        };
        p.base(binding, false);
        p.line("add rule", "guard counter drop");
        Ok(p)
    }

    pub fn compile(
        allocation: Allocation,
        revision: u64,
        config: &Config,
    ) -> Result<Self, ApiError> {
        Self::compile_mode(
            allocation,
            revision,
            config,
            None,
            None,
            u64::from(LEASE_SECONDS) * 1000,
        )
    }

    /// Explicit trusted DNS mode; callers must provide the concrete installer.
    pub fn compile_with_dns(
        allocation: Allocation,
        revision: u64,
        config: &Config,
        binding: Option<&DnsBindings>,
    ) -> Result<Self, ApiError> {
        Self::compile_mode(
            allocation,
            revision,
            config,
            Some(SetNames::bootstrap()),
            binding,
            u64::from(LEASE_SECONDS) * 1000,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn compile_with_lease(
        allocation: Allocation,
        revision: u64,
        config: &Config,
        dns: bool,
        binding: Option<&DnsBindings>,
        milliseconds: u64,
    ) -> Result<Self, ApiError> {
        Self::compile_mode(
            allocation,
            revision,
            config,
            dns.then(SetNames::bootstrap),
            binding,
            milliseconds,
        )
    }

    fn compile_mode(
        allocation: Allocation,
        revision: u64,
        config: &Config,
        dns: Option<SetNames>,
        binding: Option<&DnsBindings>,
        milliseconds: u64,
    ) -> Result<Self, ApiError> {
        allocation.validate()?;
        config.model()?;
        if milliseconds == 0 || milliseconds > u64::from(LEASE_SECONDS) * 1000 {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "live policy lease is outside its bound",
            ));
        }
        let mut p = Self {
            allocation,
            revision,
            batch: String::new(),
        };
        p.base(binding, true);
        if let Some(names) = &dns {
            p.batch.push_str(&names.declarations(&p.allocation)?);
        }
        p.line("add chain", "decision");
        p.line("add rule", "guard iifname @live jump decision");
        p.line("add rule", "guard counter drop");
        p.decisions(config, dns.as_ref(), true)?;
        p.line(
            "add element",
            &format!(
                "live {{ \"{}\" timeout {} }}",
                p.allocation.bridge,
                if milliseconds == u64::from(LEASE_SECONDS) * 1000 {
                    format!("{LEASE_SECONDS}s")
                } else {
                    format!("{milliseconds}ms")
                }
            ),
        );
        p.bounded()?;
        Ok(p)
    }

    /// Swap chain references in one batch. Existing timed elements and the
    /// trusted controller's live set are never recreated or renewed here.
    pub fn activate_dns(
        allocation: Allocation,
        revision: u64,
        config: &Config,
        old: &SetNames,
        new: &SetNames,
    ) -> Result<Self, ApiError> {
        allocation.validate()?;
        config.model()?;
        let token = new
            .token()
            .filter(|token| Some(*token) != old.token())
            .ok_or_else(|| error(ErrorCode::InvalidRequest, "invalid DNS activation token"))?;
        let mut p = Self {
            allocation,
            revision,
            batch: String::new(),
        };
        p.line("flush chain", "decision");
        for level in 0..config.policies.len() {
            p.line("flush chain", &format!("level_{level}"));
        }
        p.decisions(config, Some(new), false)?;
        if let Some(previous) = old.token() {
            p.line("delete chain", &format!("dns_txn_{}", previous.simple()));
        }
        p.line("add chain", &format!("dns_txn_{}", token.simple()));
        for (name, _, _) in old.entries() {
            p.line("delete set", name);
        }
        p.bounded()?;
        Ok(p)
    }

    fn decisions(
        &mut self,
        config: &Config,
        dns: Option<&SetNames>,
        create: bool,
    ) -> Result<(), ApiError> {
        let policies = config
            .policies
            .iter()
            .map(Policy::compile)
            .collect::<Result<Vec<_>, _>>()?;
        let overlay = |rules: &[NetworkRule]| {
            Policy::compile(&NetworkPolicy {
                default_action: NetworkAction::Deny,
                rules: rules.to_vec(),
            })
        };
        let deny = overlay(&config.deny_always)?;
        let allow = overlay(&config.allow_always)?;
        if let Some(ports) = config.tcp_cap.as_ref().filter(|p| !p.is_empty()) {
            let ports = ports
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>();
            self.line(
                "add rule",
                &format!(
                    "decision meta l4proto tcp tcp dport != {{ {} }} counter drop",
                    join_ports(ports.iter())
                ),
            );
        }
        for rule in deny.rules() {
            self.rule("decision", rule, "drop", dns.is_some())?;
        }
        for rule in allow.rules() {
            self.rule("decision", rule, "accept", dns.is_some())?;
        }
        if let Some(names) = dns {
            self.line(
                "add rule",
                &format!("decision ip daddr @{} counter accept", names.operator_v4()),
            );
            self.line(
                "add rule",
                &format!("decision ip6 daddr @{} counter accept", names.operator_v6()),
            );
        }
        for (level, policy) in policies.iter().enumerate() {
            let chain = format!("level_{level}");
            if create {
                self.line("add chain", &chain);
            }
            self.line("add rule", &format!("decision jump {chain}"));
            for rule in policy
                .rules()
                .iter()
                .filter(|r| r.action() == NetworkAction::Deny)
            {
                self.rule(&chain, rule, "drop", dns.is_some())?;
            }
            if let Some(names) = dns {
                self.line(
                    "add rule",
                    &format!("{chain} ip daddr @{} counter return", names.user_v4()),
                );
                self.line(
                    "add rule",
                    &format!("{chain} ip6 daddr @{} counter return", names.user_v6()),
                );
            }
            for rule in policy
                .rules()
                .iter()
                .filter(|r| r.action() == NetworkAction::Allow)
            {
                self.rule(&chain, rule, "return", dns.is_some())?;
            }
            self.line(
                "add rule",
                &format!(
                    "{chain} counter {}",
                    if policy.default_action() == NetworkAction::Deny {
                        "drop"
                    } else {
                        "return"
                    }
                ),
            );
        }
        self.line("add rule", "decision counter accept");
        Ok(())
    }

    fn bounded(&self) -> Result<(), ApiError> {
        if self.batch.len() > MAX_BATCH {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "compiled egress policy exceeds batch limit",
            ));
        }
        Ok(())
    }

    fn base(&mut self, binding: Option<&DnsBindings>, ready: bool) {
        let table = self.allocation.table();
        self.batch.push_str(&format!("add table inet {table}\n"));
        self.line("add chain", &self.allocation.owner_chain());
        self.line("add chain", &format!("revision_{}", self.revision));
        self.line(
            "add set",
            &format!("live {{ type ifname; flags timeout; timeout {LEASE_SECONDS}s; }}"),
        );
        self.line(
            "add chain",
            "input { type filter hook input priority -190; policy accept; }",
        );
        // Scoped link-neighbor infrastructure, not an application permission.
        // Router advertisements, redirects and other host input stay denied.
        self.line("add rule", &format!("input meta iif {} ip6 hoplimit 255 icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} icmpv6 code 0 counter accept",self.allocation.ifindex));
        if binding.is_some() && ready {
            self.line(
                "add chain",
                "dns_pre { type nat hook prerouting priority -110; policy accept; }",
            );
            self.line(
                "add chain",
                "dns_out { type nat hook output priority -110; policy accept; }",
            );
        }
        for listener in binding.into_iter().flat_map(DnsBindings::iter) {
            let (family, nfproto, destination) = if listener.address.is_ipv4() {
                (
                    "ip",
                    "ipv4",
                    format!("{}:{}", listener.address, listener.port),
                )
            } else {
                (
                    "ip6",
                    "ipv6",
                    format!("[{}]:{}", listener.address, listener.port),
                )
            };
            for protocol in ["udp", "tcp"] {
                let endpoint = format!(
                    "{family} daddr {} {protocol} dport {}",
                    listener.address, listener.port
                );
                if ready {
                    self.line(
                        "add rule",
                        &format!(
                            "input meta iif {} {endpoint} counter accept",
                            self.allocation.ifindex
                        ),
                    );
                    self.line(
                        "add rule",
                        &format!("input iifname \"lo\" {endpoint} counter accept"),
                    );
                }
                self.line("add rule", &format!("input {endpoint} counter drop"));
                if ready {
                    self.line("add rule",&format!("dns_pre meta nfproto {nfproto} meta iif {} {protocol} dport 53 dnat {family} to {destination}",self.allocation.ifindex));
                    self.line(
                        "add rule",
                        &format!(
                            "dns_out {family} daddr {} {protocol} dport 53 dnat {family} to {destination}",
                            listener.address
                        ),
                    );
                }
            }
        }
        self.line(
            "add rule",
            &format!("input meta iif {} counter drop", self.allocation.ifindex),
        );
        self.line("add chain", "guard");
        self.line(
            "add chain",
            "forward { type filter hook forward priority -190; policy accept; }",
        );
        self.line(
            "add rule",
            &format!(
                "forward meta iif {} iifname \"{}\" jump guard",
                self.allocation.ifindex, self.allocation.bridge
            ),
        );
    }

    fn line(&mut self, operation: &str, tail: &str) {
        self.batch.push_str(&format!(
            "{operation} inet {} {tail}\n",
            self.allocation.table()
        ));
    }

    fn rule(
        &mut self,
        chain: &str,
        rule: &Rule,
        verdict: &str,
        names_enabled: bool,
    ) -> Result<(), ApiError> {
        let target = match rule.destination() {
            Destination::Any => String::new(),
            Destination::Address(ip) => {
                format!("{} daddr {ip} ", if ip.is_ipv4() { "ip" } else { "ip6" })
            }
            Destination::Network(net) => format!(
                "{} daddr {net} ",
                if net.addr().is_ipv4() { "ip" } else { "ip6" }
            ),
            Destination::Domain(_) | Destination::Subdomains(_) => {
                if names_enabled {
                    return Ok(());
                }
                return Err(error(
                    ErrorCode::UnsupportedCapability,
                    "host adapter requires static address targets until DNS lease integration",
                ));
            }
        };
        let ports = if rule.ports().is_empty() {
            String::new()
        } else {
            format!(
                "meta l4proto tcp tcp dport {{ {} }} ",
                join_ports(rule.ports().iter())
            )
        };
        self.line(
            "add rule",
            &format!("{chain} {target}{ports}counter {verdict}"),
        );
        Ok(())
    }

    pub fn script(&self) -> &str {
        &self.batch
    }
}

fn join_ports<'a>(ports: impl Iterator<Item = &'a u16>) -> String {
    ports.map(u16::to_string).collect::<Vec<_>>().join(", ")
}
