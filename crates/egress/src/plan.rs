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

impl Config {
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
        allocation.validate()?;
        let mut p = Self {
            allocation,
            revision,
            batch: String::new(),
        };
        p.base();
        p.line("add rule", "guard counter drop");
        Ok(p)
    }

    pub fn compile(
        allocation: Allocation,
        revision: u64,
        config: &Config,
    ) -> Result<Self, ApiError> {
        Self::compile_mode(allocation, revision, config, None)
    }

    /// Explicit trusted DNS mode; callers must provide the concrete installer.
    pub fn compile_with_dns(
        allocation: Allocation,
        revision: u64,
        config: &Config,
    ) -> Result<Self, ApiError> {
        Self::compile_mode(allocation, revision, config, Some(SetNames::bootstrap()))
    }

    fn compile_mode(
        allocation: Allocation,
        revision: u64,
        config: &Config,
        dns: Option<SetNames>,
    ) -> Result<Self, ApiError> {
        allocation.validate()?;
        config.model()?;
        let mut p = Self {
            allocation,
            revision,
            batch: String::new(),
        };
        p.base();
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
                "live {{ \"{}\" timeout {LEASE_SECONDS}s }}",
                p.allocation.bridge
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

    fn base(&mut self) {
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
