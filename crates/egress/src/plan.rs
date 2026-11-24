use crate::error;
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
        allocation.validate()?;
        if config.policies.is_empty() || config.policies.len() > 5 {
            return Err(error(
                ErrorCode::InvalidRequest,
                "egress requires one to five policy levels",
            ));
        }
        // Validate operator authority before rendering any command.
        Overlays::compile(
            &config.deny_always,
            &config.allow_always,
            config.tcp_cap.as_deref(),
        )?;
        let policies = config
            .policies
            .iter()
            .map(Policy::compile)
            .collect::<Result<Vec<_>, _>>()?;
        let compile_overlay = |rules: &[NetworkRule]| {
            Policy::compile(&NetworkPolicy {
                default_action: NetworkAction::Deny,
                rules: rules.to_vec(),
            })
        };
        let deny = compile_overlay(&config.deny_always)?;
        let allow = compile_overlay(&config.allow_always)?;
        let mut p = Self {
            allocation,
            revision,
            batch: String::new(),
        };
        p.base();
        p.line("add chain", "decision");
        p.line("add rule", "guard iifname @live jump decision");
        p.line("add rule", "guard counter drop");
        if let Some(ports) = config.tcp_cap.as_ref().filter(|v| !v.is_empty()) {
            let ports = ports
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>();
            p.line(
                "add rule",
                &format!(
                    "decision meta l4proto tcp tcp dport != {{ {} }} counter drop",
                    join_ports(ports.iter())
                ),
            );
        }
        for rule in deny.rules() {
            p.rule("decision", rule, "drop")?;
        }
        for rule in allow.rules() {
            p.rule("decision", rule, "accept")?;
        }
        for (level, policy) in policies.iter().enumerate() {
            let chain = format!("level_{level}");
            p.line("add chain", &chain);
            p.line("add rule", &format!("decision jump {chain}"));
            for rule in policy
                .rules()
                .iter()
                .filter(|r| r.action() == NetworkAction::Deny)
            {
                p.rule(&chain, rule, "drop")?;
            }
            for rule in policy
                .rules()
                .iter()
                .filter(|r| r.action() == NetworkAction::Allow)
            {
                p.rule(&chain, rule, "return")?;
            }
            let verdict = if policy.default_action() == NetworkAction::Deny {
                "drop"
            } else {
                "return"
            };
            p.line("add rule", &format!("{chain} counter {verdict}"));
        }
        p.line("add rule", "decision counter accept");
        let bridge = p.allocation.bridge.clone();
        p.line(
            "add element",
            &format!("live {{ \"{bridge}\" timeout {LEASE_SECONDS}s }}"),
        );
        if p.batch.len() > MAX_BATCH {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "compiled egress policy exceeds batch limit",
            ));
        }
        Ok(p)
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

    fn rule(&mut self, chain: &str, rule: &Rule, verdict: &str) -> Result<(), ApiError> {
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
