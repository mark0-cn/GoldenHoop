use crate::{Allocation, Config, EthernetPlan, LEASE_SECONDS, Plan, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    os::{
        linux::net::SocketAddrExt,
        unix::{
            fs::MetadataExt,
            net::{SocketAddr, UnixDatagram},
        },
    },
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

const NFT: &str = "/usr/sbin/nft";
const MAX_OUTPUT: u64 = 4 * 1024 * 1024;
mod resolver;
mod source;
pub use resolver::{Listening, Resolution};

#[derive(Debug, Serialize)]
pub struct Observation {
    pub installed: bool,
    pub revision: Option<u64>,
    pub uncertain: bool,
    pub table_sha256: Option<String>,
    pub maximum_lease_seconds: u32,
    pub ethernet_guarded: bool,
    pub ethernet_sha256: Option<String>,
    pub source_guarded: bool,
    pub source_binding_sha256: Option<String>,
}

pub struct Manager {
    allocation: Allocation,
    revision: Option<u64>,
    uncertain: bool,
    can_renew: bool,
    lease_until: Option<Instant>,
    dns: Option<resolver::DnsState>,
    ethernet_required: bool,
    source_scope: Option<crate::SourceScope>,
    // Abstract Unix names share the host network namespace, including across
    // containers with distinct /run mounts. Dropping the process releases it.
    _lock: UnixDatagram,
}

impl Manager {
    pub async fn new(allocation: Allocation) -> Result<Self, ApiError> {
        allocation.validate()?;
        let status = std::fs::read_to_string("/proc/self/status").map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "cannot inspect manager credentials",
            )
        })?;
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
        };
        let only_net_admin = |value: Option<&str>| {
            value.and_then(|v| u64::from_str_radix(v, 16).ok()) == Some(1 << 12)
        };
        if !only_net_admin(field("CapEff:"))
            || !only_net_admin(field("CapPrm:"))
            || field("NoNewPrivs:") != Some("1")
        {
            return Err(error(
                ErrorCode::Forbidden,
                "manager requires only NET_ADMIN and no-new-privileges",
            ));
        }
        let meta = std::fs::symlink_metadata(NFT).map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "trusted nft executable is unavailable",
            )
        })?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(error(ErrorCode::Forbidden, "untrusted nft executable"));
        }
        let address = SocketAddr::from_abstract_name(allocation.owner().as_bytes())
            .map_err(|_| error(ErrorCode::InvalidRequest, "invalid manager lock name"))?;
        let lock = UnixDatagram::bind_addr(&address).map_err(|_| {
            error(
                ErrorCode::Conflict,
                "allocation already has a packet-filter controller",
            )
        })?;
        let mut manager = Self {
            allocation,
            revision: None,
            uncertain: false,
            can_renew: false,
            lease_until: None,
            dns: None,
            ethernet_required: false,
            source_scope: None,
            _lock: lock,
        };
        // Reconcile the immutable floor on attachment. A restart cannot forget
        // an existing owned guard and silently continue without it later.
        manager.ethernet_required = manager.ethernet().await?.is_some();
        if let Some(observed) = manager.source_guard().await? {
            manager.uncertain = !observed.healthy || !manager.ethernet_required;
            manager.ethernet_required = true;
            manager.source_scope = Some(observed.scope);
        }
        Ok(manager)
    }

    fn check_bridge(&self) -> Result<(), ApiError> {
        let path = Path::new("/sys/class/net").join(&self.allocation.bridge);
        let observed = std::fs::read_to_string(path.join("ifindex"))
            .map_err(|_| error(ErrorCode::Conflict, "allocated bridge is unavailable"))?;
        let alias = std::fs::read_to_string(path.join("ifalias"))
            .map_err(|_| error(ErrorCode::Conflict, "allocated bridge alias is unavailable"))?;
        if observed.trim().parse::<u32>().ok() != Some(self.allocation.ifindex)
            || alias.trim_end_matches('\n') != self.allocation.owner()
            || !path.join("bridge").is_dir()
        {
            return Err(error(
                ErrorCode::Conflict,
                "bridge allocation identity changed",
            ));
        }
        if let Some(bindings) = self.dns.as_ref().and_then(|s| s.binding.as_ref()) {
            let addresses = crate::frontend::bridge_addresses(&self.allocation.bridge)?;
            let observed = std::iter::once(std::net::IpAddr::V4(addresses.v4))
                .chain(addresses.v6.map(std::net::IpAddr::V6))
                .collect::<std::collections::BTreeSet<_>>();
            let bound = bindings
                .iter()
                .map(|b| b.address())
                .collect::<std::collections::BTreeSet<_>>();
            if observed != bound {
                return Err(error(ErrorCode::Conflict, "bound bridge addresses changed"));
            }
        }
        if let Some(scope) = &self.source_scope {
            self.check_source_scope(scope)?;
        }
        Ok(())
    }

    async fn table(&self) -> Result<Option<(u64, Value)>, ApiError> {
        let value: Value = serde_json::from_slice(&nft(&["--json", "list", "tables"], None).await?)
            .map_err(|_| error(ErrorCode::BackendUnavailable, "invalid nft table inventory"))?;
        let entries = value["nftables"]
            .as_array()
            .ok_or_else(|| error(ErrorCode::BackendUnavailable, "missing nft table inventory"))?;
        let table = self.allocation.table();
        if !entries
            .iter()
            .any(|entry| entry["table"]["family"] == "inet" && entry["table"]["name"] == table)
        {
            return Ok(None);
        }
        let value: Value =
            serde_json::from_slice(&nft(&["--json", "list", "table", "inet", &table], None).await?)
                .map_err(|_| {
                    error(
                        ErrorCode::BackendUnavailable,
                        "invalid nft table observation",
                    )
                })?;
        let entries = value["nftables"].as_array().ok_or_else(|| {
            error(
                ErrorCode::BackendUnavailable,
                "missing nft table observation",
            )
        })?;
        let tables = entries
            .iter()
            .filter_map(|e| e.get("table"))
            .collect::<Vec<_>>();
        if tables.len() != 1 || tables[0]["family"] != "inet" || tables[0]["name"] != table {
            return Err(error(ErrorCode::Conflict, "nft table identity differs"));
        }
        let chains = entries
            .iter()
            .filter_map(|e| e.get("chain"))
            .collect::<Vec<_>>();
        let owners = chains
            .iter()
            .filter_map(|c| c["name"].as_str())
            .filter(|n| n.starts_with("goldenhoop_"))
            .collect::<Vec<_>>();
        let revisions = chains
            .iter()
            .filter_map(|c| c["name"].as_str())
            .filter_map(|n| n.strip_prefix("revision_"))
            .collect::<Vec<_>>();
        if owners != [self.allocation.owner_chain()]
            || revisions.len() != 1
            || chains
                .iter()
                .any(|c| c["family"] != "inet" || c["table"] != table)
        {
            return Err(error(
                ErrorCode::Conflict,
                "nft allocation ownership differs",
            ));
        }
        let revision = revisions[0]
            .parse::<u64>()
            .map_err(|_| error(ErrorCode::Conflict, "invalid nft policy revision"))?;
        if revisions[0] != revision.to_string() {
            return Err(error(
                ErrorCode::Conflict,
                "noncanonical nft policy revision",
            ));
        }
        Ok(Some((revision, value)))
    }

    pub async fn inspect(&self) -> Result<Observation, ApiError> {
        let table = self.table().await?;
        let ethernet = self.ethernet().await?;
        let source = self.source_guard().await?;
        Ok(Observation {
            installed: table.is_some(),
            revision: table.as_ref().map(|(r, _)| *r),
            uncertain: self.uncertain
                || (self.ethernet_required && ethernet.is_none())
                || !self.source_matches(source.as_ref()),
            table_sha256: table.map(|(_, v)| {
                format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&v).expect("JSON value"))
                )
            }),
            maximum_lease_seconds: LEASE_SECONDS,
            ethernet_guarded: ethernet.is_some(),
            ethernet_sha256: ethernet.map(|v| {
                format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&v).expect("JSON value"))
                )
            }),
            source_guarded: source.as_ref().is_some_and(|s| s.healthy)
                && self.source_matches(source.as_ref()),
            source_binding_sha256: source.map(|s| s.scope.digest()),
        })
    }

    async fn ethernet(&self) -> Result<Option<Value>, ApiError> {
        let table = self.allocation.ethernet_table();
        let inventory: Value =
            serde_json::from_slice(&nft(&["--json", "list", "tables"], None).await?)
                .map_err(|_| error(ErrorCode::BackendUnavailable, "invalid nft table inventory"))?;
        let entries = inventory["nftables"]
            .as_array()
            .ok_or_else(|| error(ErrorCode::BackendUnavailable, "missing nft table inventory"))?;
        if !entries
            .iter()
            .any(|e| e["table"]["family"] == "bridge" && e["table"]["name"] == table)
        {
            return Ok(None);
        }
        let observed: Value = serde_json::from_slice(
            &nft(&["--json", "list", "table", "bridge", &table], None).await?,
        )
        .map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "invalid Ethernet guard observation",
            )
        })?;
        EthernetPlan::verify(&self.allocation, &observed)?;
        Ok(Some(observed))
    }

    /// Install the immutable route-only floor before workload publication. A
    /// missing bridge-family kernel feature is a hard failure, never fallback.
    pub async fn enable_ethernet(&mut self, expected: u64) -> Result<Observation, ApiError> {
        if self.uncertain || self.can_renew || self.revision != Some(expected) {
            return Err(error(
                ErrorCode::InvalidState,
                "enable Ethernet only after known quarantine",
            ));
        }
        self.expected(expected).await?;
        if self.ethernet().await?.is_some() {
            return Err(error(ErrorCode::Conflict, "Ethernet guard already exists"));
        }
        let plan = EthernetPlan::new(&self.allocation)?;
        self.ethernet_required = true;
        self.uncertain = true;
        self.can_renew = false;
        self.lease_until = None;
        nft(&["--file", "-"], Some(plan.script().as_bytes())).await?;
        let observed = self.inspect().await?;
        self.check_bridge()?;
        if !observed.ethernet_guarded || observed.revision != Some(expected) {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "Ethernet guard installation is unconfirmed",
            ));
        }
        self.uncertain = false;
        Ok(Observation {
            uncertain: false,
            ..observed
        })
    }

    pub async fn install(&mut self) -> Result<Observation, ApiError> {
        self.check_bridge()?;
        if self.table().await?.is_some() || self.uncertain {
            return Err(error(
                ErrorCode::Conflict,
                "egress table already exists or is uncertain",
            ));
        }
        self.commit(Plan::quarantine(self.allocation.clone(), 0)?, false, false)
            .await
    }

    async fn expected(&self, expected: u64) -> Result<(), ApiError> {
        self.check_bridge()?;
        if self.table().await?.map(|(r, _)| r) != Some(expected) {
            return Err(error(ErrorCode::Conflict, "egress policy revision differs"));
        }
        if self.ethernet_required && self.ethernet().await?.is_none() {
            return Err(error(
                ErrorCode::Conflict,
                "required Ethernet guard is unavailable",
            ));
        }
        if !self.source_matches(self.source_guard().await?.as_ref()) {
            return Err(error(
                ErrorCode::Conflict,
                "required source guard is unavailable or changed",
            ));
        }
        Ok(())
    }

    pub async fn apply(&mut self, expected: u64, config: &Config) -> Result<Observation, ApiError> {
        self.check_lifetime()?;
        if self.uncertain || self.revision != Some(expected) {
            return Err(error(
                ErrorCode::InvalidState,
                "quarantine is required before policy changes",
            ));
        }
        let next = expected
            .checked_add(1)
            .ok_or_else(|| error(ErrorCode::Conflict, "egress revision exhausted"))?;
        let model = self.dns.as_ref().map(|_| config.model()).transpose()?;
        let plan = if self.dns.is_some() {
            Plan::compile_with_dns(
                self.allocation.clone(),
                next,
                config,
                self.dns.as_ref().and_then(|state| state.binding.as_ref()),
            )?
        } else {
            Plan::compile(self.allocation.clone(), next, config)?
        };
        self.expected(expected).await?;
        let observed = self.commit(plan, true, true).await?;
        if let Some(dns) = &mut self.dns {
            dns.model = model;
            dns.config = Some(config.clone());
            dns.book = Some(crate::dns::LeaseBook::new(next, dns.deadline));
            dns.active = crate::dns::SetNames::bootstrap();
        }
        Ok(observed)
    }

    /// Recovery always replaces an owned policy with quarantine before any
    /// further lease. Reading a revision alone cannot authorize renewal.
    pub async fn quarantine(&mut self, expected: u64) -> Result<Observation, ApiError> {
        let next = expected
            .checked_add(1)
            .ok_or_else(|| error(ErrorCode::Conflict, "egress revision exhausted"))?;
        self.expected(expected).await?;
        let observed = self
            .commit(
                Plan::quarantine_with_binding(
                    self.allocation.clone(),
                    next,
                    self.dns.as_ref().and_then(|state| state.binding.as_ref()),
                )?,
                true,
                false,
            )
            .await?;
        if let Some(dns) = &mut self.dns {
            dns.invalidate(next);
        }
        Ok(observed)
    }

    async fn commit(
        &mut self,
        plan: Plan,
        replace: bool,
        can_renew: bool,
    ) -> Result<Observation, ApiError> {
        let mut batch = String::new();
        if replace {
            batch.push_str(&format!("delete table inet {}\n", self.allocation.table()));
        }
        batch.push_str(&plan.batch);
        self.uncertain = true;
        self.can_renew = false;
        self.lease_until = None;
        let started = Instant::now();
        nft(&["--file", "-"], Some(batch.as_bytes())).await?;
        let observed = self.inspect().await?;
        if observed.revision != Some(plan.revision)
            || (self.ethernet_required && !observed.ethernet_guarded)
            || (self.source_scope.is_some() && !observed.source_guarded)
        {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "kernel did not confirm policy revision",
            ));
        }
        self.revision = Some(plan.revision);
        self.uncertain = false;
        self.can_renew = can_renew;
        self.lease_until = can_renew
            .then_some(started + Duration::from_millis(u64::from(LEASE_SECONDS) * 1000 - 11));
        Ok(Observation {
            uncertain: false,
            ..observed
        })
    }

    pub async fn renew(&mut self, expected: u64) -> Result<Observation, ApiError> {
        self.check_lifetime()?;
        if self.uncertain || !self.can_renew || self.revision != Some(expected) {
            return Err(error(
                ErrorCode::InvalidState,
                "egress lease is not renewable",
            ));
        }
        self.expected(expected).await?;
        let batch = format!(
            "flush set inet {} live\nadd element inet {} live {{ \"{}\" timeout {LEASE_SECONDS}s }}\n",
            self.allocation.table(),
            self.allocation.table(),
            self.allocation.bridge
        );
        self.uncertain = true;
        self.can_renew = false;
        self.lease_until = None;
        let started = Instant::now();
        nft(&["--file", "-"], Some(batch.as_bytes())).await?;
        let observed = self.inspect().await?;
        if observed.revision != Some(expected)
            || (self.ethernet_required && !observed.ethernet_guarded)
            || (self.source_scope.is_some() && !observed.source_guarded)
        {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "kernel did not confirm lease revision",
            ));
        }
        self.uncertain = false;
        self.can_renew = true;
        self.lease_until =
            Some(started + Duration::from_millis(u64::from(LEASE_SECONDS) * 1000 - 11));
        Ok(Observation {
            uncertain: false,
            ..observed
        })
    }

    pub async fn remove(&mut self, expected: u64) -> Result<Observation, ApiError> {
        // No live network may lose its deny boundary. The caller must collect
        // all endpoints and the owned network, then request table removal.
        if Path::new("/sys/class/net")
            .join(&self.allocation.bridge)
            .try_exists()
            .map_err(|_| {
                error(
                    ErrorCode::BackendUnavailable,
                    "cannot inspect bridge collection",
                )
            })?
        {
            return Err(error(
                ErrorCode::Conflict,
                "collect the bridge before removing its filter",
            ));
        }
        let mut batch = String::new();
        if let Some((revision, _)) = self.table().await? {
            if revision != expected {
                return Err(error(ErrorCode::Conflict, "egress policy revision differs"));
            }
            batch.push_str(&format!("delete table inet {}\n", self.allocation.table()));
        }
        if self.ethernet().await?.is_some() {
            batch.push_str(&format!(
                "delete table bridge {}\n",
                self.allocation.ethernet_table()
            ));
        }
        if let Some(source) = self.source_guard().await? {
            if self
                .source_scope
                .as_ref()
                .is_some_and(|expected| expected != &source.scope)
            {
                return Err(error(
                    ErrorCode::Conflict,
                    "source collection identity differs",
                ));
            }
            batch.push_str(&format!(
                "delete table bridge {}\n",
                self.allocation.source_table()
            ));
        }
        if !batch.is_empty() {
            self.uncertain = true;
            self.can_renew = false;
            self.lease_until = None;
            nft(&["--file", "-"], Some(batch.as_bytes())).await?;
        }
        // Absence is expected only after the actual collection transaction.
        self.ethernet_required = false;
        self.source_scope = None;
        let observed = self.inspect().await?;
        if observed.installed
            || observed.ethernet_guarded
            || observed.source_guarded
            || observed.source_binding_sha256.is_some()
        {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "egress collection is unconfirmed",
            ));
        }
        self.revision = None;
        self.uncertain = false;
        self.can_renew = false;
        self.lease_until = None;
        self.dns = None;
        Ok(Observation {
            uncertain: false,
            ..observed
        })
    }
}

pub(crate) async fn nft(args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, ApiError> {
    let mut command = Command::new(NFT);
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_| error(ErrorCode::BackendUnavailable, "cannot launch trusted nft"))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = child
        .stdout
        .take()
        .expect("piped stdout")
        .take(MAX_OUTPUT + 1);
    let mut stderr = child
        .stderr
        .take()
        .expect("piped stderr")
        .take(MAX_OUTPUT + 1);
    let operation = async {
        let write = async {
            if let Some(bytes) = input {
                stdin.write_all(bytes).await?;
            }
            drop(stdin);
            Ok::<_, std::io::Error>(())
        };
        let out = async {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).await?;
            Ok::<_, std::io::Error>(bytes)
        };
        let err = async {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).await?;
            Ok::<_, std::io::Error>(bytes)
        };
        let (written, output, errors, status) = tokio::join!(write, out, err, child.wait());
        let output = output?;
        let errors = errors?;
        written?;
        Ok::<_, std::io::Error>((status?, output, errors))
    };
    let result = tokio::time::timeout(Duration::from_secs(8), operation).await;
    let (status, output, errors) = result
        .map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "nft observation or mutation timed out",
            )
        })?
        .map_err(|_| error(ErrorCode::BackendUnavailable, "nft transport failed"))?;
    if !status.success() || output.len() as u64 > MAX_OUTPUT || errors.len() as u64 > MAX_OUTPUT {
        return Err(error(
            ErrorCode::BackendUnavailable,
            "nft rejected the operation or exceeded output limits",
        ));
    }
    Ok(output)
}
