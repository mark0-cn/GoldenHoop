use crate::{Allocation, Config, EthernetPlan, LEASE_SECONDS, Plan, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    os::unix::{fs::MetadataExt, net::UnixDatagram},
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
mod binding;
mod credentials;
mod destinations;
mod effective;
mod observation;
mod resolver;
mod snapshot;
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
    pub destinations_guarded: bool,
    pub destination_binding_sha256: Option<String>,
}

pub struct Manager {
    allocation: Allocation,
    revision: Option<u64>,
    uncertain: bool,
    can_renew: bool,
    lease_until: Option<Instant>,
    effective_policy: Option<Config>,
    dns: Option<resolver::DnsState>,
    ethernet_required: bool,
    source_scope: Option<crate::SourceScope>,
    destinations: Option<crate::DestinationDefinition>,
    credential_redirect: Option<crate::CredentialRedirect>,
    packet_epoch: uuid::Uuid,
    // Abstract Unix names share the host network namespace, including across
    // containers with distinct /run mounts. Dropping the process releases it.
    _lock: UnixDatagram,
}

pub(super) fn table_revision(allocation: &Allocation, value: &Value) -> Result<u64, ApiError> {
    let table = allocation.table();
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
    if owners != [allocation.owner_chain()]
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
    Ok(revision)
}

impl Manager {
    pub fn allocation(&self) -> &Allocation {
        &self.allocation
    }
    pub async fn new(allocation: Allocation) -> Result<Self, ApiError> {
        allocation.validate()?;
        crate::host::authority()?;
        let meta = std::fs::symlink_metadata(NFT).map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "trusted nft executable is unavailable",
            )
        })?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(error(ErrorCode::Forbidden, "untrusted nft executable"));
        }
        let lock = crate::host::allocation_lock(&allocation)?;
        let mut manager = Self {
            allocation,
            revision: None,
            uncertain: false,
            can_renew: false,
            lease_until: None,
            effective_policy: None,
            dns: None,
            ethernet_required: false,
            source_scope: None,
            destinations: None,
            credential_redirect: None,
            packet_epoch: uuid::Uuid::new_v4(),
            _lock: lock,
        };
        // Reconcile the immutable floor on attachment. A restart cannot forget
        // an existing owned guard and silently continue without it later.
        let observed = manager.observed_tables().await?;
        manager.ethernet_required = observed.ethernet_sha256.is_some();
        if let Some(observed) = observed.source {
            manager.uncertain = !observed.healthy || !manager.ethernet_required;
            manager.ethernet_required = true;
            manager.source_scope = Some(observed.scope);
        }
        if let Some(observed) = observed.destinations {
            manager.uncertain |= !observed.healthy;
            manager.destinations = Some(observed.definition);
        }
        if let Some(observed) = observed.credential {
            manager.credential_redirect = Some(observed);
            // A restarted process has no provider material or live packets.
            // Recovery must install a fresh broker snapshot under quarantine.
            manager.can_renew = false;
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
        if let Some(definition) = &self.destinations {
            self.check_destination_scope(definition)?;
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
        let value: Value = serde_json::from_slice(
            &nft(
                &["--json", "--numeric", "list", "table", "inet", &table],
                None,
            )
            .await?,
        )
        .map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "invalid nft table observation",
            )
        })?;
        let revision = table_revision(&self.allocation, &value)?;
        Ok(Some((revision, value)))
    }

    pub async fn inspect(&self) -> Result<Observation, ApiError> {
        let observed = self.observed_tables().await?;
        let table = observed.table;
        let ethernet = observed.ethernet_sha256;
        let source = observed.source;
        let destinations = observed.destinations;
        Ok(Observation {
            installed: table.is_some(),
            revision: table.as_ref().map(|(r, _)| *r),
            uncertain: self.uncertain
                || (self.ethernet_required && ethernet.is_none())
                || !self.source_matches(source.as_ref())
                || !self.destinations_match(destinations.as_ref()),
            table_sha256: table.map(|(_, digest)| digest),
            maximum_lease_seconds: LEASE_SECONDS,
            ethernet_guarded: ethernet.is_some(),
            ethernet_sha256: ethernet,
            source_guarded: source.as_ref().is_some_and(|s| s.healthy)
                && self.source_matches(source.as_ref()),
            source_binding_sha256: source.map(|s| s.scope.digest()),
            destinations_guarded: destinations.as_ref().is_some_and(|d| d.healthy)
                && self.destinations_match(destinations.as_ref()),
            destination_binding_sha256: destinations.map(|d| d.definition.digest()),
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
        self.commit(Plan::quarantine(self.allocation.clone(), 0)?, false, None)
            .await
    }

    async fn expected(&self, expected: u64) -> Result<(), ApiError> {
        self.check_bridge()?;
        let observed = self.observed_tables().await?;
        self.expected_observation(expected, &observed)?;
        self.check_bridge()?;
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
        let plan = Plan::compile_with_lease(
            self.allocation.clone(),
            next,
            config,
            self.dns.is_some(),
            self.dns.as_ref().and_then(|s| s.binding.as_ref()),
            self.live_milliseconds()?,
        )?;
        self.expected(expected).await?;
        let observed = self.commit(plan, true, Some(config)).await?;
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
                None,
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
        policy: Option<&Config>,
    ) -> Result<Observation, ApiError> {
        self.verify_credential_guard().await?;
        let mut batch = String::new();
        if replace {
            batch.push_str(&format!("delete table inet {}\n", self.allocation.table()));
        }
        batch.push_str(&plan.batch);
        self.uncertain = true;
        self.can_renew = false;
        self.lease_until = None;
        self.effective_policy = None;
        let started = Instant::now();
        nft(&["--file", "-"], Some(batch.as_bytes())).await?;
        let observed = self.inspect().await?;
        if observed.revision != Some(plan.revision)
            || (self.ethernet_required && !observed.ethernet_guarded)
            || (self.source_scope.is_some() && !observed.source_guarded)
            || (self.destinations.is_some() && !observed.destinations_guarded)
        {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "kernel did not confirm policy revision",
            ));
        }
        let confirmed = if let Some(config) = policy {
            Some(
                self.verify_kernel_policy(
                    plan.revision,
                    config,
                    self.dns
                        .as_ref()
                        .map(|_| crate::dns::SetNames::bootstrap())
                        .as_ref(),
                )
                .await?
                .until,
            )
        } else {
            None
        };
        self.revision = Some(plan.revision);
        self.uncertain = false;
        self.can_renew = policy.is_some();
        self.effective_policy = policy.cloned();
        self.lease_until = confirmed.map(|end| {
            end.min(started + Duration::from_millis(u64::from(LEASE_SECONDS) * 1000 - 11))
        });
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
        let config = self
            .effective_policy
            .clone()
            .ok_or_else(|| error(ErrorCode::InvalidState, "effective policy is unavailable"))?;
        let names = self.dns.as_ref().map(|s| s.active.clone());
        self.uncertain = true;
        self.can_renew = false;
        self.lease_until = None;
        if self.ethernet_required
            && self.source_scope.is_some()
            && self.destinations.is_some()
            && let Some(names) = names.as_ref()
        {
            return self
                .renew_protected(expected, &config, names)
                .await
                .map(|(observation, _)| observation);
        }
        self.expected(expected).await?;
        self.verify_kernel_policy(expected, &config, names.as_ref())
            .await?;
        let milliseconds = self.live_milliseconds()?;
        let batch = format!(
            "flush set inet {} live\nadd element inet {} live {{ \"{}\" timeout {milliseconds}ms }}\n",
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
            || (self.destinations.is_some() && !observed.destinations_guarded)
        {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "kernel did not confirm lease revision",
            ));
        }
        let confirmed = self
            .verify_kernel_policy(expected, &config, names.as_ref())
            .await?
            .until;
        self.uncertain = false;
        self.can_renew = true;
        self.lease_until =
            Some(confirmed.min(started + Duration::from_millis(milliseconds.saturating_sub(11))));
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
        if let Some(observed) = self.credential_guard().await? {
            if self
                .credential_redirect
                .as_ref()
                .is_some_and(|expected| expected.digest() != observed.digest())
            {
                return Err(error(
                    ErrorCode::Conflict,
                    "credential collection identity differs",
                ));
            }
            batch.push_str(&format!(
                "delete table inet {}\n",
                self.allocation.credential_table()
            ));
        }
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
        if let Some(destination) = self.destination_guard().await? {
            if self
                .destinations
                .as_ref()
                .is_some_and(|expected| *expected != destination.definition)
            {
                return Err(error(
                    ErrorCode::Conflict,
                    "destination collection identity differs",
                ));
            }
            batch.push_str(&format!(
                "delete table inet {}\n",
                self.allocation.destination_table()
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
        self.destinations = None;
        self.credential_redirect = None;
        let observed = self.inspect().await?;
        if observed.installed
            || observed.ethernet_guarded
            || observed.source_guarded
            || observed.source_binding_sha256.is_some()
            || observed.destinations_guarded
            || observed.destination_binding_sha256.is_some()
        {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "egress collection is unconfirmed",
            ));
        }
        if self.credential_guard().await?.is_some() {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "credential redirect collection is unconfirmed",
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
    nft_bounded(args, input, MAX_OUTPUT).await
}

pub(crate) async fn nft_bounded(
    args: &[&str],
    input: Option<&[u8]>,
    output_limit: u64,
) -> Result<Vec<u8>, ApiError> {
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
        .take(output_limit + 1);
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
    if !status.success() || output.len() as u64 > output_limit || errors.len() as u64 > MAX_OUTPUT {
        return Err(error(
            ErrorCode::BackendUnavailable,
            "nft rejected the operation or exceeded output limits",
        ));
    }
    Ok(output)
}
