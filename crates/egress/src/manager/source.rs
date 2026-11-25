use super::*;
use crate::{Endpoint, SourcePlan, SourceScope};
mod port;

pub(super) struct SourceObservation {
    pub scope: SourceScope,
    pub healthy: bool,
}
impl Manager {
    /// Bind provider addresses to the sole actual host bridge port under deny.
    /// No workload-selected port or index is accepted by this entry point.
    pub async fn bind_runtime_source(
        &mut self,
        expected: u64,
        addresses: crate::EndpointAddresses,
    ) -> Result<crate::SourceBindingReceipt, ApiError> {
        self.check_bridge()?;
        let endpoint = port::observe(Path::new("/sys/class/net"), &self.allocation, &addresses)?;
        let observed = self.bind_source(expected, endpoint.clone()).await?;
        let receipt = async {
            self.check_bridge()?;
            if port::observe(Path::new("/sys/class/net"), &self.allocation, &addresses)? != endpoint
            {
                return Err(error(
                    ErrorCode::Conflict,
                    "native source port changed during binding",
                ));
            }
            let guard = self.source_guard().await?.ok_or_else(|| {
                error(
                    ErrorCode::BackendUnavailable,
                    "source guard readback is missing",
                )
            })?;
            self.check_source_scope(&guard.scope)?;
            if !guard.healthy
                || !self.source_matches(Some(&guard))
                || !observed.source_guarded
                || observed.uncertain
                || observed.revision != Some(expected)
                || observed.source_binding_sha256.as_deref() != Some(guard.scope.digest().as_str())
            {
                return Err(error(
                    ErrorCode::BackendUnavailable,
                    "native source binding is unconfirmed",
                ));
            }
            let receipt = crate::SourceBindingReceipt {
                allocation: self.allocation.clone(),
                source: guard.scope,
                revision: expected,
                observed_at: chrono::Utc::now(),
            };
            receipt.validate()?;
            Ok(receipt)
        }
        .await;
        if receipt.is_err() {
            self.uncertain = true;
            self.can_renew = false;
            self.lease_until = None;
        }
        receipt
    }
    pub(super) async fn source_guard(&self) -> Result<Option<SourceObservation>, ApiError> {
        let table = self.allocation.source_table();
        let inventory: Value = serde_json::from_slice(
            &nft(&["--json", "list", "tables"], None).await?,
        )
        .map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "invalid source table inventory",
            )
        })?;
        let entries = inventory["nftables"].as_array().ok_or_else(|| {
            error(
                ErrorCode::BackendUnavailable,
                "missing source table inventory",
            )
        })?;
        if !entries
            .iter()
            .any(|e| e["table"]["family"] == "bridge" && e["table"]["name"] == table)
        {
            return Ok(None);
        }
        let value: Value = serde_json::from_slice(
            &nft(&["--json", "list", "table", "bridge", &table], None).await?,
        )
        .map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "invalid source guard observation",
            )
        })?;
        let scope = SourcePlan::descriptor(&self.allocation, &value)?;
        let healthy = SourcePlan::new(&self.allocation, &scope)?
            .verify(&self.allocation, &value)
            .is_ok();
        Ok(Some(SourceObservation { scope, healthy }))
    }
    pub(super) fn source_matches(&self, observation: Option<&SourceObservation>) -> bool {
        match (&self.source_scope, observation) {
            (None, None) => true,
            (Some(expected), Some(actual)) => actual.healthy && expected == &actual.scope,
            _ => false,
        }
    }
    pub(super) fn check_source_scope(&self, scope: &SourceScope) -> Result<(), ApiError> {
        scope.validate(&self.allocation)?;
        let path = Path::new("/sys/class/net").join(&scope.endpoint.port);
        let read_index = |path: &Path| {
            std::fs::read_to_string(path)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
        };
        if read_index(&path.join("ifindex")) != Some(scope.endpoint.ifindex)
            || read_index(&path.join("master/ifindex")) != Some(self.allocation.ifindex)
            || !path.join("brport").is_dir()
        {
            return Err(error(
                ErrorCode::Conflict,
                "allocated source port identity changed",
            ));
        }
        let bridge = Path::new("/sys/class/net").join(&self.allocation.bridge);
        let mac = std::fs::read_to_string(bridge.join("address"))
            .ok()
            .and_then(|s| s.trim().parse::<crate::Mac>().ok());
        let addresses = crate::frontend::bridge_addresses(&self.allocation.bridge)?;
        if mac != Some(scope.gateway_mac)
            || addresses.v4 != scope.gateway4
            || addresses.v6 != scope.gateway6
        {
            return Err(error(
                ErrorCode::Conflict,
                "allocated source gateway identity changed",
            ));
        }
        Ok(())
    }
    /// Trusted provider metadata only, while quarantine is confirmed. No guest
    /// packet, DNS field or in-sandbox claim can choose its source descriptor.
    pub async fn bind_source(
        &mut self,
        expected: u64,
        endpoint: Endpoint,
    ) -> Result<Observation, ApiError> {
        if self.uncertain
            || self.can_renew
            || self.revision != Some(expected)
            || self.source_scope.is_some()
        {
            return Err(error(
                ErrorCode::InvalidState,
                "bind source once after known quarantine",
            ));
        }
        self.expected(expected).await?;
        if self.ethernet().await?.is_none() {
            return Err(error(
                ErrorCode::InvalidState,
                "source binding requires the immutable Ethernet floor",
            ));
        }
        if self.source_guard().await?.is_some() {
            return Err(error(ErrorCode::Conflict, "source guard already exists"));
        }
        let bridge = Path::new("/sys/class/net").join(&self.allocation.bridge);
        let gateway_mac = std::fs::read_to_string(bridge.join("address"))
            .map_err(|_| {
                error(
                    ErrorCode::BackendUnavailable,
                    "cannot inspect allocated bridge MAC",
                )
            })?
            .trim()
            .parse::<crate::Mac>()?;
        let addresses = crate::frontend::bridge_addresses(&self.allocation.bridge)?;
        let scope = SourceScope {
            endpoint,
            gateway_mac,
            gateway4: addresses.v4,
            gateway6: addresses.v6,
        };
        self.check_source_scope(&scope)?;
        let plan = SourcePlan::new(&self.allocation, &scope)?;
        self.source_scope = Some(scope);
        self.uncertain = true;
        self.can_renew = false;
        self.lease_until = None;
        nft(&["--file", "-"], Some(plan.script().as_bytes())).await?;
        let observed = self.inspect().await?;
        self.check_bridge()?;
        if !observed.source_guarded
            || observed.source_binding_sha256.as_deref()
                != self
                    .source_scope
                    .as_ref()
                    .map(SourceScope::digest)
                    .as_deref()
            || observed.revision != Some(expected)
        {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "source guard installation is unconfirmed",
            ));
        }
        self.uncertain = false;
        Ok(Observation {
            uncertain: false,
            ..observed
        })
    }
}
