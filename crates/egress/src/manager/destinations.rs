use super::*;
use crate::{DestinationDefinition, DestinationListener, DestinationPlan, DestinationScope};
use std::net::IpAddr;

pub(super) struct DestinationObservation {
    pub definition: DestinationDefinition,
    pub healthy: bool,
}
impl Manager {
    pub(super) async fn destination_guard(
        &self,
    ) -> Result<Option<DestinationObservation>, ApiError> {
        let table = self.allocation.destination_table();
        let inventory: Value = serde_json::from_slice(
            &nft(&["--json", "list", "tables"], None).await?,
        )
        .map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "invalid destination inventory",
            )
        })?;
        let entries = inventory["nftables"].as_array().ok_or_else(|| {
            error(
                ErrorCode::BackendUnavailable,
                "missing destination inventory",
            )
        })?;
        if !entries
            .iter()
            .any(|e| e["table"]["family"] == "inet" && e["table"]["name"] == table)
        {
            return Ok(None);
        }
        let value: Value =
            serde_json::from_slice(&nft(&["--json", "list", "table", "inet", &table], None).await?)
                .map_err(|_| {
                    error(
                        ErrorCode::BackendUnavailable,
                        "invalid destination guard observation",
                    )
                })?;
        let definition = DestinationPlan::descriptor(&self.allocation, &value)?;
        let healthy = DestinationPlan::new(&self.allocation, &definition)?
            .verify(&self.allocation, &value)
            .is_ok();
        Ok(Some(DestinationObservation {
            definition,
            healthy,
        }))
    }
    pub(super) fn destinations_match(&self, observed: Option<&DestinationObservation>) -> bool {
        match (&self.destinations, observed) {
            (None, None) => true,
            (Some(expected), Some(actual)) => actual.healthy && *expected == actual.definition,
            _ => false,
        }
    }
    pub(super) fn check_destination_scope(
        &self,
        definition: &DestinationDefinition,
    ) -> Result<(), ApiError> {
        if crate::frontend::host_addresses()? != definition.scope.host_addresses {
            return Err(error(
                ErrorCode::Conflict,
                "protected host address inventory changed",
            ));
        }
        if let Some(bindings) = self.dns.as_ref().and_then(|d| d.binding.as_ref()) {
            let actual = bindings
                .iter()
                .map(|b| DestinationListener {
                    address: b.address(),
                    port: b.port(),
                })
                .collect::<Vec<_>>();
            if actual != definition.dns {
                return Err(error(
                    ErrorCode::Conflict,
                    "protected DNS infrastructure changed",
                ));
            }
        }
        Ok(())
    }
    /// Private trusted provisioning only. Host and listener observations come
    /// from this manager; the caller supplies only administrator-owned intent.
    pub async fn protect_destinations(
        &mut self,
        expected: u64,
        private_exceptions: Vec<String>,
        control_addresses: Vec<IpAddr>,
    ) -> Result<Observation, ApiError> {
        if self.uncertain
            || self.can_renew
            || self.revision != Some(expected)
            || self.destinations.is_some()
        {
            return Err(error(
                ErrorCode::InvalidState,
                "configure destinations once after known quarantine",
            ));
        }
        self.expected(expected).await?;
        if self.destination_guard().await?.is_some() {
            return Err(error(
                ErrorCode::Conflict,
                "destination guard already exists",
            ));
        }
        let definition = DestinationDefinition {
            scope: DestinationScope {
                host_addresses: crate::frontend::host_addresses()?,
                control_addresses,
                private_exceptions,
            },
            dns: self
                .dns
                .as_ref()
                .and_then(|d| d.binding.as_ref())
                .into_iter()
                .flat_map(|b| b.iter())
                .map(|b| DestinationListener {
                    address: b.address(),
                    port: b.port(),
                })
                .collect(),
        }
        .canonical()?;
        self.check_destination_scope(&definition)?;
        let plan = DestinationPlan::new(&self.allocation, &definition)?;
        self.destinations = Some(definition);
        self.uncertain = true;
        self.can_renew = false;
        self.lease_until = None;
        nft(&["--file", "-"], Some(plan.script().as_bytes())).await?;
        let observed = self.inspect().await?;
        self.check_bridge()?;
        if !observed.destinations_guarded || observed.revision != Some(expected) {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "destination installation is unconfirmed",
            ));
        }
        self.uncertain = false;
        Ok(Observation {
            uncertain: false,
            ..observed
        })
    }
}
