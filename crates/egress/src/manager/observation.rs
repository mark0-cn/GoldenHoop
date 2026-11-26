use super::*;
use crate::{CredentialRedirect, CredentialRedirectPlan, DestinationPlan, SourcePlan};

pub(super) struct ObservedTables {
    pub table: Option<(u64, String)>,
    pub main_native: Option<Value>,
    pub ethernet_sha256: Option<String>,
    pub source: Option<source::SourceObservation>,
    pub destinations: Option<destinations::DestinationObservation>,
    pub credential: Option<CredentialRedirect>,
    pub credential_native: Option<Value>,
}

fn digest(value: &Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("native JSON"))
    )
}

impl Manager {
    /// The same per-table ownership/shape verifiers, using one bounded actual
    /// dump instead of repeated list-inventory/list-table child processes.
    /// Absence stays distinct from a malformed or failed native observation.
    pub(super) async fn observed_tables(&self) -> Result<ObservedTables, ApiError> {
        let bytes = nft_bounded(
            &["--json", "list", "ruleset"],
            None,
            crate::MAX_SNAPSHOT_BYTES as u64,
        )
        .await?;
        let snapshot = crate::ScopedKernelSnapshot::inventory(&self.allocation, &bytes)?;
        let main_native = snapshot.observed_table(&self.allocation.table()).cloned();
        let table = main_native
            .as_ref()
            .map(|value| -> Result<_, ApiError> {
                Ok((table_revision(&self.allocation, value)?, digest(value)))
            })
            .transpose()?;
        let ethernet_sha256 = snapshot
            .observed_table(&self.allocation.ethernet_table())
            .map(|value| -> Result<_, ApiError> {
                EthernetPlan::verify(&self.allocation, value)?;
                Ok(digest(value))
            })
            .transpose()?;
        let source = snapshot
            .observed_table(&self.allocation.source_table())
            .map(|value| -> Result<_, ApiError> {
                let scope = SourcePlan::descriptor(&self.allocation, value)?;
                let healthy = SourcePlan::new(&self.allocation, &scope)?
                    .verify(&self.allocation, value)
                    .is_ok();
                Ok(source::SourceObservation { scope, healthy })
            })
            .transpose()?;
        let destinations = snapshot
            .observed_table(&self.allocation.destination_table())
            .map(|value| -> Result<_, ApiError> {
                let definition = DestinationPlan::descriptor(&self.allocation, value)?;
                let healthy = DestinationPlan::new(&self.allocation, &definition)?
                    .verify(&self.allocation, value)
                    .is_ok();
                Ok(destinations::DestinationObservation {
                    definition,
                    healthy,
                })
            })
            .transpose()?;
        let credential_native = snapshot
            .observed_table(&self.allocation.credential_table())
            .cloned();
        let credential = credential_native
            .as_ref()
            .map(|value| CredentialRedirectPlan::descriptor(&self.allocation, value))
            .transpose()?;
        Ok(ObservedTables {
            table,
            main_native,
            ethernet_sha256,
            source,
            destinations,
            credential,
            credential_native,
        })
    }

    pub(super) fn expected_observation(
        &self,
        expected: u64,
        observed: &ObservedTables,
    ) -> Result<(), ApiError> {
        if observed.table.as_ref().map(|(r, _)| *r) != Some(expected) {
            return Err(error(ErrorCode::Conflict, "egress policy revision differs"));
        }
        if self.ethernet_required && observed.ethernet_sha256.is_none() {
            return Err(error(
                ErrorCode::Conflict,
                "required Ethernet guard is unavailable",
            ));
        }
        if !self.source_matches(observed.source.as_ref()) {
            return Err(error(
                ErrorCode::Conflict,
                "required source guard is unavailable or changed",
            ));
        }
        if !self.destinations_match(observed.destinations.as_ref()) {
            return Err(error(
                ErrorCode::Conflict,
                "required destination guard is unavailable or changed",
            ));
        }
        match (
            &self.credential_redirect,
            &observed.credential,
            &observed.credential_native,
        ) {
            (Some(expected), Some(_), Some(native)) => {
                CredentialRedirectPlan::new(&self.allocation, expected.clone())?
                    .verify(&self.allocation, native)?;
            }
            (None, None, None) => {}
            _ => {
                return Err(error(
                    ErrorCode::Conflict,
                    "credential ingress observation differs",
                ));
            }
        }
        Ok(())
    }
}
