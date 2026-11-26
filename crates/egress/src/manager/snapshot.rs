use super::effective::KernelPolicy;
use super::*;
use crate::{
    DestinationDefinition, DestinationPlan, MAX_SNAPSHOT_BYTES, ScopedKernelSnapshot, SourcePlan,
    SourceScope,
    dns::{SetNames, StagedSets},
};

struct Floors {
    source: SourceScope,
    destinations: DestinationDefinition,
    sha256: String,
    ethernet_sha256: String,
}

impl Manager {
    async fn kernel_snapshot(&self) -> Result<ScopedKernelSnapshot, ApiError> {
        let bytes = nft_bounded(
            // Preserve the immutable floors' native symbolic representation.
            // The policy verifier canonicalizes only verified equivalents.
            &["--json", "list", "ruleset"],
            None,
            MAX_SNAPSHOT_BYTES as u64,
        )
        .await?;
        ScopedKernelSnapshot::parse(&self.allocation, &bytes)
    }

    fn verify_snapshot(
        &self,
        snapshot: &ScopedKernelSnapshot,
        expected: u64,
        config: &Config,
        names: &SetNames,
    ) -> Result<Floors, ApiError> {
        self.check_bridge()?;
        let main = snapshot.table(&self.allocation.table())?;
        if table_revision(&self.allocation, main)? != expected {
            return Err(error(ErrorCode::Conflict, "egress policy revision differs"));
        }
        let ethernet = snapshot.table(&self.allocation.ethernet_table())?;
        EthernetPlan::verify(&self.allocation, ethernet)?;
        let table = snapshot.table(&self.allocation.source_table())?;
        let source = SourcePlan::descriptor(&self.allocation, table)?;
        SourcePlan::new(&self.allocation, &source)?.verify(&self.allocation, table)?;
        let source_observation = super::source::SourceObservation {
            scope: source.clone(),
            healthy: true,
        };
        if !self.source_matches(Some(&source_observation)) {
            return Err(error(
                ErrorCode::Conflict,
                "required source guard is unavailable or changed",
            ));
        }
        let table = snapshot.table(&self.allocation.destination_table())?;
        let destinations = DestinationPlan::descriptor(&self.allocation, table)?;
        DestinationPlan::new(&self.allocation, &destinations)?.verify(&self.allocation, table)?;
        let destination_observation = super::destinations::DestinationObservation {
            definition: destinations.clone(),
            healthy: true,
        };
        if !self.destinations_match(Some(&destination_observation)) {
            return Err(error(
                ErrorCode::Conflict,
                "required destination guard is unavailable or changed",
            ));
        }
        match (
            &self.credential_redirect,
            snapshot.table(&self.allocation.credential_table()),
        ) {
            (Some(definition), Ok(table)) => {
                crate::CredentialRedirectPlan::new(&self.allocation, definition.clone())?
                    .verify(&self.allocation, table)?;
            }
            (Some(_), Err(error)) => return Err(error),
            (None, Ok(_)) => {
                return Err(error(
                    ErrorCode::Conflict,
                    "unexpected credential ingress in protected snapshot",
                ));
            }
            (None, Err(_)) => {}
        }
        crate::policy_readback::verify_structure(
            &self.allocation,
            expected,
            config,
            self.dns.as_ref().and_then(|s| s.binding.as_ref()),
            Some(names),
            main,
        )?;
        Ok(Floors {
            source,
            destinations,
            sha256: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(main).expect("native JSON"))
            ),
            ethernet_sha256: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(ethernet).expect("native JSON"))
            ),
        })
    }

    /// Observe every required floor before and after the native textual lease
    /// sample. Existing pure verifiers and the original timing deduction remain
    /// unchanged; repeated per-table CLI processes are replaced by two dumps.
    pub(super) async fn protected_kernel(
        &self,
        expected: u64,
        config: &Config,
        names: &SetNames,
    ) -> Result<(KernelPolicy, SourceScope, DestinationDefinition), ApiError> {
        let before = self.kernel_snapshot().await?;
        self.verify_snapshot(&before, expected, config, names)?;
        let started = Instant::now();
        let bytes = nft(&["list", "table", "inet", &self.allocation.table()], None).await?;
        let finished = Instant::now();
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "invalid native policy observation",
            )
        })?;
        let until = crate::policy_readback::verify_native_lease(
            &self.allocation,
            text,
            started,
            finished,
            self.dns.as_ref().map(|s| s.deadline),
        )?;
        let memberships = if let Some(book) = self.dns.as_ref().and_then(|s| s.book.as_ref()) {
            book.memberships(started)?
        } else if names.token().is_none() {
            Vec::new()
        } else {
            return Err(error(
                ErrorCode::InvalidState,
                "active DNS authority is absent",
            ));
        };
        StagedSets::observation(&self.allocation, names.clone(), &memberships)?
            .confirm_current_native(text, started, finished)?;
        let after = self.kernel_snapshot().await?;
        let floors = self.verify_snapshot(&after, expected, config, names)?;
        if until <= Instant::now() {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "kernel live lease elapsed during readback",
            ));
        }
        Ok((
            KernelPolicy {
                until,
                sha256: floors.sha256,
                ethernet_sha256: Some(floors.ethernet_sha256),
            },
            floors.source,
            floors.destinations,
        ))
    }

    /// Every former expected()/inspect() predicate is verified in each
    /// protected sample. Keep the fresh observations instead of rereading
    /// the same tables through another sequence of CLI processes.
    pub(super) async fn renew_protected(
        &mut self,
        expected: u64,
        config: &Config,
        names: &SetNames,
    ) -> Result<Observation, ApiError> {
        self.protected_kernel(expected, config, names).await?;
        let milliseconds = self.live_milliseconds()?;
        let batch = format!(
            "flush set inet {} live\nadd element inet {} live {{ \"{}\" timeout {milliseconds}ms }}\n",
            self.allocation.table(),
            self.allocation.table(),
            self.allocation.bridge
        );
        let started = Instant::now();
        nft(&["--file", "-"], Some(batch.as_bytes())).await?;
        let (kernel, source, destinations) = self.protected_kernel(expected, config, names).await?;
        self.check_bridge()?;
        self.check_lifetime()?;
        let ethernet_sha256 = kernel.ethernet_sha256.ok_or_else(|| {
            error(
                ErrorCode::Conflict,
                "protected Ethernet observation is absent",
            )
        })?;
        let observation = Observation {
            installed: true,
            revision: Some(expected),
            uncertain: false,
            table_sha256: Some(kernel.sha256),
            maximum_lease_seconds: LEASE_SECONDS,
            ethernet_guarded: true,
            ethernet_sha256: Some(ethernet_sha256),
            source_guarded: true,
            source_binding_sha256: Some(source.digest()),
            destinations_guarded: true,
            destination_binding_sha256: Some(destinations.digest()),
        };
        self.lease_until = Some(
            kernel
                .until
                .min(started + Duration::from_millis(milliseconds.saturating_sub(11))),
        );
        self.uncertain = false;
        self.can_renew = true;
        Ok(observation)
    }
}
