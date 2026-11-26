use super::*;
use crate::{
    EffectivePolicyReceipt, ProtectedBindingReceipt,
    dns::{SetNames, StagedSets},
};

pub(super) struct KernelPolicy {
    pub until: Instant,
    pub sha256: String,
    pub ethernet_sha256: Option<String>,
}
pub(super) struct PolicySample {
    pub observed_at: chrono::DateTime<chrono::Utc>,
    pub started: Instant,
    pub kernel: KernelPolicy,
    pub source: crate::SourceScope,
    pub destinations: crate::DestinationDefinition,
}
impl Manager {
    pub(super) fn live_milliseconds(&self) -> Result<u64, ApiError> {
        let maximum = u64::from(LEASE_SECONDS) * 1000;
        let remaining = self
            .dns
            .as_ref()
            .map(|dns| {
                dns.deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .saturating_sub(250)
                    .min(u128::from(maximum)) as u64
            })
            .unwrap_or(maximum);
        if remaining == 0 {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "original lifetime has no live lease window",
            ));
        }
        Ok(remaining)
    }

    pub(super) async fn verify_kernel_policy(
        &self,
        revision: u64,
        config: &Config,
        names: Option<&SetNames>,
    ) -> Result<KernelPolicy, ApiError> {
        if self.ethernet_required
            && self.source_scope.is_some()
            && self.destinations.is_some()
            && let Some(names) = names
        {
            self.check_lifetime()?;
            // The protected snapshot brackets the same native-duration sample
            // with exact main, Ethernet, source, destination and credential
            // readback. Reuse it for renewal instead of launching each table
            // reader separately before and after that sample.
            let (kernel, _, _) = self.protected_kernel(revision, config, names).await?;
            self.check_lifetime()?;
            return Ok(kernel);
        }
        self.expected(revision).await?;
        let (_, native) = self
            .table()
            .await?
            .ok_or_else(|| error(ErrorCode::Conflict, "effective policy is absent"))?;
        crate::policy_readback::verify_structure(
            &self.allocation,
            revision,
            config,
            self.dns.as_ref().and_then(|s| s.binding.as_ref()),
            names,
            &native,
        )?;
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
        if let Some(names) = names {
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
        }
        self.expected(revision).await?;
        let (_, after) = self
            .table()
            .await?
            .ok_or_else(|| error(ErrorCode::Conflict, "effective policy disappeared"))?;
        crate::policy_readback::verify_structure(
            &self.allocation,
            revision,
            config,
            self.dns.as_ref().and_then(|s| s.binding.as_ref()),
            names,
            &after,
        )?;
        if until <= Instant::now() {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "kernel live lease elapsed during readback",
            ));
        }
        Ok(KernelPolicy {
            until,
            sha256: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&after).expect("native JSON"))
            ),
            ethernet_sha256: None,
        })
    }

    pub async fn inspect_policy(
        &mut self,
        expected: u64,
    ) -> Result<EffectivePolicyReceipt, ApiError> {
        self.check_lifetime()?;
        if self.uncertain
            || !self.can_renew
            || self.revision != Some(expected)
            || self.lease_until.is_none_or(|end| end <= Instant::now())
            || !self.ethernet_required
            || self.source_scope.is_none()
            || self.destinations.is_none()
            || self.effective_policy.is_none()
        {
            return Err(error(
                ErrorCode::InvalidState,
                "effective policy inspection requires a known protected live lease",
            ));
        }
        let result = self.inspect_policy_inner(expected).await;
        if result.is_err() {
            self.uncertain = true;
            self.can_renew = false;
            self.lease_until = None;
        }
        result
    }
    async fn inspect_policy_inner(
        &self,
        expected: u64,
    ) -> Result<EffectivePolicyReceipt, ApiError> {
        // The wall timestamp and monotonic budget describe the same sampling
        // start. Capture wall time first so it cannot move the budget past the
        // original absolute lifetime merely through local capture order.
        let observed_at = chrono::Utc::now();
        let started = Instant::now();
        let config = self
            .effective_policy
            .as_ref()
            .ok_or_else(|| error(ErrorCode::InvalidState, "effective policy is absent"))?;
        let dns = self
            .dns
            .as_ref()
            .ok_or_else(|| error(ErrorCode::InvalidState, "trusted DNS is absent"))?;
        self.policy_context(config)?;
        let (kernel, source, destinations) =
            self.protected_kernel(expected, config, &dns.active).await?;
        self.policy_receipt(
            expected,
            config,
            PolicySample {
                observed_at,
                started,
                kernel,
                source,
                destinations,
            },
            self.lease_until
                .ok_or_else(|| error(ErrorCode::InvalidState, "local lease is absent"))?,
        )
    }

    pub(super) fn policy_context(
        &self,
        config: &Config,
    ) -> Result<chrono::DateTime<chrono::Utc>, ApiError> {
        let dns = self
            .dns
            .as_ref()
            .ok_or_else(|| error(ErrorCode::InvalidState, "trusted DNS is absent"))?;
        let expires_at = dns
            .expires_at
            .ok_or_else(|| error(ErrorCode::InvalidState, "original DNS lifetime is absent"))?;
        if dns.binding.is_none()
            || dns
                .config
                .as_ref()
                .map(Config::digest)
                .transpose()?
                .as_ref()
                != Some(&config.digest()?)
            || dns.book.as_ref().is_none_or(|book| book.is_unknown())
        {
            return Err(error(
                ErrorCode::InvalidState,
                "trusted DNS policy authority is absent",
            ));
        }
        Ok(expires_at)
    }

    pub(super) fn policy_receipt(
        &self,
        expected: u64,
        config: &Config,
        sample: PolicySample,
        local_until: Instant,
    ) -> Result<EffectivePolicyReceipt, ApiError> {
        let expires_at = self.policy_context(config)?;
        self.check_bridge()?;
        self.check_lifetime()?;
        let until = sample.kernel.until.min(local_until);
        let remaining =
            crate::policy_binding::sampled_lease_budget(sample.started, Instant::now(), until)?;
        let receipt = EffectivePolicyReceipt {
            binding: ProtectedBindingReceipt {
                allocation: self.allocation.clone(),
                source: sample.source,
                destinations: sample.destinations,
                revision: expected,
                expires_at,
                observed_at: sample.observed_at,
            },
            config_sha256: config.digest()?,
            native_sha256: sample.kernel.sha256,
            lease_remaining_milliseconds: remaining,
        };
        receipt.validate_config(config)?;
        Ok(receipt)
    }
}
