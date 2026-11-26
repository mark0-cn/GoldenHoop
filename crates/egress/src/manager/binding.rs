use super::*;

impl Manager {
    /// Reobserve all immutable floors and the complete deny table. In-memory
    /// descriptors alone cannot attest a protected native binding.
    pub async fn inspect_binding(
        &self,
        expected: u64,
    ) -> Result<crate::ProtectedBindingReceipt, ApiError> {
        self.check_lifetime()?;
        if self.uncertain
            || self.can_renew
            || self.lease_until.is_some()
            || self.revision != Some(expected)
            || !self.ethernet_required
        {
            return Err(error(
                ErrorCode::InvalidState,
                "binding inspection requires known quarantine",
            ));
        }
        let dns = self
            .dns
            .as_ref()
            .ok_or_else(|| error(ErrorCode::InvalidState, "DNS is not configured"))?;
        let expires_at = dns
            .expires_at
            .ok_or_else(|| error(ErrorCode::InvalidState, "DNS lacks original native expiry"))?;
        let bindings = dns
            .binding
            .as_ref()
            .ok_or_else(|| error(ErrorCode::InvalidState, "DNS listeners are not bound"))?;
        self.check_bridge()?;
        // Verify both complete native samples with the original pure deny and
        // floor predicates. Repeated per-table processes add no new authority.
        let mut confirmed = None;
        for _ in 0..2 {
            let observed = self.observed_tables().await?;
            self.expected_observation(expected, &observed)?;
            let table = observed
                .main_native
                .as_ref()
                .ok_or_else(|| error(ErrorCode::Conflict, "quarantine table is absent"))?;
            crate::quarantine::verify(&self.allocation, expected, bindings, table)?;
            confirmed = Some(observed);
        }
        let observed = confirmed
            .ok_or_else(|| error(ErrorCode::Conflict, "quarantine observation is absent"))?;
        let source = observed
            .source
            .ok_or_else(|| error(ErrorCode::Conflict, "source guard is absent"))?;
        let destinations = observed
            .destinations
            .ok_or_else(|| error(ErrorCode::Conflict, "destination guard is absent"))?;
        self.check_bridge()?;
        self.check_lifetime()?;
        let receipt = crate::ProtectedBindingReceipt {
            allocation: self.allocation.clone(),
            source: source.scope,
            destinations: destinations.definition,
            revision: expected,
            expires_at,
            observed_at: chrono::Utc::now(),
        };
        receipt.validate()?;
        Ok(receipt)
    }
}
