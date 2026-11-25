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
        self.expected(expected).await?;
        let (revision, table) = self
            .table()
            .await?
            .ok_or_else(|| error(ErrorCode::Conflict, "quarantine table is absent"))?;
        if revision != expected {
            return Err(error(ErrorCode::Conflict, "quarantine revision changed"));
        }
        crate::quarantine::verify(&self.allocation, expected, bindings, &table)?;
        let source = self
            .source_guard()
            .await?
            .ok_or_else(|| error(ErrorCode::Conflict, "source guard is absent"))?;
        let destinations = self
            .destination_guard()
            .await?
            .ok_or_else(|| error(ErrorCode::Conflict, "destination guard is absent"))?;
        if !self.source_matches(Some(&source)) || !self.destinations_match(Some(&destinations)) {
            return Err(error(ErrorCode::Conflict, "immutable guard changed"));
        }
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
