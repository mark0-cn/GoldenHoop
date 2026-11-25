//! Fresh protected quarantine observation. This is neither a lease nor Ready.
use crate::{Allocation, DestinationDefinition, SourceScope, error};
use chrono::{DateTime, Utc};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedBindingReceipt {
    pub allocation: Allocation,
    pub source: SourceScope,
    pub destinations: DestinationDefinition,
    pub revision: u64,
    pub expires_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
}
impl ProtectedBindingReceipt {
    pub fn validate(&self) -> Result<(), ApiError> {
        self.source.validate(&self.allocation)?;
        let canonical = self.destinations.canonical()?;
        let gateways = std::iter::once(self.source.gateway4.into())
            .chain(self.source.gateway6.map(std::net::IpAddr::V6))
            .collect::<Vec<_>>();
        if canonical != self.destinations
            || canonical.dns.iter().map(|d| d.address).collect::<Vec<_>>() != gateways
            || self.observed_at >= self.expires_at
        {
            return Err(error(ErrorCode::Conflict, "protected binding differs"));
        }
        Ok(())
    }
}

/// Freeze the monotonic deadline before any asynchronous native observation.
/// The upper bound preserves the public maximum TTL without accepting an
/// arbitrary longer expiry on this private path.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn remaining_lifetime(
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<std::time::Duration, ApiError> {
    let remaining = expires_at.signed_duration_since(now);
    if remaining <= chrono::Duration::zero() {
        return Err(error(
            ErrorCode::DeadlineExceeded,
            "sandbox lifetime elapsed",
        ));
    }
    if remaining > chrono::Duration::seconds(86400) {
        return Err(error(
            ErrorCode::InvalidRequest,
            "sandbox lifetime exceeds maximum",
        ));
    }
    remaining
        .to_std()
        .map_err(|_| error(ErrorCode::InvalidRequest, "invalid sandbox lifetime"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_expiry_supports_full_ttl_without_rounding_or_extension() {
        let now = Utc::now();
        for seconds in [1, 1801, 65536, 86400] {
            assert_eq!(
                remaining_lifetime(now + chrono::Duration::seconds(seconds), now).unwrap(),
                std::time::Duration::from_secs(seconds as u64)
            );
        }
        assert_eq!(
            remaining_lifetime(now + chrono::Duration::milliseconds(1), now).unwrap(),
            std::time::Duration::from_millis(1)
        );
        assert!(remaining_lifetime(now, now).is_err());
        assert!(remaining_lifetime(now - chrono::Duration::seconds(1), now).is_err());
        assert!(remaining_lifetime(now + chrono::Duration::seconds(86401), now).is_err());
    }
}
