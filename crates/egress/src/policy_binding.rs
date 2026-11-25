//! Fresh effective-policy and bounded-lease observation, not sandbox Ready.
use crate::{Config, LEASE_SECONDS, ProtectedBindingReceipt, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectivePolicyReceipt {
    pub binding: ProtectedBindingReceipt,
    pub config_sha256: String,
    pub native_sha256: String,
    /// Verified budget at `binding.observed_at`, the start of sampling. A
    /// private reader anchors it at its own request start, never at receipt time.
    pub lease_remaining_milliseconds: u32,
}
impl EffectivePolicyReceipt {
    pub fn validate(&self) -> Result<(), ApiError> {
        self.binding.validate()?;
        let hash = |v: &str| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !hash(&self.config_sha256)
            || !hash(&self.native_sha256)
            || self.lease_remaining_milliseconds == 0
            || self.lease_remaining_milliseconds > LEASE_SECONDS * 1000
            || self
                .binding
                .observed_at
                .checked_add_signed(chrono::Duration::milliseconds(i64::from(
                    self.lease_remaining_milliseconds,
                )))
                .is_none_or(|end| end > self.binding.expires_at)
        {
            return Err(error(
                ErrorCode::Conflict,
                "effective policy receipt differs",
            ));
        }
        Ok(())
    }
    pub fn validate_config(&self, config: &Config) -> Result<(), ApiError> {
        self.validate()?;
        if self.config_sha256 != config.digest()? {
            return Err(error(
                ErrorCode::Conflict,
                "effective policy configuration differs",
            ));
        }
        Ok(())
    }
}

#[cfg(any(unix, test))]
pub(crate) fn sampled_lease_budget(
    started: std::time::Instant,
    finished: std::time::Instant,
    until: std::time::Instant,
) -> Result<u32, ApiError> {
    if finished < started || until <= finished {
        return Err(error(
            ErrorCode::DeadlineExceeded,
            "effective policy sampling has no live lease",
        ));
    }
    // Sampling must finish before the same already-issued native lease ends.
    // Keeping its start-relative budget lets a private reader account for
    // transport without deducting the verified server work a second time.
    let remaining = u32::try_from(until.duration_since(started).as_millis())
        .map_err(|_| error(ErrorCode::Conflict, "invalid live lease bound"))?;
    if remaining == 0 || remaining > LEASE_SECONDS * 1000 {
        return Err(error(ErrorCode::Conflict, "invalid live lease bound"));
    }
    Ok(remaining)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn sampling_budget_retains_server_work_without_extending_native_expiry() {
        let client_start = Instant::now();
        for lifetime_ms in [1_000, 5_000, 10_000] {
            let native_until = client_start + Duration::from_millis(lifetime_ms);
            for inbound_ms in [0, 5, 300] {
                let server_start = client_start + Duration::from_millis(inbound_ms);
                for work_ms in [0, 200, 4_000] {
                    let server_finish = server_start + Duration::from_millis(work_ms);
                    let budget = sampled_lease_budget(server_start, server_finish, native_until);
                    if server_finish >= native_until {
                        assert!(budget.is_err());
                        continue;
                    }
                    let budget = budget.unwrap();
                    assert_eq!(u64::from(budget), lifetime_ms - inbound_ms);
                    // The client uses its own request start. It never receives
                    // a server monotonic timestamp or assumes matching epochs.
                    let local_until = client_start + Duration::from_millis(u64::from(budget));
                    assert!(local_until <= native_until);
                    let receive = server_finish + Duration::from_millis(100);
                    if receive < local_until {
                        assert!(local_until.duration_since(receive) <= native_until - receive);
                    }
                    let late_receive = native_until + Duration::from_millis(1);
                    assert!(local_until <= late_receive);
                }
            }
        }
    }

    #[test]
    fn sampling_budget_refuses_expired_reversed_zero_and_over_maximum_windows() {
        let start = Instant::now();
        let maximum = Duration::from_secs(u64::from(LEASE_SECONDS));
        for (began, finished, until) in [
            (start + Duration::from_millis(1), start, start + maximum),
            (start, start + maximum, start + maximum),
            (start, start + maximum, start + Duration::from_secs(1)),
            (start, start, start + Duration::from_nanos(999)),
            (
                start,
                start + Duration::from_secs(2),
                start + maximum + Duration::from_millis(1),
            ),
        ] {
            assert!(sampled_lease_budget(began, finished, until).is_err());
        }
        assert_eq!(
            sampled_lease_budget(start, start, start + maximum).unwrap(),
            LEASE_SECONDS * 1000
        );
    }
}
