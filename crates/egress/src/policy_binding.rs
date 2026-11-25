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
