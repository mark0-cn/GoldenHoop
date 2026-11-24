//! Trusted host packet-filter adapter. No production capability is published.
//! The caller must supply a journal-bound allocation over private stdio.
pub mod dns;
mod plan;
pub use plan::{Allocation, Config, LEASE_SECONDS, Plan};

#[cfg(target_os = "linux")]
mod manager;
#[cfg(target_os = "linux")]
pub use manager::{Manager, Observation};

use goldenhoop_protocol::{ApiError, ErrorCode};

fn error(code: ErrorCode, message: &'static str) -> ApiError {
    ApiError::new(code, message)
}
