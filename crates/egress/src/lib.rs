//! Trusted host packet-filter adapter. No production capability is published.
//! The caller must supply a journal-bound allocation over private stdio.
pub mod dns;
mod ethernet;
pub use ethernet::EthernetPlan;
mod plan;
pub use plan::{Allocation, Config, DnsBinding, DnsBindings, LEASE_SECONDS, Plan};
#[cfg(target_os = "linux")]
pub mod frontend;

#[cfg(target_os = "linux")]
mod manager;
#[cfg(target_os = "linux")]
pub use manager::{Listening, Manager, Observation, Resolution};

use goldenhoop_protocol::{ApiError, ErrorCode};

fn error(code: ErrorCode, message: &'static str) -> ApiError {
    ApiError::new(code, message)
}
