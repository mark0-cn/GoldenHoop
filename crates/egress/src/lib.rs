//! Trusted host packet-filter adapter. No production capability is published.
//! The caller must supply a journal-bound allocation over private stdio.
pub mod controller;
pub mod dns;
mod identity;
pub use identity::NetworkIdentity;
mod ethernet;
pub use ethernet::EthernetPlan;
mod source;
pub use source::{Endpoint, Mac, SourcePlan, SourceScope};
mod destinations;
pub use destinations::{DestinationClass, DestinationScope, ProtectedDestinations};
mod destination_plan;
pub use destination_plan::{DestinationDefinition, DestinationListener, DestinationPlan};
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
