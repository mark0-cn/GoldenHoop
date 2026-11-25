//! Trusted host packet-filter adapter. No production capability is published.
//! The caller must supply a journal-bound allocation over private stdio.
mod collection;
pub mod controller;
pub use collection::CollectionReceipt;
mod controller_plan;
pub use controller_plan::{COLLECTION_SECONDS, ControllerPlan, ControllerPurpose};
pub mod dns;
mod identity;
pub use identity::NetworkIdentity;
mod ethernet;
#[cfg(target_os = "linux")]
mod host;
pub mod native;
pub use ethernet::EthernetPlan;
mod source;
pub use source::{Endpoint, EndpointAddresses, Mac, SourceBindingReceipt, SourcePlan, SourceScope};
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
