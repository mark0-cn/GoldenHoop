//! Trusted Firecracker control components. These do not advertise a runtime
//! profile: actual jailed boot, execution and collection remain separate gates.
#[cfg(target_os = "linux")]
pub mod agent;
#[cfg(target_os = "linux")]
pub mod api;
pub mod checkpoint;
pub mod control;
#[cfg(target_os = "linux")]
mod fileio;
pub mod kvm;
#[cfg(target_os = "linux")]
pub mod lifecycle;
#[cfg(target_os = "linux")]
pub mod machine;
pub mod models;
pub mod rootfs;
#[cfg(target_os = "linux")]
pub mod vsock;

use goldenhoop_protocol::ApiError;
#[cfg(target_os = "linux")]
use goldenhoop_protocol::ErrorCode;
use serde::Serialize;

/// Conservatively retain dispatch uncertainty instead of retrying a mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchState {
    NotSent,
    Rejected,
    Uncertain,
}

#[derive(Debug)]
pub struct CallError {
    pub dispatch: DispatchState,
    pub error: ApiError,
}

impl CallError {
    #[cfg(target_os = "linux")]
    pub(crate) fn new(dispatch: DispatchState, code: ErrorCode, message: &'static str) -> Self {
        let mut error = ApiError::new(code, message);
        if dispatch != DispatchState::NotSent {
            error.retryable = false;
        }
        Self { dispatch, error }
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.dispatch, self.error)
    }
}

impl std::error::Error for CallError {}
