//! Shared work transport with an explicit boundary for Docker-only protection.
use super::*;
use async_trait::async_trait;
use std::path::PathBuf;

pub struct RuntimeSetup {
    pub agent_image: Option<String>,
    pub kernel_probe_image: Option<String>,
    pub allow_runc_development: bool,
    pub firecracker_config: Option<PathBuf>,
}

#[async_trait]
pub(super) trait WorkerDriver: SandboxRuntime {
    async fn profile_snapshot(&self) -> RuntimeProfile;
    async fn reap_expired(&self) -> Result<Vec<Uuid>, ApiError>;
    fn protected_docker(&self) -> Result<&DockerDriver, ApiError> {
        Err(ApiError::new(
            ErrorCode::UnsupportedCapability,
            "this backend has no verified protected Docker network path",
        ))
    }
}

#[async_trait]
impl WorkerDriver for DockerDriver {
    async fn profile_snapshot(&self) -> RuntimeProfile {
        DockerDriver::profile_snapshot(self).await
    }
    async fn reap_expired(&self) -> Result<Vec<Uuid>, ApiError> {
        DockerDriver::reap_expired(self).await
    }
    fn protected_docker(&self) -> Result<&DockerDriver, ApiError> {
        Ok(self)
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl WorkerDriver for goldenhoop_firecracker::lifecycle::FirecrackerDriver {
    async fn profile_snapshot(&self) -> RuntimeProfile {
        goldenhoop_firecracker::lifecycle::FirecrackerDriver::profile_snapshot(self).await
    }
    async fn reap_expired(&self) -> Result<Vec<Uuid>, ApiError> {
        goldenhoop_firecracker::lifecycle::FirecrackerDriver::reap_expired(self).await
    }
}
