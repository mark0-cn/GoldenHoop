//! Shared work transport with an explicit boundary for Docker-only protection.
use super::*;
use async_trait::async_trait;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
fn image_admission_error(error: ApiError) -> ApiError {
    if error.code == ErrorCode::Conflict {
        // No native create request has been sent at this point. An unready,
        // collected or changed image refuses this create; it must not turn
        // into an Unknown reservation that later starts a different workload.
        ApiError::new(
            ErrorCode::InvalidRequest,
            "prepared image is not currently admissible",
        )
    } else {
        error
    }
}

pub struct RuntimeSetup {
    pub agent_image: Option<String>,
    pub kernel_probe_image: Option<String>,
    pub allow_runc_development: bool,
    pub firecracker_config: Option<PathBuf>,
}

#[async_trait]
pub(super) trait WorkerDriver: SandboxRuntime {
    async fn create_workload(
        &self,
        _store: &Store,
        _blobs: &goldenhoop_artifacts::BlobStore,
        sandbox: &Sandbox,
        request: &CreateSandbox,
    ) -> Result<RuntimeHandle, ApiError> {
        self.create(sandbox, request).await
    }
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
    async fn create_workload(
        &self,
        store: &Store,
        blobs: &goldenhoop_artifacts::BlobStore,
        sandbox: &Sandbox,
        request: &CreateSandbox,
    ) -> Result<RuntimeHandle, ApiError> {
        if !request.image.starts_with("prepared:") {
            return self.create(sandbox, request).await;
        }
        // Existing generations carry their selected manifest and independent
        // writable disk. Recovery must not require the original image job to
        // remain Ready or its source blobs to remain stored.
        if self
            .discover()
            .await?
            .iter()
            .any(|handle| handle.sandbox_id == sandbox.id)
        {
            return self.create(sandbox, request).await;
        }
        let reference = request
            .image
            .parse::<goldenhoop_images::PreparedImageReference>()?;
        let policy = self.prepared_image_policy().ok_or_else(|| {
            ApiError::new(
                ErrorCode::UnsupportedCapability,
                "native prepared images are not configured",
            )
        })?;
        policy.staging_directory().map_err(|_| {
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "native prepared image staging is not actually bounded",
            )
        })?;
        let preparer = goldenhoop_images::prepare::ImagePreparer::connect(
            store.clone(),
            blobs.clone(),
            policy.allow_runc_development,
        )
        .await?;
        let info = preparer
            .inspect_ready(reference.id, &policy.inventory)
            .await
            .map_err(image_admission_error)?;
        if info.reference != reference {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "prepared image generation or manifest differs",
            ));
        }
        policy.validate_info(&info).map_err(|_| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                "prepared image violates the configured guest policy or disk bounds",
            )
        })?;
        let copy = preparer
            .materialize_ready(&reference, &policy.inventory, &policy.staging_root)
            .await
            .map_err(image_admission_error)?;
        if copy.installation_id() != store.installation_id() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "prepared image installation differs",
            ));
        }
        let (info, file) = copy.into_parts();
        self.create_prepared(sandbox, request, info, file).await
    }
    async fn profile_snapshot(&self) -> RuntimeProfile {
        goldenhoop_firecracker::lifecycle::FirecrackerDriver::profile_snapshot(self).await
    }
    async fn reap_expired(&self) -> Result<Vec<Uuid>, ApiError> {
        goldenhoop_firecracker::lifecycle::FirecrackerDriver::reap_expired(self).await
    }
}
