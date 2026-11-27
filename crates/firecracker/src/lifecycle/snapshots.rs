//! Projection of authenticated, source-bound native observations for the worker.
use super::*;
use crate::checkpoint::{CheckpointManifest, CheckpointReference};
use goldenhoop_runtime::{MemoryCaptureObservation, MemoryCaptureRequest, MemoryCaptureState};
use std::collections::BTreeMap;

fn inconsistent() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "native capture observation differs from its original binding",
    )
}
pub(super) fn validate(
    cfg: &DriverConfig,
    request: &MemoryCaptureRequest,
) -> std::result::Result<(), ApiError> {
    request.validate_identity()?;
    if cfg.checkpoints.is_none() || request.source.image.starts_with("prepared:") {
        return Err(ApiError::new(
            ErrorCode::UnsupportedCapability,
            "native memory continuation is unavailable for this configured source",
        ));
    }
    if request.handle.profile != PROFILE {
        return Err(inconsistent());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    capture: Uuid,
    phase: String,
    capture_outcome: String,
    reserved_bytes: u64,
    #[serde(default)]
    reference: Option<CheckpointReference>,
    #[serde(default)]
    manifest: Option<CheckpointManifest>,
    #[serde(default)]
    content_verified: Option<bool>,
    #[serde(default)]
    objects_absent: Option<bool>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default, rename = "restoration")]
    _restoration: Option<serde_json::Value>,
}

pub(super) fn project(
    cfg: &DriverConfig,
    request: &MemoryCaptureRequest,
    value: serde_json::Value,
) -> std::result::Result<MemoryCaptureObservation, ApiError> {
    request.validate_identity()?;
    let status: Status = serde_json::from_value(value).map_err(|_| inconsistent())?;
    if status.capture != request.id {
        return Err(inconsistent());
    }
    let state = match (status.phase.as_str(), status.capture_outcome.as_str()) {
        ("reserved" | "capturing" | "publishing", "pending")
            if status.content_verified != Some(true)
                && status.objects_absent != Some(true)
                && status.reserved_bytes > 0
                && status.error.is_none() =>
        {
            MemoryCaptureState::Pending
        }
        ("ready", "ready")
            if status.content_verified == Some(true)
                && status.objects_absent != Some(true)
                && status.error.is_none() =>
        {
            let manifest = status.manifest.ok_or_else(inconsistent)?;
            let reference = status.reference.ok_or_else(inconsistent)?;
            if manifest.source.installation != cfg.installation_id
                || manifest.source.sandbox != request.source.id
                || manifest.source.capture != request.id
                || super::driver::native_handle(
                    manifest.source.installation,
                    manifest.source.sandbox,
                    manifest.source.source_generation,
                )
                .backend_ref
                    != request.handle.backend_ref
                || manifest.resources != request.source.resources
                || manifest.reference().map_err(|_| inconsistent())? != reference
            {
                return Err(inconsistent());
            }
            let bytes = manifest
                .state
                .size_bytes
                .checked_add(manifest.memory.size_bytes)
                .and_then(|n| n.checked_add(manifest.disk.size_bytes))
                .ok_or_else(inconsistent)?;
            if status.reserved_bytes < bytes {
                return Err(inconsistent());
            }
            let objects = BTreeMap::from([
                ("state".into(), format!("sha256:{}", manifest.state.sha256)),
                (
                    "memory".into(),
                    format!("sha256:{}", manifest.memory.sha256),
                ),
                ("disk".into(), format!("sha256:{}", manifest.disk.sha256)),
            ]);
            MemoryCaptureState::Ready {
                manifest: Box::new(SnapshotManifest {
                    format_version: 1,
                    id: request.id,
                    source_sandbox_id: request.source.id,
                    kind: SnapshotKind::MemoryAndDisk,
                    driver: request.source.profile.clone(),
                    architecture: manifest.runtime.architecture,
                    image_digest: request.source.image.clone(),
                    objects,
                    runtime_version: manifest.runtime.firecracker_version,
                    created_at: request.created_at,
                }),
                reference: serde_json::to_value(reference).map_err(|_| inconsistent())?,
            }
        }
        ("collected", "ready" | "failed" | "unconfirmed")
            if status.objects_absent == Some(true)
                && status.reserved_bytes == 0
                && status.content_verified != Some(true)
                && status.manifest.is_none()
                && status.reference.is_none() =>
        {
            MemoryCaptureState::Collected
        }
        ("failed" | "collecting" | "collected", "ready" | "failed" | "unconfirmed") => {
            // The root journal retains the original diagnostic. Host paths and
            // private restoration data do not become public API error text.
            let _ = status.error;
            MemoryCaptureState::Failed(ApiError::new(
                ErrorCode::BackendUnavailable,
                "native capture is failed or no longer available; original resources require collection",
            ))
        }
        _ => return Err(inconsistent()),
    };
    Ok(MemoryCaptureObservation {
        id: request.id,
        source: request.handle.clone(),
        state,
    })
}

#[cfg(test)]
mod tests;
