//! Trusted image preparation orchestration. A source export is not a prepared
//! VM disk and never publishes runtime, snapshot or template capabilities.
#[cfg(target_os = "linux")]
mod coordination;
#[cfg(target_os = "linux")]
pub mod export;
#[cfg(target_os = "linux")]
pub mod host;
#[cfg(target_os = "linux")]
pub mod prepare;
#[cfg(target_os = "linux")]
mod transfer;

use goldenhoop_artifacts::LargeBlobRef;
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    pub id: Uuid,
    pub generation: Uuid,
    /// A locally cached platform-specific image ID, never a mutable tag.
    pub source_image: String,
}
impl ExportRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.id.is_nil() || self.generation.is_nil() || !image_id(&self.source_image) {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "invalid source export intent",
            ));
        }
        Ok(())
    }
}
pub(crate) fn image_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(hex_id)
}
pub(crate) fn hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Serialize)]
pub struct ExportReport {
    pub id: Uuid,
    pub generation: Uuid,
    pub archive_ready: bool,
    pub provider_cleanup: String,
    pub archive: Option<LargeBlobRef>,
    pub source_observation: Option<serde_json::Value>,
    pub recovery_observation: Option<serde_json::Value>,
    pub error: Option<ApiError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePrepareRequest {
    pub id: Uuid,
    pub generation: Uuid,
    pub source_image: String,
    /// Administrator-trusted, locally cached, platform-specific converter ID.
    pub builder_image: String,
    pub runtime: goldenhoop_image_builder::BuilderRuntime,
    pub disk_bytes: u64,
}
impl ImagePrepareRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.id.is_nil()
            || self.generation.is_nil()
            || !image_id(&self.source_image)
            || !image_id(&self.builder_image)
            || !(64 * 1024 * 1024..=goldenhoop_image_builder::MAX_DISK_BYTES)
                .contains(&self.disk_bytes)
            || !self.disk_bytes.is_multiple_of(4096)
        {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "invalid immutable image preparation intent",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct ImagePrepareReport {
    pub id: Uuid,
    pub generation: Uuid,
    pub phase: String,
    pub image_ready: bool,
    pub provider_cleanup: String,
    pub manifest: Option<goldenhoop_image_builder::PreparedImage>,
    pub disk: Option<LargeBlobRef>,
    pub host_observation: Option<serde_json::Value>,
    pub converter_observation: Option<serde_json::Value>,
    pub recovery_observation: Option<serde_json::Value>,
    pub error: Option<ApiError>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_non_nil_immutable_source_intents_are_admitted() {
        let mut request = ExportRequest {
            id: Uuid::new_v4(),
            generation: Uuid::new_v4(),
            source_image: format!("sha256:{}", "a".repeat(64)),
        };
        request.validate().unwrap();
        for value in [
            "debian:latest".into(),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}\n", "a".repeat(64)),
        ] {
            request.source_image = value;
            assert!(request.validate().is_err());
        }
        request.source_image = format!("sha256:{}", "b".repeat(64));
        request.id = Uuid::nil();
        assert!(request.validate().is_err());
    }
}
