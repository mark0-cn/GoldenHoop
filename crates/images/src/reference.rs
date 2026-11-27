//! Public-safe immutable names. Private storage and host observations are not
//! part of an image reference or the metadata returned to a consumer.
use goldenhoop_image_builder::PreparedImage;
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedImageReference {
    pub id: Uuid,
    pub generation: Uuid,
    pub manifest_sha256: String,
}
fn invalid() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidRequest,
        "invalid immutable prepared image reference",
    )
}
impl PreparedImageReference {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.id.is_nil() || self.generation.is_nil() || !crate::hex_id(&self.manifest_sha256) {
            return Err(invalid());
        }
        Ok(())
    }

    /// Hash the typed manifest as a sorted-key JSON value, independent of its
    /// original whitespace or object field order. Callers validate its binding
    /// to the preparation request and the trusted inventory separately.
    pub fn for_manifest(id: Uuid, manifest: &PreparedImage) -> Result<Self, ApiError> {
        let mut value = serde_json::to_value(manifest).map_err(|_| invalid())?;
        value.sort_all_objects();
        let bytes = serde_json::to_vec(&value).map_err(|_| invalid())?;
        let result = Self {
            id,
            generation: manifest.generation,
            manifest_sha256: format!("{:x}", Sha256::digest(bytes)),
        };
        result.validate()?;
        Ok(result)
    }
}
impl fmt::Display for PreparedImageReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "prepared:{}:{}:{}",
            self.id, self.generation, self.manifest_sha256
        )
    }
}
impl FromStr for PreparedImageReference {
    type Err = ApiError;
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        // Reject aliases, uppercase UUIDs, whitespace and extra components.
        if raw.len() != 147 {
            return Err(invalid());
        }
        let parts: Vec<_> = raw.split(':').collect();
        if parts.len() != 4 || parts[0] != "prepared" {
            return Err(invalid());
        }
        let result = Self {
            id: Uuid::parse_str(parts[1]).map_err(|_| invalid())?,
            generation: Uuid::parse_str(parts[2]).map_err(|_| invalid())?,
            manifest_sha256: parts[3].into(),
        };
        result.validate()?;
        if result.to_string() != raw {
            return Err(invalid());
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyImageInfo {
    pub reference: PreparedImageReference,
    pub manifest: PreparedImage,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_name_matches_an_independent_sorted_json_vector() {
        let content = serde_json::json!({"sha256":"a".repeat(64),"size_bytes":512});
        let manifest: PreparedImage = serde_json::from_value(serde_json::json!({
            "format":1,"generation":"00112233-4455-6677-8899-aabbccddeeff",
            "archive":content,"agent":content,"init":content,
            "disk":{"sha256":"d".repeat(64),"size_bytes":67108864},
            "mke2fs":content,"e2fsck":content,"created_at":"2026-11-27T00:00:00Z",
            "builder_version":"0.1.0-alpha.1"
        }))
        .unwrap();
        // Independently computed with Python json.dumps(sort_keys=True,
        // separators=(',', ':')) + hashlib.sha256. Also run this vector with
        // serde_json/preserve_order enabled; dependency features must not rename
        // a previously acknowledged image.
        let reference = PreparedImageReference::for_manifest(Uuid::new_v4(), &manifest).unwrap();
        assert_eq!(
            reference.manifest_sha256,
            "2a19a3e72ecf0e086b41c71835228192fa4a9dd954d8e9cbdc1d69d350b8ef8a"
        );
    }

    #[test]
    fn image_names_are_canonical_and_cannot_select_a_path_or_mutable_tag() {
        let reference = PreparedImageReference {
            id: Uuid::new_v4(),
            generation: Uuid::new_v4(),
            manifest_sha256: "a".repeat(64),
        };
        let raw = reference.to_string();
        assert_eq!(raw.parse::<PreparedImageReference>().unwrap(), reference);
        for value in [
            format!("{raw} "),
            format!("{raw}:extra"),
            raw.to_uppercase(),
            raw.replace(':', "/"),
            "debian:latest".into(),
            "/host/rootfs.ext4".into(),
            raw.replace(&reference.id.to_string(), &Uuid::nil().to_string()),
            raw.replace(&reference.generation.to_string(), &Uuid::nil().to_string()),
            raw.replace(&reference.manifest_sha256, &"A".repeat(64)),
        ] {
            assert!(value.parse::<PreparedImageReference>().is_err(), "{value}");
        }
        assert!(
            serde_json::from_value::<PreparedImageReference>(serde_json::json!({
                "id":reference.id,"generation":reference.generation,
                "manifest_sha256":reference.manifest_sha256,"path":"/host/rootfs"
            }))
            .is_err()
        );
    }
}
