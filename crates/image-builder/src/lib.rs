//! Offline image conversion inside an explicitly isolated build container.
//! Host image resolution, allocation journals and export/collection are separate
//! responsibilities; an image manifest alone does not establish a usable VM.
#[cfg(target_os = "linux")]
mod archive;
#[cfg(target_os = "linux")]
pub mod linux;
mod permit;
pub use permit::{BuilderInventory, BuilderLimits, BuilderRuntime, HostPermit};
mod rootfs;
pub use rootfs::{
    InspectedFile, RootfsGuestConfig, RootfsInspection, RootfsInspectionInventory,
    RootfsInspectionReport, RootfsInspectionRequest,
};

use serde::{Deserialize, Serialize};
use std::io;
use uuid::Uuid;

pub const MAX_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_DISK_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 200_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Content {
    pub sha256: String,
    pub size_bytes: u64,
}
impl Content {
    pub fn validate(&self, maximum: u64) -> io::Result<()> {
        if self.size_bytes == 0 || self.size_bytes > maximum || !valid_sha(&self.sha256) {
            return Err(invalid("invalid image content digest or length"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub generation: Uuid,
    pub archive: Content,
    pub agent: Content,
    pub init: Content,
    pub disk_bytes: u64,
}
impl PrepareRequest {
    pub fn fingerprint(&self) -> io::Result<String> {
        use sha2::{Digest, Sha256};
        self.validate()?;
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
    pub fn validate(&self) -> io::Result<()> {
        self.archive.validate(MAX_ARCHIVE_BYTES)?;
        self.agent.validate(64 * 1024 * 1024)?;
        self.init.validate(64 * 1024 * 1024)?;
        if self.generation.is_nil()
            || self.disk_bytes < 64 * 1024 * 1024
            || self.disk_bytes > MAX_DISK_BYTES
            || !self.disk_bytes.is_multiple_of(4096)
        {
            return Err(invalid("invalid image preparation generation or disk size"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedImage {
    pub format: u32,
    pub generation: Uuid,
    pub archive: Content,
    pub agent: Content,
    pub init: Content,
    pub disk: Content,
    pub mke2fs: Content,
    pub e2fsck: Content,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub builder_version: String,
}

impl PreparedImage {
    pub fn validate_for(
        &self,
        request: &PrepareRequest,
        inventory: &BuilderInventory,
    ) -> io::Result<()> {
        request.validate()?;
        inventory.validate()?;
        self.disk.validate(MAX_DISK_BYTES)?;
        if self.format != 1
            || self.generation != request.generation
            || self.archive != request.archive
            || self.agent != request.agent
            || self.init != request.init
            || self.agent != inventory.agent
            || self.init != inventory.init
            || self.mke2fs != inventory.mke2fs
            || self.e2fsck != inventory.e2fsck
            || self.disk.size_bytes != request.disk_bytes
            || self.builder_version != inventory.builder_version
        {
            return Err(invalid(
                "prepared image is not bound to this request and pinned builder",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareReport {
    pub passed: bool,
    pub staging_absent: bool,
    pub tools_collected: bool,
    pub manifest: Option<PreparedImage>,
    pub error: Option<String>,
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_image_intents_cannot_admit_io() {
        let good = Content {
            sha256: "a".repeat(64),
            size_bytes: 512,
        };
        let mut request = PrepareRequest {
            generation: Uuid::new_v4(),
            archive: good.clone(),
            agent: good.clone(),
            init: good,
            disk_bytes: 1024 * 1024 * 1024,
        };
        request.validate().unwrap();
        request.generation = Uuid::nil();
        assert!(request.validate().is_err());
        request.generation = Uuid::new_v4();
        request.disk_bytes = MAX_DISK_BYTES + 4096;
        assert!(request.validate().is_err());
        request.disk_bytes = 64 * 1024 * 1024 + 1;
        assert!(request.validate().is_err());
        request.disk_bytes = 64 * 1024 * 1024;
        request.archive.size_bytes = MAX_ARCHIVE_BYTES + 1;
        assert!(request.validate().is_err());
        request.archive.size_bytes = 512;
        request.agent.sha256 = "A".repeat(64);
        assert!(request.validate().is_err());
    }
}
