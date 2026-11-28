//! Independent disk content for a fresh boot. A reference is not launch, source
//! recovery, inspection, or garbage-collection authority.
use crate::{
    checkpoint::CaptureIdentity,
    control::{GUEST_CONTROL_VERSION, GuestBarrierPhase, GuestRootfsBarrierInfo},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[cfg(target_os = "linux")]
pub mod storage;

pub const MAX_ROOTFS_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;
fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsArtifact {
    pub sha256: String,
    pub size_bytes: u64,
}
impl RootfsArtifact {
    fn validate(&self, maximum: u64) -> Result<(), &'static str> {
        if !valid_sha(&self.sha256) || self.size_bytes == 0 || self.size_bytes > maximum {
            return Err("rootfs artifact digest or size differs");
        }
        Ok(())
    }
}

/// Cold boot pins its executable/kernel/guest ABI without adopting a retained
/// CPU state, host CPU fingerprint, running process or public execution ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsBoot {
    pub firecracker_version: String,
    pub firecracker_sha256: String,
    pub jailer_sha256: String,
    pub kernel: RootfsArtifact,
    pub architecture: String,
    pub guest_control_version: u16,
    pub agent: RootfsArtifact,
    pub init: RootfsArtifact,
    pub guest_config: RootfsArtifact,
    pub control_port: u32,
    pub workload_pids: u32,
}
impl RootfsBoot {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.kernel.validate(128 * MIB)?;
        self.agent.validate(64 * MIB)?;
        self.init.validate(64 * MIB)?;
        self.guest_config.validate(4096)?;
        if self.firecracker_version != "1.18.0"
            || !valid_sha(&self.firecracker_sha256)
            || !valid_sha(&self.jailer_sha256)
            || self.architecture != "x86_64"
            || self.guest_control_version != GUEST_CONTROL_VERSION
            || self.control_port != 52
            || !(16..=65535).contains(&self.workload_pids)
        {
            return Err("rootfs boot assets, architecture or guest ABI differs");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RootfsOrigin {
    Configured {
        disk: RootfsArtifact,
    },
    Prepared {
        image: Uuid,
        generation: Uuid,
        manifest_sha256: String,
        disk: RootfsArtifact,
    },
}
impl RootfsOrigin {
    fn validate(&self) -> Result<(), &'static str> {
        let disk = match self {
            Self::Configured { disk } => disk,
            Self::Prepared {
                image,
                generation,
                manifest_sha256,
                disk,
            } => {
                if image.is_nil() || generation.is_nil() || !valid_sha(manifest_sha256) {
                    return Err("rootfs source prepared-image identity differs");
                }
                disk
            }
        };
        disk.validate(MAX_ROOTFS_BYTES)?;
        valid_disk_size(disk.size_bytes)
    }
}
fn valid_disk_size(bytes: u64) -> Result<(), &'static str> {
    if !(64 * MIB..=MAX_ROOTFS_BYTES).contains(&bytes) || !bytes.is_multiple_of(4096) {
        return Err("rootfs disk size or alignment differs");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsCaptureIntent {
    pub source: CaptureIdentity,
    pub boot: RootfsBoot,
    pub origin: RootfsOrigin,
    pub barrier: Uuid,
    pub inspection_generation: Uuid,
    pub inspector_inventory_sha256: String,
    pub disk_id: Uuid,
    pub disk_bytes: u64,
}
impl RootfsCaptureIntent {
    pub fn validate(&self) -> Result<(), &'static str> {
        if [
            self.source.installation,
            self.source.sandbox,
            self.source.source_generation,
            self.source.capture,
            self.barrier,
            self.inspection_generation,
            self.disk_id,
        ]
        .iter()
        .any(Uuid::is_nil)
            || !valid_sha(&self.source.request_sha256)
            || !valid_sha(&self.inspector_inventory_sha256)
        {
            return Err("rootfs capture identity differs");
        }
        self.boot.validate()?;
        self.origin.validate()?;
        let origin_disk = match &self.origin {
            RootfsOrigin::Configured { disk } | RootfsOrigin::Prepared { disk, .. } => disk,
        };
        if origin_disk.size_bytes != self.disk_bytes {
            return Err("rootfs source image disk length differs");
        }
        valid_disk_size(self.disk_bytes)
    }
    pub fn fingerprint(&self) -> Result<String, &'static str> {
        self.validate()?;
        let mut digest = Sha256::new();
        digest.update(b"goldenhoop.rootfs-capture.intent.v1\0");
        digest.update(serde_json::to_vec(self).map_err(|_| "cannot encode rootfs intent")?);
        Ok(format!("{:x}", digest.finalize()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsManifest {
    pub format: u16,
    pub filesystem: RootfsFilesystem,
    pub intent: RootfsCaptureIntent,
    pub barrier: GuestRootfsBarrierInfo,
    pub disk: RootfsArtifact,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootfsFilesystem {
    Ext4,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsReference {
    pub installation: Uuid,
    pub capture: Uuid,
    pub manifest_sha256: String,
}
impl RootfsManifest {
    pub fn validate(&self, reserved_bytes: u64) -> Result<(), &'static str> {
        self.intent.validate()?;
        self.disk.validate(MAX_ROOTFS_BYTES)?;
        self.barrier
            .validate(self.intent.source.source_generation, self.intent.barrier)?;
        if self.format != 1
            || self.barrier.phase != GuestBarrierPhase::Quiesced
            || self.disk.size_bytes != self.intent.disk_bytes
            || self.disk.size_bytes > reserved_bytes
        {
            return Err("rootfs manifest, frozen receipt or reservation differs");
        }
        Ok(())
    }
    pub fn reference(&self) -> Result<RootfsReference, &'static str> {
        self.validate(u64::MAX)?;
        let mut digest = Sha256::new();
        digest.update(b"goldenhoop.rootfs-snapshot.manifest.v1\0");
        digest.update(serde_json::to_vec(self).map_err(|_| "cannot encode rootfs manifest")?);
        Ok(RootfsReference {
            installation: self.intent.source.installation,
            capture: self.intent.source.capture,
            manifest_sha256: format!("{:x}", digest.finalize()),
        })
    }
    pub fn admit(
        &self,
        reference: &RootfsReference,
        expected_boot: &RootfsBoot,
        reserved_bytes: u64,
    ) -> Result<(), &'static str> {
        self.validate(reserved_bytes)?;
        if self.reference()? != *reference || &self.intent.boot != expected_boot {
            return Err("rootfs manifest differs from its trusted reference or boot policy");
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
