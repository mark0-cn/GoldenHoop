//! Private checkpoint content admission, independent of a live producer or jail.
//! This does not create a snapshot, publish durable content or authorize restore.
use crate::control::{GUEST_CONTROL_VERSION, GuestBarrierInfo, GuestBarrierPhase};
use goldenhoop_protocol::ResourceLimits;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[cfg(target_os = "linux")]
mod staging;
#[cfg(target_os = "linux")]
pub use staging::{CheckpointFiles, StagedCheckpoint};

const MIB: u64 = 1024 * 1024;
pub const MAX_CHECKPOINT_STATE_BYTES: u64 = 16 * MIB;
const MAX_MEMORY_BYTES: u64 = 16 * 1024 * MIB;
const MAX_DISK_BYTES: u64 = 16 * 1024 * MIB;

fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointContent {
    pub id: Uuid,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Exact compatibility only; no attempt to infer a weaker compatible CPU/VMM.
/// These observations are supplied by the future authenticated capture caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRuntime {
    pub firecracker_version: String,
    pub firecracker_sha256: String,
    pub jailer_sha256: String,
    pub kernel_sha256: String,
    pub architecture: String,
    pub host_compatibility_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureIdentity {
    pub installation: Uuid,
    pub sandbox: Uuid,
    pub source_generation: Uuid,
    pub capture: Uuid,
    pub request_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointManifest {
    pub format: u16,
    pub source: CaptureIdentity,
    pub runtime: CheckpointRuntime,
    pub resources: ResourceLimits,
    pub barrier: GuestBarrierInfo,
    pub state: CheckpointContent,
    pub memory: CheckpointContent,
    pub disk: CheckpointContent,
}

/// Pin this reference in trusted durable metadata before consuming a manifest.
/// A content reference is not producer absence, a restore claim or GC authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointReference {
    pub installation: Uuid,
    pub capture: Uuid,
    pub manifest_sha256: String,
}

impl CheckpointManifest {
    fn validate(&self, budget_bytes: u64) -> Result<u64, &'static str> {
        let source = &self.source;
        let runtime = &self.runtime;
        if self.format != 1
            || [
                source.installation,
                source.sandbox,
                source.source_generation,
                source.capture,
            ]
            .iter()
            .any(Uuid::is_nil)
            || !valid_sha(&source.request_sha256)
            || runtime.firecracker_version != "1.18.0"
            || runtime.architecture != "x86_64"
            || [
                &runtime.firecracker_sha256,
                &runtime.jailer_sha256,
                &runtime.kernel_sha256,
                &runtime.host_compatibility_sha256,
            ]
            .iter()
            .any(|value| !valid_sha(value))
            || self.resources.cpu_millis == 0
            || self.resources.cpu_millis > 8000
            || !(128 * MIB..=MAX_MEMORY_BYTES).contains(&self.resources.memory_bytes)
            || !self.resources.memory_bytes.is_multiple_of(MIB)
            || !(16..=65535).contains(&self.resources.pids)
            || self.barrier.protocol != GUEST_CONTROL_VERSION
            || self.barrier.phase != GuestBarrierPhase::Quiesced
        {
            return Err("checkpoint identity, compatibility, resources or barrier differs");
        }
        self.barrier
            .validate(source.source_generation, self.barrier.barrier)?;
        let objects = [&self.state, &self.memory, &self.disk];
        if objects
            .iter()
            .any(|object| object.id.is_nil() || !valid_sha(&object.sha256))
            || self.state.id == self.memory.id
            || self.state.id == self.disk.id
            || self.memory.id == self.disk.id
            || self.state.size_bytes == 0
            || self.state.size_bytes > MAX_CHECKPOINT_STATE_BYTES
            || self.memory.size_bytes != self.resources.memory_bytes
            || !(64 * MIB..=MAX_DISK_BYTES).contains(&self.disk.size_bytes)
            || !self.disk.size_bytes.is_multiple_of(4096)
        {
            return Err("checkpoint object identity, length or memory layout differs");
        }
        let total = objects.into_iter().try_fold(0u64, |total, object| {
            total
                .checked_add(object.size_bytes)
                .ok_or("checkpoint byte count overflows")
        })?;
        if total > budget_bytes {
            return Err("checkpoint exceeds the caller's reserved byte budget");
        }
        Ok(total)
    }

    pub fn reference(&self) -> Result<CheckpointReference, &'static str> {
        self.validate(u64::MAX)?;
        let mut digest = Sha256::new();
        digest.update(b"goldenhoop.private-checkpoint.v1\0");
        digest.update(serde_json::to_vec(self).map_err(|_| "cannot encode checkpoint manifest")?);
        Ok(CheckpointReference {
            installation: self.source.installation,
            capture: self.source.capture,
            manifest_sha256: format!("{:x}", digest.finalize()),
        })
    }

    pub fn admit(
        &self,
        reference: &CheckpointReference,
        expected_runtime: &CheckpointRuntime,
        reserved_bytes: u64,
    ) -> Result<u64, &'static str> {
        let total = self.validate(reserved_bytes)?;
        if &self.runtime != expected_runtime || self.reference()? != *reference {
            return Err("checkpoint manifest or exact runtime differs from its trusted reference");
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests;
