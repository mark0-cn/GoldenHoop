use crate::{Content, PrepareRequest, invalid, valid_sha};
use serde::{Deserialize, Serialize};
use std::io;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuilderInventory {
    pub format: u32,
    pub builder_version: String,
    pub agent: Content,
    pub init: Content,
    pub mke2fs: Content,
    pub e2fsck: Content,
}
impl BuilderInventory {
    pub fn validate(&self) -> io::Result<()> {
        if self.format != 1 || self.builder_version != env!("CARGO_PKG_VERSION") {
            return Err(invalid("unsupported pinned builder inventory"));
        }
        for item in [&self.agent, &self.init, &self.mke2fs, &self.e2fsck] {
            item.validate(64 * 1024 * 1024)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum BuilderRuntime {
    Runsc,
    RuncDevelopment,
}

/// Effective host limits, read outside a userspace kernel. Guest virtual
/// cgroups are not evidence of host enforcement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuilderLimits {
    pub memory_max: u64,
    pub swap_max: u64,
    pub pids_max: u64,
    pub cpu_quota: u64,
    pub cpu_period: u64,
}
impl BuilderLimits {
    pub fn validate(&self) -> io::Result<()> {
        if self.memory_max == 0
            || self.memory_max > 2 * 1024 * 1024 * 1024
            || self.swap_max != 0
            || !(16..=128).contains(&self.pids_max)
            || self.cpu_quota == 0
            || self.cpu_period == 0
            || u128::from(self.cpu_quota) > u128::from(self.cpu_period) * 2
        {
            return Err(invalid(
                "host builder limits exceed the conversion boundary",
            ));
        }
        Ok(())
    }
}

/// A decision delivered once over private Docker stdin by the trusted host
/// parent after actual image/placement/cgroup validation. This is not a signed
/// self-attestation: arbitrary JSON cannot prove host enforcement. The parent
/// and its exclusive control of the pinned converter's stdin are required.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPermit {
    pub format: u32,
    pub installation_id: Uuid,
    pub job_id: Uuid,
    pub generation: Uuid,
    pub nonce: Uuid,
    pub builder_image: String,
    pub request_sha256: String,
    pub runtime: BuilderRuntime,
    pub limits: BuilderLimits,
}
impl HostPermit {
    pub fn validate_for(&self, request: &PrepareRequest) -> io::Result<()> {
        request.validate()?;
        self.limits.validate()?;
        if self.format != 1
            || self.installation_id.is_nil()
            || self.job_id.is_nil()
            || self.nonce.is_nil()
            || self.generation != request.generation
            || self.request_sha256 != request.fingerprint()?
            || !self
                .builder_image
                .strip_prefix("sha256:")
                .is_some_and(valid_sha)
        {
            return Err(invalid(
                "host permit does not authorize this exact preparation",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn foreign_generation_changed_content_and_unbounded_host_permits_are_refused() {
        let content = Content {
            sha256: "a".repeat(64),
            size_bytes: 512,
        };
        let mut request = PrepareRequest {
            generation: Uuid::new_v4(),
            archive: content.clone(),
            agent: content.clone(),
            init: content,
            disk_bytes: 64 * 1024 * 1024,
        };
        let mut permit = HostPermit {
            format: 1,
            installation_id: Uuid::new_v4(),
            job_id: Uuid::new_v4(),
            generation: request.generation,
            nonce: Uuid::new_v4(),
            builder_image: format!("sha256:{}", "b".repeat(64)),
            request_sha256: request.fingerprint().unwrap(),
            runtime: BuilderRuntime::Runsc,
            limits: BuilderLimits {
                memory_max: 1024 * 1024 * 1024,
                swap_max: 0,
                pids_max: 128,
                cpu_quota: 100000,
                cpu_period: 100000,
            },
        };
        permit.validate_for(&request).unwrap();
        request.generation = Uuid::new_v4();
        assert!(permit.validate_for(&request).is_err());
        request.generation = permit.generation;
        request.archive.sha256 = "c".repeat(64);
        assert!(permit.validate_for(&request).is_err());
        request.archive.sha256 = "a".repeat(64);
        permit.limits.swap_max = 1;
        assert!(permit.validate_for(&request).is_err());
        permit.limits.swap_max = 0;
        permit.limits.cpu_quota = 200001;
        assert!(permit.validate_for(&request).is_err());
        permit.limits.cpu_quota = u64::MAX;
        permit.limits.cpu_period = u64::MAX;
        permit.limits.validate().unwrap();
        permit.limits.cpu_period = 1;
        assert!(permit.limits.validate().is_err());
    }
    #[test]
    fn prepared_manifest_cannot_change_disk_size_assets_tools_or_builder_version() {
        let content = Content {
            sha256: "a".repeat(64),
            size_bytes: 512,
        };
        let inventory = BuilderInventory {
            format: 1,
            builder_version: env!("CARGO_PKG_VERSION").into(),
            agent: content.clone(),
            init: content.clone(),
            mke2fs: content.clone(),
            e2fsck: content.clone(),
        };
        let request = PrepareRequest {
            generation: Uuid::new_v4(),
            archive: content.clone(),
            agent: content.clone(),
            init: content.clone(),
            disk_bytes: 64 * 1024 * 1024,
        };
        let good = crate::PreparedImage {
            format: 1,
            generation: request.generation,
            archive: content.clone(),
            agent: content.clone(),
            init: content.clone(),
            disk: Content {
                sha256: "b".repeat(64),
                size_bytes: request.disk_bytes,
            },
            mke2fs: content.clone(),
            e2fsck: content,
            created_at: chrono::Utc::now(),
            builder_version: inventory.builder_version.clone(),
        };
        good.validate_for(&request, &inventory).unwrap();
        let mut changed = good.clone();
        changed.disk.size_bytes += 4096;
        assert!(changed.validate_for(&request, &inventory).is_err());
        let mut changed = good.clone();
        changed.agent.sha256 = "c".repeat(64);
        assert!(changed.validate_for(&request, &inventory).is_err());
        let mut changed = good.clone();
        changed.e2fsck.sha256 = "d".repeat(64);
        assert!(changed.validate_for(&request, &inventory).is_err());
        let mut changed = good;
        changed.builder_version = "foreign".into();
        assert!(changed.validate_for(&request, &inventory).is_err());
    }
}
