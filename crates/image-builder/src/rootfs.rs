//! Private cold-boot disk inspection. This is not a memory checkpoint or a
//! prepared-tar manifest, and grants no runtime capability or launch authority.
use crate::{Content, MAX_DISK_BYTES, invalid};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use uuid::Uuid;

/// The guest PID1 configuration schema. Missing fields follow the same defaults
/// as goldenhoop-init; unknown fields are refused. The trusted host supplies the
/// expected values, rather than accepting a policy chosen by the inspected disk.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct RootfsGuestConfig {
    pub control_port: u32,
    pub pids: u32,
}
impl Default for RootfsGuestConfig {
    fn default() -> Self {
        Self {
            control_port: 52,
            pids: 256,
        }
    }
}
impl RootfsGuestConfig {
    pub fn validate(&self) -> io::Result<()> {
        if self.control_port == 0 || self.control_port >= 1024 || !(16..=65535).contains(&self.pids)
        {
            return Err(invalid("invalid expected rootfs guest configuration"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsInspectionRequest {
    pub generation: Uuid,
    pub disk: Content,
    pub agent: Content,
    pub init: Content,
    pub guest: RootfsGuestConfig,
}
impl RootfsInspectionRequest {
    pub fn validate(&self) -> io::Result<()> {
        self.disk.validate(MAX_DISK_BYTES)?;
        self.agent.validate(64 * 1024 * 1024)?;
        self.init.validate(64 * 1024 * 1024)?;
        self.guest.validate()?;
        if self.generation.is_nil()
            || self.disk.size_bytes < 64 * 1024 * 1024
            || !self.disk.size_bytes.is_multiple_of(4096)
        {
            return Err(invalid("invalid rootfs inspection identity or disk size"));
        }
        Ok(())
    }
    pub fn fingerprint(&self) -> io::Result<String> {
        self.validate()?;
        let mut digest = Sha256::new();
        digest.update(b"goldenhoop.rootfs-inspection.request.v1\0");
        digest.update(serde_json::to_vec(self)?);
        Ok(format!("{:x}", digest.finalize()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootfsInspectionInventory {
    pub format: u32,
    pub builder_version: String,
    pub agent: Content,
    pub init: Content,
    pub e2fsck: Content,
    pub debugfs: Content,
}
impl RootfsInspectionInventory {
    pub fn validate(&self) -> io::Result<()> {
        if self.format != 1 || self.builder_version != env!("CARGO_PKG_VERSION") {
            return Err(invalid("unsupported pinned rootfs inspector inventory"));
        }
        for value in [&self.agent, &self.init, &self.e2fsck, &self.debugfs] {
            value.validate(64 * 1024 * 1024)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectedFile {
    /// A path inside the guest filesystem, never a host input/output pathname.
    pub path: String,
    pub inode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub links: u32,
    pub content: Content,
}
impl InspectedFile {
    fn validate(&self, paths: &[&str], mode: u32, maximum: u64) -> io::Result<()> {
        self.content.validate(maximum)?;
        if !paths.contains(&self.path.as_str())
            || self.inode <= 2
            || self.uid != 0
            || self.gid != 0
            || self.mode != mode
            || self.links != 1
        {
            return Err(invalid("inspected rootfs boot asset metadata differs"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsInspection {
    pub format: u32,
    pub generation: Uuid,
    pub disk: Content,
    pub agent: InspectedFile,
    pub init: InspectedFile,
    pub guest_config: InspectedFile,
    pub guest: RootfsGuestConfig,
    pub inventory: RootfsInspectionInventory,
}
impl RootfsInspection {
    pub fn validate_for(
        &self,
        request: &RootfsInspectionRequest,
        inventory: &RootfsInspectionInventory,
    ) -> io::Result<()> {
        request.validate()?;
        inventory.validate()?;
        self.agent.validate(
            &["/usr/local/bin/goldenhoop-agent"],
            0o755,
            64 * 1024 * 1024,
        )?;
        self.init.validate(
            &["/sbin/goldenhoop-init", "/usr/sbin/goldenhoop-init"],
            0o755,
            64 * 1024 * 1024,
        )?;
        self.guest_config
            .validate(&["/etc/goldenhoop/guest.json"], 0o644, 4096)?;
        if self.format != 1
            || self.generation != request.generation
            || self.disk != request.disk
            || self.agent.content != request.agent
            || self.init.content != request.init
            || self.agent.content != inventory.agent
            || self.init.content != inventory.init
            || self.guest != request.guest
            || self.inventory != *inventory
            || [self.agent.inode, self.init.inode, self.guest_config.inode]
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != 3
        {
            return Err(invalid(
                "rootfs inspection differs from its input or pinned inspector",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsInspectionReport {
    pub passed: bool,
    pub staging_absent: bool,
    pub tools_collected: bool,
    pub inspection: Option<RootfsInspection>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (
        RootfsInspectionRequest,
        RootfsInspectionInventory,
        RootfsInspection,
    ) {
        let asset = Content {
            sha256: "a".repeat(64),
            size_bytes: 512,
        };
        let request = RootfsInspectionRequest {
            generation: Uuid::new_v4(),
            disk: Content {
                sha256: "d".repeat(64),
                size_bytes: 64 * 1024 * 1024,
            },
            agent: asset.clone(),
            init: asset.clone(),
            guest: RootfsGuestConfig::default(),
        };
        let inventory = RootfsInspectionInventory {
            format: 1,
            builder_version: env!("CARGO_PKG_VERSION").into(),
            agent: asset.clone(),
            init: asset.clone(),
            e2fsck: asset.clone(),
            debugfs: asset.clone(),
        };
        let file = |path: &str, inode, mode| InspectedFile {
            path: path.into(),
            inode,
            uid: 0,
            gid: 0,
            mode,
            links: 1,
            content: asset.clone(),
        };
        let found = RootfsInspection {
            format: 1,
            generation: request.generation,
            disk: request.disk.clone(),
            agent: file("/usr/local/bin/goldenhoop-agent", 18, 0o755),
            init: file("/usr/sbin/goldenhoop-init", 19, 0o755),
            guest_config: file("/etc/goldenhoop/guest.json", 20, 0o644),
            guest: request.guest.clone(),
            inventory: inventory.clone(),
        };
        (request, inventory, found)
    }
    #[test]
    fn inspection_refuses_foreign_disk_generation_tools_and_boot_asset_metadata() {
        let (request, inventory, good) = fixture();
        good.validate_for(&request, &inventory).unwrap();
        let mut bad = good.clone();
        bad.generation = Uuid::new_v4();
        assert!(bad.validate_for(&request, &inventory).is_err());
        let mut bad = good.clone();
        bad.disk.sha256 = "e".repeat(64);
        assert!(bad.validate_for(&request, &inventory).is_err());
        let mut bad = good.clone();
        bad.inventory.debugfs.sha256 = "e".repeat(64);
        assert!(bad.validate_for(&request, &inventory).is_err());
        let mut bad = good.clone();
        bad.agent.content.sha256 = "e".repeat(64);
        assert!(bad.validate_for(&request, &inventory).is_err());
        for field in ["uid", "gid", "links", "mode", "inode", "path"] {
            let mut value = serde_json::to_value(&good).unwrap();
            value["init"][field] = match field {
                "path" => serde_json::json!("/workspace/init"),
                "mode" => serde_json::json!(0o777),
                _ => serde_json::json!(2),
            };
            let bad: RootfsInspection = serde_json::from_value(value).unwrap();
            assert!(bad.validate_for(&request, &inventory).is_err(), "{field}");
        }
        let mut bad = good.clone();
        bad.init.inode = bad.agent.inode;
        assert!(bad.validate_for(&request, &inventory).is_err());
        let mut bad = good;
        bad.guest.pids = 128;
        assert!(bad.validate_for(&request, &inventory).is_err());
    }
    #[test]
    fn tar_authorization_cannot_be_replayed_for_rootfs_inspection_or_changed_intent() {
        let (mut request, _, _) = fixture();
        let archive = crate::PrepareRequest {
            generation: request.generation,
            archive: request.disk.clone(),
            agent: request.agent.clone(),
            init: request.init.clone(),
            disk_bytes: request.disk.size_bytes,
        };
        let mut permit = crate::HostPermit {
            format: 1,
            installation_id: Uuid::new_v4(),
            job_id: Uuid::new_v4(),
            generation: request.generation,
            nonce: Uuid::new_v4(),
            builder_image: format!("sha256:{}", "b".repeat(64)),
            request_sha256: archive.fingerprint().unwrap(),
            runtime: crate::BuilderRuntime::Runsc,
            limits: crate::BuilderLimits {
                memory_max: 1024 * 1024 * 1024,
                swap_max: 0,
                pids_max: 64,
                cpu_quota: 100000,
                cpu_period: 100000,
            },
        };
        permit.validate_for(&archive).unwrap();
        assert!(permit.validate_rootfs(&request).is_err());
        permit.request_sha256 = request.fingerprint().unwrap();
        permit.validate_rootfs(&request).unwrap();
        assert!(permit.validate_for(&archive).is_err());
        request.guest.pids = 128;
        assert!(permit.validate_rootfs(&request).is_err());
        request.guest.pids = 256;
        request.generation = Uuid::new_v4();
        assert!(permit.validate_rootfs(&request).is_err());
    }
    #[test]
    fn rootfs_intent_is_separate_from_tar_conversion_and_binds_guest_configuration() {
        let content = Content {
            sha256: "a".repeat(64),
            size_bytes: 64 * 1024 * 1024,
        };
        let mut request = RootfsInspectionRequest {
            generation: Uuid::new_v4(),
            disk: content.clone(),
            agent: content.clone(),
            init: content.clone(),
            guest: RootfsGuestConfig::default(),
        };
        let fingerprint = request.fingerprint().unwrap();
        let archive = crate::PrepareRequest {
            generation: request.generation,
            archive: content.clone(),
            agent: content.clone(),
            init: content,
            disk_bytes: request.disk.size_bytes,
        };
        assert_ne!(fingerprint, archive.fingerprint().unwrap());
        request.guest.pids = 128;
        assert_ne!(fingerprint, request.fingerprint().unwrap());
        request.guest.control_port = 1024;
        assert!(request.validate().is_err());
        assert!(serde_json::from_str::<RootfsGuestConfig>(r#"{"extra":1}"#).is_err());
        assert_eq!(
            serde_json::from_str::<RootfsGuestConfig>("{}").unwrap(),
            RootfsGuestConfig::default()
        );
    }
}
