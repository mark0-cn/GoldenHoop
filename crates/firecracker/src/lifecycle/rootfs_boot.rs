//! Disk-only boot identity. It never acquires the memory continuation claim.
use super::*;
use crate::rootfs::{
    RootfsArtifact, RootfsBoot, RootfsManifest, RootfsReference, storage::RootfsBootTarget,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsBootRequest {
    pub sandbox: Sandbox,
    pub request: CreateSandbox,
    pub reference: RootfsReference,
    pub operation: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_source: Option<goldenhoop_runtime::RuntimeHandle>,
}
impl RootfsBootRequest {
    pub(crate) fn digest(&self) -> Result<String> {
        if [
            self.sandbox.id,
            self.reference.capture,
            self.reference.installation,
            self.operation,
        ]
        .iter()
        .any(Uuid::is_nil)
            || self.reference.manifest_sha256.len() != 64
        {
            return Err(invalid("rootfs native target identity differs").into());
        }
        let mut hash = Sha256::new();
        hash.update(b"goldenhoop.native-rootfs-boot.v1\0");
        hash.update(serde_json::to_vec(&(
            &self.request,
            &self.reference,
            self.operation,
            self.sandbox.id,
            self.sandbox.created_at,
            self.sandbox.expires_at,
            &self.expected_source,
        ))?);
        Ok(format!("{:x}", hash.finalize()))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootfsBootBinding {
    pub target: RootfsBootTarget,
    pub manifest: RootfsManifest,
}
impl DriverConfig {
    pub(crate) fn rootfs_boot_contract(&self) -> Result<RootfsBoot> {
        let policy = self
            .rootfs
            .as_ref()
            .ok_or_else(|| invalid("rootfs policy is absent"))?;
        policy.validate()?;
        let content = |c: &goldenhoop_image_builder::Content| RootfsArtifact {
            sha256: c.sha256.clone(),
            size_bytes: c.size_bytes,
        };
        let value = RootfsBoot {
            firecracker_version: crate::api::SUPPORTED_VMM_VERSION.into(),
            firecracker_sha256: self.artifacts.firecracker.sha256.clone(),
            jailer_sha256: self.artifacts.jailer.sha256.clone(),
            kernel: RootfsArtifact {
                sha256: self.artifacts.kernel.sha256.clone(),
                size_bytes: self.artifacts.kernel.size,
            },
            architecture: std::env::consts::ARCH.into(),
            guest_control_version: crate::control::GUEST_CONTROL_VERSION,
            agent: content(&policy.inventory.agent),
            init: content(&policy.inventory.init),
            guest_config: policy.guest_config.clone(),
            control_port: policy.guest.control_port,
            workload_pids: policy.guest.pids,
        };
        value.validate().map_err(invalid)?;
        Ok(value)
    }
    pub(crate) fn rootfs_boot_artifacts(&self, binding: &RootfsBootBinding) -> Result<BootInput> {
        binding
            .manifest
            .admit(
                &binding.target.reference,
                &self.rootfs_boot_contract()?,
                binding.manifest.intent.disk_bytes,
            )
            .map_err(invalid)?;
        let mut value = self.artifacts.clone();
        value.rootfs = Artifact {
            path: binding.target.disk_path(),
            sha256: binding.manifest.disk.sha256.clone(),
            size: binding.manifest.disk.size_bytes,
        };
        Ok(value)
    }
}
impl RootfsBootBinding {
    pub(crate) fn validate(&self, cfg: &DriverConfig, record: &VmJournal) -> Result<()> {
        self.target.matches(&self.manifest)?;
        if self.target.reference.installation != cfg.installation_id
            || self.target.sandbox != record.owner.sandbox_id
            || self.target.generation != record.owner.generation
            || self.target.request_sha256 != record.owner.request_sha256
            || self.target.path() != cfg.paths(record.owner.generation)?.root
            || record.selected_image.is_some()
            || record.restore.is_some()
            || record.resources.pids != self.manifest.intent.boot.workload_pids
            || record.artifacts != cfg.rootfs_boot_artifacts(self)?
        {
            return Err(
                invalid("native rootfs boot journal differs from its immutable binding").into(),
            );
        }
        Ok(())
    }
    pub(crate) fn same(&self, other: &Self) -> Result<bool> {
        Ok(serde_json::to_vec(self)? == serde_json::to_vec(other)?)
    }
}
/// Constructed only after the native collector has closed its original journal.
/// This receipt can close a pending source hold, never launch or resume a VM.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CollectedRootfsBoot {
    target: RootfsBootTarget,
    boot: String,
    namespace: (u64, u64),
    supervisor: Option<ProcessIdentity>,
    vmm: Option<ProcessIdentity>,
    directory: Option<root::CollectedDirectory>,
    native_journal_sha256: String,
}
impl CollectedRootfsBoot {
    pub(super) fn observe(cfg: &DriverConfig, record: &VmJournal) -> Result<Self> {
        record.validate(cfg, record.owner.sandbox_id)?;
        if record.phase != "collected" {
            return Err(invalid("rootfs target collection is not acknowledged").into());
        }
        let binding = record
            .rootfs_boot
            .as_ref()
            .ok_or_else(|| invalid("rootfs target binding absent"))?;
        let directory = match (&record.vm_root, &record.supervisor) {
            (Some(receipt), Some(producer)) if record.root_collection_started => {
                Some(receipt.confirm_collected(
                    binding.target.path(),
                    record.owner.generation,
                    producer,
                )?)
            }
            (None, _) => None,
            _ => return Err(invalid("rootfs target root collection receipt is incomplete").into()),
        };
        let ns = File::open("/proc/self/ns/pid")?.metadata()?;
        let proof = Self {
            target: binding.target.clone(),
            boot: boot_id()?,
            namespace: (ns.dev(), ns.ino()),
            supervisor: record.supervisor.clone(),
            vmm: record.process.as_ref().map(|p| ProcessIdentity {
                pid: p.pid,
                start_ticks: p.start_ticks,
                boot_id: p.boot_id.clone(),
                executable_sha256: p.executable_sha256.clone(),
                uid: p.uid,
            }),
            directory,
            native_journal_sha256: format!("{:x}", Sha256::digest(serde_json::to_vec(record)?)),
        };
        proof.matches(&binding.target)?;
        proof.require_absent()?;
        Ok(proof)
    }
    pub(crate) fn matches(&self, target: &RootfsBootTarget) -> Result<()> {
        if self.target != *target
            || self.native_journal_sha256.len() != 64
            || self.namespace.1 == 0
            || Uuid::parse_str(&self.boot)?.is_nil()
            || self.directory.as_ref().is_some_and(|r| {
                self.supervisor
                    .as_ref()
                    .is_none_or(|p| !r.binding_matches(target.path(), target.generation, p))
            })
        {
            return Err(invalid("rootfs native collection receipt differs").into());
        }
        Ok(())
    }
    pub(crate) fn require_absent(&self) -> Result<()> {
        let ns = File::open("/proc/self/ns/pid")?.metadata()?;
        if self.boot != boot_id()?
            || self.namespace != (ns.dev(), ns.ino())
            || !recovery::absent(self.target.path())?
        {
            return Err(
                invalid("rootfs target collection observation context or root differs").into(),
            );
        }
        let suffix = format!(
            "{}-{}",
            self.target.reference.installation.simple(),
            self.target.generation.simple()
        );
        for prefix in ["ghs", "ghv"] {
            if !recovery::absent(&Path::new("/sys/fs/cgroup").join(format!("{prefix}-{suffix}")))? {
                return Err(invalid("rootfs target native cgroup remains present").into());
            }
        }
        for process in [&self.supervisor, &self.vmm].into_iter().flatten() {
            if !reaper::process_absent(process)? {
                return Err(invalid("rootfs target original process remains present").into());
            }
        }
        if let Some(directory) = &self.directory {
            directory.verify()?;
        }
        Ok(())
    }
}
