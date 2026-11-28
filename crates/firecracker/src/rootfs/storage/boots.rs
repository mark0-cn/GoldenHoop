//! Independent cold-boot targets. These references never consume a memory claim.
use super::*;
use crate::lifecycle::{recovery, root::Root};

/// Bound before native dispatch. A target identity is permanently spent even
/// after its source hold closes; exact retry cannot select different content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsBootTarget {
    pub reference: RootfsReference,
    pub operation: Uuid,
    pub sandbox: Uuid,
    pub generation: Uuid,
    pub request_sha256: String,
    path: PathBuf,
    parent: Identity,
}
impl RootfsBootTarget {
    pub fn observe(
        reference: RootfsReference,
        operation: Uuid,
        sandbox: Uuid,
        generation: Uuid,
        request_sha256: String,
        path: PathBuf,
    ) -> Result<Self> {
        let target = Self {
            reference,
            operation,
            sandbox,
            generation,
            request_sha256,
            parent: Identity::of(&parent(&path)?)?,
            path,
        };
        target.validate()?;
        if !recovery::absent(&target.path)? {
            return Err(invalid("rootfs target root already exists before admission").into());
        }
        Ok(target)
    }
    fn validate(&self) -> Result<()> {
        if [
            self.reference.installation,
            self.reference.capture,
            self.operation,
            self.sandbox,
            self.generation,
        ]
        .iter()
        .any(Uuid::is_nil)
            || !valid_sha(&self.reference.manifest_sha256)
            || !valid_sha(&self.request_sha256)
            || !self.path.is_absolute()
            || self.path.components().any(|p| {
                matches!(
                    p,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || self.path.file_name().and_then(|v| v.to_str())
                != Some(&self.generation.simple().to_string()[..12])
            || Identity::of(&parent(&self.path)?)? != self.parent
        {
            return Err(invalid("rootfs target intent or original parent differs").into());
        }
        Ok(())
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn disk_path(&self) -> PathBuf {
        self.path
            .join("j/firecracker")
            .join(self.generation.to_string())
            .join("root/rootfs.ext4")
    }
    pub(crate) fn matches(&self, manifest: &RootfsManifest) -> Result<()> {
        self.validate()?;
        if self.reference != manifest.reference().map_err(invalid)?
            || self.sandbox == manifest.intent.source.sandbox
            || self.generation == manifest.intent.source.source_generation
        {
            return Err(
                invalid("rootfs cold-boot target belongs to another source or generation").into(),
            );
        }
        Ok(())
    }
}
fn parent(path: &Path) -> Result<File> {
    let path = path
        .parent()
        .ok_or_else(|| invalid("rootfs target parent absent"))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(invalid("rootfs target parent is not trusted").into());
    }
    Ok(file)
}
fn name(target: Uuid) -> String {
    format!("boot-{target}.json")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Materialization {
    target: RootfsBootTarget,
    content: RootfsArtifact,
    inode: Identity,
    root: crate::lifecycle::root::Receipt,
    supervisor: Actor,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BootRecord {
    format: u16,
    store: Uuid,
    target: RootfsBootTarget,
    manager: Actor,
    dispatched: bool,
    copy: Option<Materialization>,
    collection: Option<crate::lifecycle::CollectedRootfsBoot>,
}
impl BootRecord {
    pub(super) fn validate(&self, root: &Directory) -> Result<()> {
        self.target.validate()?;
        self.manager.validate()?;
        let record = root.record(self.target.reference.capture)?;
        let manifest = record
            .manifest
            .as_ref()
            .ok_or_else(|| invalid("rootfs boot source manifest absent"))?;
        self.target.matches(manifest)?;
        if self.format != 1
            || self.store != root.store()
            || self.manager.process.uid != 0
            || self.target.reference.installation != root.installation()
            || self.target.path.starts_with(&root.path)
            || root.path.starts_with(&self.target.path)
        {
            return Err(invalid("rootfs boot reference ownership differs").into());
        }
        if let Some(copy) = &self.copy {
            copy.supervisor.validate()?;
            if !self.dispatched
                || copy.target != self.target
                || copy.content != manifest.disk
                || !copy.root.binding_matches(
                    &self.target.path,
                    self.target.generation,
                    &copy.supervisor.process,
                )
            {
                return Err(invalid("rootfs independent-copy receipt differs").into());
            }
        }
        if let Some(collection) = &self.collection {
            collection.matches(&self.target)?;
        }
        Ok(())
    }
    fn holds_source(&self) -> bool {
        self.copy.is_none() && self.collection.is_none()
    }
}
pub(super) fn validate_pending(root: &Directory, filename: &str, bytes: &[u8]) -> Result<()> {
    let record: BootRecord = serde_json::from_slice(bytes)?;
    record.validate(root)?;
    if name(record.target.sandbox) != filename {
        return Err(invalid("pending rootfs boot filename differs").into());
    }
    Ok(())
}
impl RootfsStore {
    fn boot_records(&self) -> Result<Vec<BootRecord>> {
        self.root.recover(&[])?;
        let mut records = Vec::new();
        for (count, entry) in std::fs::read_dir(&self.root.path)?.enumerate() {
            if count >= 32768 {
                return Err(invalid("rootfs inventory exceeds bound").into());
            }
            let entry = entry?;
            let filename = entry.file_name();
            let filename = filename
                .to_str()
                .ok_or_else(|| invalid("rootfs entry is not UTF8"))?;
            if let Some(raw) = filename
                .strip_prefix("boot-")
                .and_then(|v| v.strip_suffix(".json"))
            {
                let id = Uuid::parse_str(raw)?;
                if id.is_nil() || name(id) != filename || records.len() >= 8192 {
                    return Err(invalid("rootfs boot inventory differs or exceeds bound").into());
                }
                let record: BootRecord = self.root.read_json(filename)?;
                record.validate(&self.root)?;
                if record.target.sandbox != id {
                    return Err(invalid("rootfs boot target filename differs").into());
                }
                records.push(record);
            }
        }
        Ok(records)
    }
    fn boot_record(&self, target: &RootfsBootTarget) -> Result<BootRecord> {
        self.root.current()?;
        self.root.recover(&[&name(target.sandbox)])?;
        let record: BootRecord = self.root.read_json(&name(target.sandbox))?;
        record.validate(&self.root)?;
        if record.target != *target {
            return Err(invalid("rootfs target already has a different immutable intent").into());
        }
        Ok(record)
    }
    pub fn reserve_boot(
        &self,
        target: RootfsBootTarget,
        expected_boot: &RootfsBoot,
    ) -> Result<RootfsManifest> {
        self.root.current()?;
        target.validate()?;
        let _quota = self.root.quota(true)?;
        self.root.recover_capture(target.reference.capture)?;
        let source = self.root.record(target.reference.capture)?;
        let (_mutex, _) = self.root.job(&source.intent, Some(&source.mutex), true)?;
        let manifest = source
            .manifest
            .as_ref()
            .ok_or_else(|| invalid("rootfs boot source manifest absent"))?;
        manifest
            .admit(&target.reference, expected_boot, source.intent.disk_bytes)
            .map_err(invalid)?;
        target.matches(manifest)?;
        if self.root.exists(&name(target.sandbox))? {
            self.boot_record(&target)?;
            return Ok(manifest.clone());
        }
        if source.phase != Phase::Ready {
            return Err(invalid("rootfs boot requires Ready content").into());
        }
        let records = self.boot_records()?;
        if records.len() >= 8192 || records.iter().filter(|r| r.holds_source()).count() >= 128 {
            return Err(goldenhoop_protocol::ApiError::new(
                goldenhoop_protocol::ErrorCode::QuotaExceeded,
                "rootfs cold-boot references are exhausted",
            )
            .into());
        }
        let record = BootRecord {
            format: 1,
            store: self.root.store(),
            target,
            manager: Actor::current()?,
            dispatched: false,
            copy: None,
            collection: None,
        };
        record.validate(&self.root)?;
        metadata::initial_json(&self.root.path.join(name(record.target.sandbox)), &record)?;
        Ok(manifest.clone())
    }
    pub fn boot_reader(
        &self,
        target: &RootfsBootTarget,
        expected_boot: &RootfsBoot,
    ) -> Result<RootfsReadLease> {
        let record = self.boot_record(target)?;
        if !record.holds_source() {
            return Err(invalid("rootfs target source handoff is already closed").into());
        }
        self.read(&target.reference, expected_boot)
    }
    pub fn boot_reader_inherited(
        &self,
        target: &RootfsBootTarget,
        expected_boot: &RootfsBoot,
        mutex: File,
    ) -> Result<RootfsReadLease> {
        let record = self.boot_record(target)?;
        if !record.dispatched || !record.holds_source() {
            return Err(invalid("rootfs target has no original pending dispatch").into());
        }
        self.read_inherited(&target.reference, expected_boot, mutex)
    }
    pub(crate) fn dispatch_boot(&self, target: &RootfsBootTarget) -> Result<()> {
        let _quota = self.root.quota(true)?;
        let mut record = self.boot_record(target)?;
        if record.dispatched || !record.holds_source() || record.manager != Actor::current()? {
            return Err(invalid("rootfs cold boot is not a fresh original dispatch").into());
        }
        record.dispatched = true;
        metadata::atomic_json(&self.root.path.join(name(target.sandbox)), &record)
    }
    pub(crate) fn confirm_boot_materialized(
        &self,
        target: &RootfsBootTarget,
        lease: &RootfsReadLease,
        root: &Root,
    ) -> Result<()> {
        target.matches(&lease.manifest)?;
        root.verify()?;
        let supervisor = Actor::current()?;
        let receipt = root.receipt();
        if !receipt.binding_matches(&target.path, target.generation, &supervisor.process) {
            return Err(invalid("rootfs copy belongs to another native root or supervisor").into());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(target.disk_path())?;
        let metadata = file.metadata()?;
        let inode = Identity::of(&file)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() != lease.manifest.disk.size_bytes
            || inode == Identity::of(lease.file())?
            || crate::fileio::digest_exact(file.try_clone()?, metadata.len())?
                != (
                    lease.manifest.disk.sha256.clone(),
                    lease.manifest.disk.size_bytes,
                )
            || inode != Identity::of(&file)?
        {
            return Err(
                invalid("rootfs target copy is not independent or its bytes differ").into(),
            );
        }
        file.sync_all()?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(target.disk_path().parent().unwrap())?;
        directory.sync_all()?;
        root.verify()?;
        let _quota = self.root.quota(true)?;
        let mut record = self.boot_record(target)?;
        if !record.dispatched || !record.holds_source() {
            return Err(invalid("rootfs materialization is not an original pending copy").into());
        }
        record.copy = Some(Materialization {
            target: target.clone(),
            content: lease.manifest.disk.clone(),
            inode,
            root: receipt,
            supervisor,
        });
        record.validate(&self.root)?;
        metadata::atomic_json(&self.root.path.join(name(target.sandbox)), &record)
    }
    pub(crate) fn close_collected_boot(
        &self,
        target: &RootfsBootTarget,
        proof: &crate::lifecycle::CollectedRootfsBoot,
    ) -> Result<()> {
        proof.matches(target)?;
        proof.require_absent()?;
        let _quota = self.root.quota(true)?;
        self.root.recover(&[&name(target.sandbox)])?;
        if !self.root.exists(&name(target.sandbox))? {
            return Ok(());
        }
        let mut record = self.boot_record(target)?;
        if record.collection.is_some() {
            return Ok(());
        }
        if record.manager != Actor::current()? {
            record.manager.absent()?;
        }
        record.collection = Some(proof.clone());
        record.validate(&self.root)?;
        metadata::atomic_json(&self.root.path.join(name(target.sandbox)), &record)
    }
    pub(super) fn require_no_pending_boots(&self, capture: Uuid) -> Result<()> {
        if self
            .boot_records()?
            .iter()
            .any(|r| r.target.reference.capture == capture && r.holds_source())
        {
            return Err(invalid("rootfs content has pending cold-boot references").into());
        }
        Ok(())
    }
}
