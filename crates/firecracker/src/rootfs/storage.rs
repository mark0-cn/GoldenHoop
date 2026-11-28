//! Durable independent disk production. The caller supplies an authenticated
//! original guest barrier and paused VMM; this module never infers either from
//! a pathname, starts a guest, parses ext4, or implicitly thaws the source.
use super::*;
use crate::lifecycle::{self, ProcessIdentity, Result, invalid, metadata};
use goldenhoop_image_builder::{
    Content, RootfsGuestConfig, RootfsInspection, RootfsInspectionInventory,
    RootfsInspectionReport, RootfsInspectionRequest,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
mod files;
use files::{Directory, DiskReceipt, Identity, record_name};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    process: ProcessIdentity,
    namespace_device: u64,
    namespace_inode: u64,
}
impl Actor {
    fn observe(pid: u32) -> Result<Self> {
        let namespace = std::fs::metadata("/proc/self/ns/pid")?;
        let actor = Self {
            process: lifecycle::process_identity(pid)?,
            namespace_device: namespace.dev(),
            namespace_inode: namespace.ino(),
        };
        actor.validate()?;
        Ok(actor)
    }
    fn current() -> Result<Self> {
        Self::observe(std::process::id())
    }
    fn validate(&self) -> Result<()> {
        if self.process.pid <= 1
            || self.process.pid > i32::MAX as u32
            || self.process.start_ticks == 0
            || Uuid::parse_str(&self.process.boot_id)?.is_nil()
            || !valid_sha(&self.process.executable_sha256)
            || self.namespace_inode == 0
        {
            return Err(invalid("rootfs producer identity differs").into());
        }
        Ok(())
    }
    fn context(&self) -> Result<()> {
        self.validate()?;
        let namespace = std::fs::metadata("/proc/self/ns/pid")?;
        if self.process.boot_id != lifecycle::boot_id()?
            || (self.namespace_device, self.namespace_inode) != (namespace.dev(), namespace.ino())
        {
            return Err(invalid(
                "rootfs producer observation context changed; absence unconfirmed",
            )
            .into());
        }
        Ok(())
    }
    fn present(&self) -> Result<()> {
        self.context()?;
        if lifecycle::process_identity(self.process.pid)? != self.process {
            return Err(invalid("rootfs original source process differs").into());
        }
        Ok(())
    }
    fn absent(&self) -> Result<()> {
        self.context()?;
        if !lifecycle::reaper::process_absent(&self.process)? {
            return Err(invalid("rootfs original producer is still present").into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsStorePolicy {
    pub max_bytes: u64,
    pub max_captures: u32,
}
impl RootfsStorePolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.max_bytes == 0
            || self.max_bytes > 1024 * 1024 * MIB
            || !(1..=128).contains(&self.max_captures)
        {
            return Err(invalid("rootfs store policy differs").into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Reserved,
    Capturing,
    Publishing,
    Captured,
    Ready,
    Failed,
    Collecting,
    Collected,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsVmControl {
    pub pause_dispatched: bool,
    pub pause_observed: bool,
    pub resume_started: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format: u16,
    store: Uuid,
    intent: RootfsCaptureIntent,
    source_writer: Actor,
    source_disk: SourceDisk,
    vm_control: RootfsVmControl,
    producer: Actor,
    producer_settled: bool,
    mutex: Identity,
    phase: Phase,
    frozen: Option<GuestRootfsBarrierInfo>,
    resumed: Option<GuestRootfsBarrierInfo>,
    manifest: Option<RootfsManifest>,
    disk: Option<DiskReceipt>,
    inspection: Option<RootfsInspection>,
    inventory: Option<RootfsInspectionInventory>,
    error: Option<String>,
}
fn content(value: &RootfsArtifact) -> Content {
    Content {
        sha256: value.sha256.clone(),
        size_bytes: value.size_bytes,
    }
}
pub fn inspector_fingerprint(inventory: &RootfsInspectionInventory) -> Result<String> {
    inventory.validate()?;
    let mut digest = Sha256::new();
    digest.update(b"goldenhoop.rootfs-capture.inspector.v1\0");
    digest.update(serde_json::to_vec(inventory)?);
    Ok(format!("{:x}", digest.finalize()))
}
fn validate_inspection(
    manifest: &RootfsManifest,
    inspection: &RootfsInspection,
    inventory: &RootfsInspectionInventory,
) -> Result<()> {
    let boot = &manifest.intent.boot;
    let request = RootfsInspectionRequest {
        generation: manifest.intent.inspection_generation,
        disk: content(&manifest.disk),
        agent: content(&boot.agent),
        init: content(&boot.init),
        guest: RootfsGuestConfig {
            control_port: boot.control_port,
            pids: boot.workload_pids,
        },
    };
    inspection.validate_for(&request, inventory)?;
    if inspector_fingerprint(inventory)? != manifest.intent.inspector_inventory_sha256
        || inspection.guest_config.content != content(&boot.guest_config)
    {
        return Err(invalid("rootfs inspected guest configuration bytes differ").into());
    }
    Ok(())
}
fn validate_resumed(
    intent: &RootfsCaptureIntent,
    frozen: Option<&GuestRootfsBarrierInfo>,
    receipt: &GuestRootfsBarrierInfo,
) -> Result<()> {
    receipt
        .validate(intent.source.source_generation, intent.barrier)
        .map_err(invalid)?;
    if receipt.phase != GuestBarrierPhase::Resumed
        || frozen.is_some_and(|f| {
            f.root != receipt.root
                || receipt.filesystem != crate::control::GuestFilesystemState::Thawed
        })
    {
        return Err(invalid("rootfs original filesystem/workload recovery is unconfirmed").into());
    }
    Ok(())
}
impl Record {
    fn validate(&self, root: &Directory) -> Result<()> {
        self.intent.validate().map_err(invalid)?;
        self.producer.validate()?;
        self.source_writer.validate()?;
        if self.format != 2
            || self.store != root.store()
            || self.intent.source.installation != root.installation()
            || self.source_writer.process.executable_sha256 != self.intent.boot.firecracker_sha256
            || self.source_disk.bytes != self.intent.disk_bytes
            || self.source_disk.uid != self.source_writer.process.uid
            || self.vm_control.pause_observed && !self.vm_control.pause_dispatched
            || self.vm_control.resume_started
                && (!self.vm_control.pause_observed
                    || matches!(self.phase, Phase::Reserved | Phase::Capturing))
            || self
                .error
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 2048)
        {
            return Err(invalid("rootfs record ownership differs").into());
        }
        if let Some(frozen) = &self.frozen {
            frozen
                .validate(self.intent.source.source_generation, self.intent.barrier)
                .map_err(invalid)?;
            if frozen.phase != GuestBarrierPhase::Quiesced {
                return Err(invalid("rootfs capture receipt is not frozen").into());
            }
        }
        if let Some(receipt) = &self.resumed {
            validate_resumed(&self.intent, self.frozen.as_ref(), receipt)?;
        }
        match (&self.manifest, &self.disk) {
            (Some(manifest), Some(disk)) => {
                manifest.validate(self.intent.disk_bytes).map_err(invalid)?;
                if manifest.intent != self.intent || self.frozen.as_ref() != Some(&manifest.barrier)
                {
                    return Err(invalid("rootfs record manifest intent differs").into());
                }
                root.validate_receipt(disk, manifest)?;
            }
            (None, None) => {}
            _ => {
                return Err(
                    invalid("rootfs manifest and disk receipt acknowledgement differs").into(),
                );
            }
        }
        match (&self.inspection, &self.inventory, &self.manifest) {
            (Some(inspection), Some(inventory), Some(manifest)) => {
                validate_inspection(manifest, inspection, inventory)?
            }
            (None, None, _) => {}
            _ => return Err(invalid("rootfs inspection acknowledgement differs").into()),
        }
        if matches!(
            self.phase,
            Phase::Publishing | Phase::Captured | Phase::Ready
        ) && self.manifest.is_none()
            || self.phase == Phase::Ready
                && (self.resumed.is_none()
                    || self.inspection.is_none()
                    || !self.producer_settled
                    || self.error.is_some())
            || self.phase == Phase::Reserved && (self.frozen.is_some() || self.manifest.is_some())
            || self.phase == Phase::Collected && !self.producer_settled
        {
            return Err(invalid("rootfs phase acknowledgements differ").into());
        }
        Ok(())
    }
    fn reserved_bytes(&self) -> u64 {
        if self.phase == Phase::Collected {
            0
        } else {
            self.intent.disk_bytes
        }
    }
}

pub struct RootfsStore {
    root: Directory,
    policy: RootfsStorePolicy,
}
pub struct RootfsCaptureSession {
    root: Directory,
    record: Record,
    _mutex: File,
}
/// Retain this entire lease until independent materialization has completed.
/// A raw descriptor is not a durable template or runtime reference.
pub struct RootfsReadLease {
    pub manifest: RootfsManifest,
    file: File,
    _mutex: File,
}
impl RootfsReadLease {
    pub fn file(&self) -> &File {
        &self.file
    }
}

impl RootfsStore {
    pub fn open_or_initialize(
        path: &Path,
        installation: Uuid,
        policy: RootfsStorePolicy,
    ) -> Result<Self> {
        policy.validate()?;
        let root = match std::fs::symlink_metadata(path) {
            Ok(_) => Directory::open(path, installation)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Directory::initialize(path, installation)?
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self { root, policy })
    }
    pub fn reserve(
        &self,
        intent: RootfsCaptureIntent,
        source_vmm_pid: u32,
        source_disk: &File,
        source_uid: u32,
    ) -> Result<RootfsCaptureSession> {
        intent.validate().map_err(invalid)?;
        if intent.source.installation != self.root.installation() {
            return Err(invalid("rootfs capture belongs to another installation").into());
        }
        self.root.current()?;
        let _quota = self.root.quota(true)?;
        self.root.recover_capture(intent.source.capture)?;
        let name = record_name(intent.source.capture);
        if self.root.exists(&name)? {
            return Err(
                invalid("rootfs capture already exists; resume its original intent").into(),
            );
        }
        let records = self.root.records()?;
        let active: Vec<_> = records
            .iter()
            .filter(|r| r.phase != Phase::Collected)
            .collect();
        let bytes = active.iter().try_fold(intent.disk_bytes, |n, r| {
            n.checked_add(r.reserved_bytes())
                .ok_or_else(|| invalid("rootfs store reservation overflows"))
        })?;
        if active.len() >= self.policy.max_captures as usize || bytes > self.policy.max_bytes {
            return Err(goldenhoop_protocol::ApiError::new(
                goldenhoop_protocol::ErrorCode::QuotaExceeded,
                "rootfs store reservation is exhausted",
            )
            .into());
        }
        let source_writer = Actor::observe(source_vmm_pid)?;
        if source_writer.process.executable_sha256 != intent.boot.firecracker_sha256 {
            return Err(invalid("rootfs source VMM executable differs").into());
        }
        source_stamp(source_disk, source_uid, intent.disk_bytes)?;
        if source_writer.process.uid != source_uid {
            return Err(invalid("rootfs source disk differs from the original VMM UID").into());
        }
        let source_disk = SourceDisk {
            identity: Identity::of(source_disk)?,
            uid: source_uid,
            bytes: intent.disk_bytes,
        };
        let (mutex, identity) = self.root.job(&intent, None, true)?;
        let record = Record {
            format: 2,
            store: self.root.store(),
            intent,
            source_writer,
            source_disk,
            vm_control: RootfsVmControl::default(),
            producer: Actor::current()?,
            producer_settled: false,
            mutex: identity,
            phase: Phase::Reserved,
            frozen: None,
            resumed: None,
            manifest: None,
            disk: None,
            inspection: None,
            inventory: None,
            error: None,
        };
        record.validate(&self.root)?;
        metadata::initial_json(&self.root.path.join(name), &record)?;
        Ok(RootfsCaptureSession {
            root: self.root.duplicate()?,
            record,
            _mutex: mutex,
        })
    }
    pub fn resume(&self, intent: &RootfsCaptureIntent) -> Result<RootfsCaptureSession> {
        self.root.current()?;
        self.root.recover_capture(intent.source.capture)?;
        let mut record = self.root.record(intent.source.capture)?;
        record.validate(&self.root)?;
        if &record.intent != intent {
            return Err(invalid("rootfs exact recovery intent differs").into());
        }
        let (mutex, _) = self.root.job(intent, Some(&record.mutex), true)?;
        // Re-read after acquiring the original mutex, never replace it by name.
        record = self.root.record(intent.source.capture)?;
        record.validate(&self.root)?;
        if &record.intent != intent
            || matches!(
                record.phase,
                Phase::Ready | Phase::Collecting | Phase::Collected
            )
        {
            return Err(invalid("rootfs capture is closed for production").into());
        }
        let current = Actor::current()?;
        if record.producer != current && !record.producer_settled {
            record.producer.absent()?;
        }
        record.producer = current;
        record.producer_settled = false;
        metadata::atomic_json(
            &self.root.path.join(record_name(intent.source.capture)),
            &record,
        )?;
        let mut session = RootfsCaptureSession {
            root: self.root.duplicate()?,
            record,
            _mutex: mutex,
        };
        if session.record.phase == Phase::Publishing
            && let Some(receipt) = &session.record.disk
        {
            if session.root.owned(receipt)?.is_some() {
                session.root.verified(receipt)?;
                let mut next = session.record.clone();
                next.phase = Phase::Captured;
                session.save(next)?;
            } else {
                session.fail("original unnamed disk was lost before durable publication")?;
            }
        }
        Ok(session)
    }
    pub fn inspect(&self, id: Uuid) -> Result<serde_json::Value> {
        self.root.current()?;
        self.root.recover_capture(id)?;
        let record = self.root.record(id)?;
        record.validate(&self.root)?;
        Ok(
            serde_json::json!({"capture":id,"phase":record.phase,"reserved_bytes":record.reserved_bytes(),
            "source_resumed":record.resumed.is_some(),"inspection_verified":record.inspection.is_some(),
            "producer_settled":record.producer_settled,"reference":record.manifest.as_ref().map(RootfsManifest::reference).transpose().map_err(invalid)?,"error":record.error}),
        )
    }
    pub fn intent(&self, id: Uuid) -> Result<Option<RootfsCaptureIntent>> {
        self.root.current()?;
        self.root.recover_capture(id)?;
        if !self.root.exists(&record_name(id))? {
            return Ok(None);
        }
        Ok(Some(self.root.record(id)?.intent))
    }
    pub fn source_recovered(&self, id: Uuid) -> Result<bool> {
        self.root.current()?;
        self.root.recover_capture(id)?;
        Ok(self.root.record(id)?.resumed.is_some())
    }
    pub fn reserved_bytes(&self) -> Result<u64> {
        self.root.current()?;
        let _quota = self.root.quota(false)?;
        self.root.records()?.iter().try_fold(0u64, |n, r| {
            n.checked_add(r.reserved_bytes())
                .ok_or_else(|| invalid("rootfs reservation overflows").into())
        })
    }
    pub fn read(
        &self,
        reference: &RootfsReference,
        expected_boot: &RootfsBoot,
    ) -> Result<RootfsReadLease> {
        self.root.current()?;
        self.root.recover_capture(reference.capture)?;
        let before = self.root.record(reference.capture)?;
        before.validate(&self.root)?;
        let (mutex, _) = self.root.job(&before.intent, Some(&before.mutex), false)?;
        let record = self.root.record(reference.capture)?;
        record.validate(&self.root)?;
        if record.phase != Phase::Ready {
            return Err(invalid("rootfs content is not Ready").into());
        }
        let manifest = record
            .manifest
            .ok_or_else(|| invalid("rootfs Ready manifest absent"))?;
        manifest
            .admit(reference, expected_boot, manifest.intent.disk_bytes)
            .map_err(invalid)?;
        let file = self.root.verified(
            record
                .disk
                .as_ref()
                .ok_or_else(|| invalid("rootfs Ready disk absent"))?,
        )?;
        Ok(RootfsReadLease {
            manifest,
            file,
            _mutex: mutex,
        })
    }
    pub fn collect(&self, id: Uuid) -> Result<serde_json::Value> {
        self.root.current()?;
        let _quota = self.root.quota(true)?;
        self.root.recover_capture(id)?;
        let before = self.root.record(id)?;
        before.validate(&self.root)?;
        let (_mutex, _) = self.root.job(&before.intent, Some(&before.mutex), true)?;
        let mut record = self.root.record(id)?;
        record.validate(&self.root)?;
        if !record.producer_settled {
            record.producer.absent()?;
        }
        if record.resumed.is_none() {
            record.source_writer.absent()?;
        }
        if record.phase != Phase::Collected {
            record.phase = Phase::Collecting;
            metadata::atomic_json(&self.root.path.join(record_name(id)), &record)?;
            self.root.collect(id, record.disk.as_ref())?;
            record.phase = Phase::Collected;
            record.producer_settled = true;
            record.validate(&self.root)?;
            metadata::atomic_json(&self.root.path.join(record_name(id)), &record)?;
        } else {
            self.root.collect(id, record.disk.as_ref())?;
        }
        Ok(
            serde_json::json!({"capture":id,"phase":"collected","disk_absent":true,"reserved_bytes":0,
            "scope":"Only independent rootfs content; no claim of original VM/jail/cgroup collection"}),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceDisk {
    identity: Identity,
    uid: u32,
    bytes: u64,
}

#[derive(PartialEq, Eq)]
struct SourceStamp {
    device: u64,
    inode: u64,
    size: u64,
    uid: u32,
    mode: u32,
    links: u64,
    changed: (i64, i64),
    modified: (i64, i64),
}
fn source_stamp(file: &File, uid: u32, size: u64) -> Result<SourceStamp> {
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != uid || m.mode() & 0o6022 != 0 || m.nlink() != 1 || m.len() != size
    {
        return Err(invalid("rootfs source descriptor ownership, type or length differs").into());
    }
    Ok(SourceStamp {
        device: m.dev(),
        inode: m.ino(),
        size: m.len(),
        uid: m.uid(),
        mode: m.mode(),
        links: m.nlink(),
        changed: (m.ctime(), m.ctime_nsec()),
        modified: (m.mtime(), m.mtime_nsec()),
    })
}
impl RootfsCaptureSession {
    pub fn intent(&self) -> &RootfsCaptureIntent {
        &self.record.intent
    }
    pub fn manifest(&self) -> Option<&RootfsManifest> {
        self.record.manifest.as_ref()
    }
    pub fn source_resumed(&self) -> bool {
        self.record.resumed.is_some()
    }
    pub fn source_receipt(&self) -> Option<&GuestRootfsBarrierInfo> {
        self.record.resumed.as_ref()
    }
    pub fn vm_control(&self) -> &RootfsVmControl {
        &self.record.vm_control
    }
    pub fn pause_dispatched(&mut self) -> Result<()> {
        if self.record.phase != Phase::Capturing
            || self.record.vm_control.pause_dispatched
            || self.record.vm_control.resume_started
        {
            return Err(invalid("rootfs VMM pause is not a fresh original dispatch").into());
        }
        let mut next = self.record.clone();
        next.vm_control.pause_dispatched = true;
        self.save(next)
    }
    pub fn pause_observed(&mut self) -> Result<()> {
        if !self.record.vm_control.pause_dispatched || self.record.vm_control.resume_started {
            return Err(invalid("rootfs original VMM pause cannot be acknowledged").into());
        }
        let mut next = self.record.clone();
        next.vm_control.pause_observed = true;
        self.save(next)
    }
    pub fn resume_started(&mut self) -> Result<()> {
        if !matches!(self.record.phase, Phase::Captured | Phase::Failed)
            || !self.record.vm_control.pause_observed
            || self.record.vm_control.resume_started
        {
            return Err(invalid("rootfs VMM resume is not a fresh closed-capture dispatch").into());
        }
        let mut next = self.record.clone();
        next.vm_control.resume_started = true;
        self.save(next)
    }
    pub fn settle(&mut self) -> Result<()> {
        if !matches!(self.record.phase, Phase::Captured | Phase::Failed) {
            return Err(invalid("rootfs independent I/O is not at a settled boundary").into());
        }
        let mut next = self.record.clone();
        next.producer_settled = true;
        self.save(next)
    }
    pub fn validate_source(&self, file: &File, uid: u32) -> Result<()> {
        source_stamp(file, uid, self.record.intent.disk_bytes)?;
        if uid != self.record.source_disk.uid
            || Identity::of(file)? != self.record.source_disk.identity
        {
            return Err(
                invalid("rootfs source descriptor is not the originally reserved disk").into(),
            );
        }
        Ok(())
    }
    fn save(&mut self, next: Record) -> Result<()> {
        self.root.current()?;
        if self.record.producer != Actor::current()?
            || next.producer != self.record.producer
            || next.intent != self.record.intent
            || next.mutex != self.record.mutex
        {
            return Err(invalid("rootfs session producer or immutable intent differs").into());
        }
        let current = self.root.record(self.record.intent.source.capture)?;
        if serde_json::to_vec(&current)? != serde_json::to_vec(&self.record)? {
            return Err(invalid("rootfs capture record changed").into());
        }
        next.validate(&self.root)?;
        metadata::atomic_json(
            &self.root.path.join(record_name(next.intent.source.capture)),
            &next,
        )?;
        self.record = next;
        Ok(())
    }
    pub fn begin(&mut self) -> Result<()> {
        if self.record.phase != Phase::Reserved {
            return Err(invalid("rootfs capture has already started").into());
        }
        self.record.source_writer.present()?;
        let mut next = self.record.clone();
        next.phase = Phase::Capturing;
        self.save(next)
    }
    /// The owning coordinator must retain its original VM lease and positive
    /// VMM pause through this synchronous copy. Dropping a caller is no thaw.
    pub fn capture(
        &mut self,
        source: File,
        source_uid: u32,
        frozen: GuestRootfsBarrierInfo,
    ) -> Result<RootfsReference> {
        self.capture_observed(source, source_uid, frozen, |_| {})
    }
    fn capture_observed(
        &mut self,
        mut source: File,
        source_uid: u32,
        frozen: GuestRootfsBarrierInfo,
        mut observe: impl FnMut(&str),
    ) -> Result<RootfsReference> {
        if self.record.phase != Phase::Capturing
            || self.record.resumed.is_some()
            || self.record.manifest.is_some()
        {
            return Err(invalid("rootfs capture is not at its original copy boundary").into());
        }
        frozen
            .validate(
                self.record.intent.source.source_generation,
                self.record.intent.barrier,
            )
            .map_err(invalid)?;
        if frozen.phase != GuestBarrierPhase::Quiesced
            || self
                .record
                .frozen
                .as_ref()
                .is_some_and(|old| old != &frozen)
        {
            return Err(invalid("rootfs source freeze acknowledgement differs").into());
        }
        self.record.source_writer.present()?;
        self.validate_source(&source, source_uid)?;
        let mut next = self.record.clone();
        next.frozen = Some(frozen.clone());
        self.save(next)?;
        let bytes = self.record.intent.disk_bytes;
        let stamp = source_stamp(&source, source_uid, bytes)?;
        source.rewind()?;
        let (sha256, size_bytes) = crate::fileio::digest_exact(source.try_clone()?, bytes)?;
        let manifest = RootfsManifest {
            format: 1,
            filesystem: RootfsFilesystem::Ext4,
            intent: self.record.intent.clone(),
            barrier: frozen,
            disk: RootfsArtifact { sha256, size_bytes },
        };
        manifest.validate(bytes).map_err(invalid)?;
        let output = crate::fileio::copy_to(
            source.try_clone()?,
            self.root.anonymous()?,
            &manifest.disk.sha256,
            bytes,
        )?;
        if source_stamp(&source, source_uid, bytes)? != stamp {
            return Err(invalid("rootfs source changed during independent materialization").into());
        }
        self.record.source_writer.present()?;
        let (file, receipt) = self.root.seal(output, &manifest)?;
        let mut next = self.record.clone();
        next.phase = Phase::Publishing;
        next.manifest = Some(manifest);
        next.disk = Some(receipt.clone());
        // The complete inode/content receipt is durable before the first link.
        self.save(next)?;
        observe("publishing_record_persisted");
        self.root.publish(&file, &receipt)?;
        observe("disk_link_persisted");
        self.root.verified(&receipt)?;
        let mut next = self.record.clone();
        next.phase = Phase::Captured;
        self.save(next)?;
        observe("captured_record_persisted");
        self.record
            .manifest
            .as_ref()
            .ok_or_else(|| invalid("rootfs manifest absent"))?
            .reference()
            .map_err(|e| invalid(e).into())
    }
    pub fn confirm_source_resumed(&mut self, receipt: GuestRootfsBarrierInfo) -> Result<()> {
        if matches!(
            self.record.phase,
            Phase::Reserved
                | Phase::Publishing
                | Phase::Ready
                | Phase::Collecting
                | Phase::Collected
        ) {
            return Err(
                invalid("rootfs source recovery is not at an acknowledged boundary").into(),
            );
        }
        self.record.source_writer.present()?;
        validate_resumed(&self.record.intent, self.record.frozen.as_ref(), &receipt)?;
        if self
            .record
            .resumed
            .as_ref()
            .is_some_and(|old| old != &receipt)
        {
            return Err(invalid("rootfs source recovery receipt changed").into());
        }
        let mut next = self.record.clone();
        next.resumed = Some(receipt);
        self.ready_or_save(next)
    }
    fn confirm_inspection(
        &mut self,
        inspection: RootfsInspection,
        inventory: RootfsInspectionInventory,
    ) -> Result<()> {
        if self.record.phase != Phase::Captured {
            return Err(invalid("rootfs disk is not captured for inspection").into());
        }
        let manifest = self
            .record
            .manifest
            .as_ref()
            .ok_or_else(|| invalid("rootfs inspection manifest absent"))?;
        validate_inspection(manifest, &inspection, &inventory)?;
        self.root.verified(
            self.record
                .disk
                .as_ref()
                .ok_or_else(|| invalid("rootfs inspection disk absent"))?,
        )?;
        let mut next = self.record.clone();
        next.inspection = Some(inspection);
        next.inventory = Some(inventory);
        self.ready_or_save(next)
    }
    /// The coordinator retains this session and its mutex until the isolated
    /// inspector and its original host process/cgroup have been collected.
    pub fn inspection_input(&self) -> Result<File> {
        if self.record.phase != Phase::Captured {
            return Err(invalid("rootfs disk is not captured for inspection").into());
        }
        self.root.verified(
            self.record
                .disk
                .as_ref()
                .ok_or_else(|| invalid("rootfs captured disk absent"))?,
        )
    }
    pub fn confirm_inspection_report(
        &mut self,
        report: RootfsInspectionReport,
        inventory: RootfsInspectionInventory,
    ) -> Result<()> {
        if !report.passed
            || !report.staging_absent
            || !report.tools_collected
            || report.error.is_some()
        {
            return Err(
                invalid("rootfs isolated inspection or tool collection is unconfirmed").into(),
            );
        }
        self.confirm_inspection(
            report
                .inspection
                .ok_or_else(|| invalid("rootfs isolated inspection result absent"))?,
            inventory,
        )
    }
    fn ready_or_save(&mut self, mut next: Record) -> Result<()> {
        if next.phase == Phase::Captured && next.resumed.is_some() && next.inspection.is_some() {
            next.phase = Phase::Ready;
            next.producer_settled = true;
        }
        if next.phase == Phase::Failed {
            next.producer_settled = true;
        }
        self.save(next)
    }
    /// Explicit failure records no source recovery and performs no object GC.
    pub fn fail(&mut self, error: &str) -> Result<()> {
        if error.is_empty()
            || matches!(
                self.record.phase,
                Phase::Ready | Phase::Collecting | Phase::Collected
            )
        {
            return Err(invalid("rootfs failure transition differs").into());
        }
        let mut next = self.record.clone();
        next.phase = Phase::Failed;
        next.producer_settled = true;
        next.error = Some(
            error
                .chars()
                .scan(0usize, |bytes, c| {
                    *bytes += c.len_utf8();
                    (*bytes <= 2048).then_some(c)
                })
                .collect(),
        );
        self.save(next)
    }
}

#[cfg(test)]
mod tests;
