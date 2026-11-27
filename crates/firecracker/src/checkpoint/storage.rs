//! Local persistent capture objects. Ready readers never require a live producer.
//! Mutation/recovery separately fences both the original producer and VMM writer.
use super::*;
use crate::lifecycle::{self, ProcessIdentity, Result, invalid, metadata};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
mod files;
pub(crate) use files::SourceDirectory;
use files::{Identity, ObjectReceipt, Root, record_name};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointStorePolicy {
    pub max_bytes: u64,
    pub max_checkpoints: u32,
}
impl CheckpointStorePolicy {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.max_bytes == 0
            || self.max_bytes > 1024 * 1024 * MIB
            || !(1..=128).contains(&self.max_checkpoints)
        {
            return Err(invalid("invalid checkpoint store policy").into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointProbeConfig {
    pub root: PathBuf,
    pub installation: Uuid,
    pub capture: Uuid,
    pub policy: CheckpointStorePolicy,
}
impl CheckpointProbeConfig {
    pub fn read(path: &Path) -> Result<Self> {
        let file = crate::machine::trusted_file(path)?;
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(invalid("checkpoint configuration exceeds bound").into());
        }
        let value: Self = serde_json::from_slice(&bytes)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        self.policy.validate()?;
        if self.installation.is_nil() || self.capture.is_nil() || !self.root.is_absolute() {
            return Err(invalid("invalid checkpoint configuration identity/path").into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    boot: String,
    namespace_device: u64,
    namespace_inode: u64,
}
impl Context {
    fn current() -> Result<Self> {
        let ns = std::fs::metadata("/proc/self/ns/pid")?;
        Ok(Self {
            boot: lifecycle::boot_id()?,
            namespace_device: ns.dev(),
            namespace_inode: ns.ino(),
        })
    }
    fn validate(&self) -> Result<()> {
        let boot = Uuid::parse_str(&self.boot)?;
        if boot.is_nil() || boot.to_string() != self.boot || self.namespace_inode == 0 {
            return Err(invalid("checkpoint observer context invalid").into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Writer {
    context: Context,
    process: ProcessIdentity,
}
impl Writer {
    pub(crate) fn observe(pid: u32) -> Result<Self> {
        let value = Self {
            context: Context::current()?,
            process: lifecycle::process_identity(pid)?,
        };
        value.validate()?;
        Ok(value)
    }
    fn current() -> Result<Self> {
        Self::observe(std::process::id())
    }
    fn validate(&self) -> Result<()> {
        self.context.validate()?;
        if self.process.pid <= 1
            || self.process.pid > i32::MAX as u32
            || self.process.start_ticks == 0
            || self.process.boot_id != self.context.boot
            || !valid_sha(&self.process.executable_sha256)
        {
            return Err(invalid("checkpoint writer identity invalid").into());
        }
        Ok(())
    }
    fn require_absent(&self) -> Result<()> {
        self.validate()?;
        // A changed boot on an arbitrary other host/namespace is not death proof.
        if self.context != Context::current()? {
            return Err(invalid("checkpoint writer context changed; absence unconfirmed").into());
        }
        if !lifecycle::reaper::process_absent(&self.process)? {
            return Err(invalid("checkpoint original writer is still present").into());
        }
        Ok(())
    }
    fn require_present(&self) -> Result<()> {
        self.validate()?;
        if self.context != Context::current()?
            || lifecycle::process_identity(self.process.pid)? != self.process
        {
            return Err(
                invalid("checkpoint source writer is not the exact current identity").into(),
            );
        }
        Ok(())
    }
}

pub(crate) fn host_compatibility() -> Result<String> {
    let context = Context::current()?;
    context.validate()?;
    let cpu = std::fs::read_to_string("/proc/cpuinfo")?;
    let mut stable = std::collections::BTreeSet::new();
    for line in cpu.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            if [
                "vendor_id",
                "cpu family",
                "model",
                "stepping",
                "microcode",
                "flags",
                "bugs",
                "clflush size",
                "cache_alignment",
                "address sizes",
            ]
            .contains(&key)
            {
                stable.insert(format!(
                    "{key}:{}",
                    value.split_whitespace().collect::<Vec<_>>().join(" ")
                ));
            }
        }
    }
    if !stable.iter().any(|s| s.starts_with("vendor_id:"))
        || !stable.iter().any(|s| s.starts_with("flags:"))
    {
        return Err(invalid("checkpoint CPU compatibility observation unavailable").into());
    }
    let mut hash = Sha256::new();
    hash.update(b"goldenhoop.checkpoint.host-context.v1\0");
    hash.update(serde_json::to_vec(&(context, stable))?);
    Ok(format!("{:x}", hash.finalize()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub source: CaptureIdentity,
    pub runtime: CheckpointRuntime,
    pub resources: ResourceLimits,
    pub barrier: Uuid,
    pub disk_bytes: u64,
    pub writer: Writer,
    pub source_directory: SourceDirectory,
}
impl Intent {
    fn validate(&self) -> Result<u64> {
        let s = &self.source;
        let r = &self.runtime;
        if [
            s.installation,
            s.sandbox,
            s.source_generation,
            s.capture,
            self.barrier,
        ]
        .iter()
        .any(Uuid::is_nil)
            || !valid_sha(&s.request_sha256)
            || r.firecracker_version != "1.18.0"
            || r.architecture != "x86_64"
            || [
                &r.firecracker_sha256,
                &r.jailer_sha256,
                &r.kernel_sha256,
                &r.host_compatibility_sha256,
            ]
            .iter()
            .any(|s| !valid_sha(s))
            || self.resources.cpu_millis == 0
            || self.resources.cpu_millis > 8000
            || !(128 * MIB..=MAX_MEMORY_BYTES).contains(&self.resources.memory_bytes)
            || !self.resources.memory_bytes.is_multiple_of(MIB)
            || !(16..=65535).contains(&self.resources.pids)
            || !(64 * MIB..=MAX_DISK_BYTES).contains(&self.disk_bytes)
            || !self.disk_bytes.is_multiple_of(4096)
        {
            return Err(invalid("checkpoint capture intent is invalid").into());
        }
        self.writer.validate()?;
        if self.writer.process.executable_sha256 != r.firecracker_sha256 {
            return Err(invalid("checkpoint source writer executable differs").into());
        }
        self.resources
            .memory_bytes
            .checked_add(MAX_CHECKPOINT_STATE_BYTES)
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(self.disk_bytes))
            .ok_or_else(|| invalid("checkpoint reservation overflows").into())
    }
    fn digest(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Reserved,
    Capturing,
    Publishing,
    Ready,
    Failed,
    Collecting,
    Collected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Pending,
    Ready,
    Failed,
    Unconfirmed,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    format: u16,
    store: Uuid,
    intent: Intent,
    mutex: Identity,
    producer: Writer,
    #[serde(default)]
    producer_settled: bool,
    phase: Phase,
    outcome: Outcome,
    reserved_bytes: u64,
    manifest: Option<CheckpointManifest>,
    reference: Option<CheckpointReference>,
    objects: Vec<ObjectReceipt>,
    error: Option<String>,
}
impl Record {
    fn validate(&self, root: &Root) -> Result<()> {
        self.producer.validate()?;
        self.intent
            .source_directory
            .validate(self.intent.source.source_generation, &root.path)?;
        if self.format != 1
            || self.store != root.nonce()
            || self.intent.source.installation != root.installation()
            || self.reserved_bytes != self.intent.validate()?
            || self.error.as_ref().is_some_and(|s| s.len() > 2048)
            || self.producer.context != self.intent.writer.context
            || self.producer.process.uid != 0
            || self.producer_settled && !matches!(self.outcome, Outcome::Ready | Outcome::Failed)
        {
            return Err(invalid("checkpoint durable record binding differs").into());
        }
        match (&self.manifest, &self.reference) {
            (Some(m), Some(r)) => {
                m.admit(r, &self.intent.runtime, self.reserved_bytes)
                    .map_err(invalid)?;
                if m.source != self.intent.source
                    || m.resources != self.intent.resources
                    || m.barrier.barrier != self.intent.barrier
                    || m.disk.size_bytes != self.intent.disk_bytes
                {
                    return Err(invalid("checkpoint manifest differs from capture intent").into());
                }
                root.validate_receipts(m, &self.objects)?;
            }
            (None, None) if self.objects.is_empty() => (),
            _ => return Err(invalid("partial checkpoint record content declaration").into()),
        }
        if matches!(self.phase, Phase::Publishing | Phase::Ready) && self.manifest.is_none()
            || self.phase == Phase::Ready
                && (self.outcome != Outcome::Ready || self.error.is_some())
            || self.outcome == Outcome::Ready && self.manifest.is_none()
            || matches!(self.phase, Phase::Reserved | Phase::Capturing) && self.manifest.is_some()
        {
            return Err(invalid("checkpoint phase/outcome declaration differs").into());
        }
        Ok(())
    }
}

pub(crate) struct CheckpointStore {
    root: Root,
    policy: CheckpointStorePolicy,
}
pub(crate) struct CaptureSession {
    store: CheckpointStore,
    _mutex: File,
    record: Record,
}
impl CheckpointStore {
    pub(crate) fn open_or_initialize(cfg: &CheckpointProbeConfig) -> Result<Self> {
        cfg.validate()?;
        let root = match std::fs::symlink_metadata(&cfg.root) {
            Ok(_) => Root::open(&cfg.root, cfg.installation)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                Root::initialize(&cfg.root, cfg.installation)?
            }
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            root,
            policy: cfg.policy.clone(),
        })
    }
    fn open(cfg: &CheckpointProbeConfig) -> Result<Self> {
        cfg.validate()?;
        Ok(Self {
            root: Root::open(&cfg.root, cfg.installation)?,
            policy: cfg.policy.clone(),
        })
    }
    pub(crate) fn reserve(&self, intent: Intent) -> Result<CaptureSession> {
        if intent.source.installation != self.root.installation() {
            return Err(invalid("foreign checkpoint installation").into());
        }
        intent
            .source_directory
            .validate(intent.source.source_generation, &self.root.path)?;
        intent.writer.require_present()?;
        intent.source_directory.require_present()?;
        let reserved = intent.validate()?;
        let _quota = self.root.quota(true)?;
        self.root.recover()?;
        let records = self.root.records()?;
        if records.iter().any(|r| {
            r.intent.source.capture == intent.source.capture
                || r.intent.source.source_generation == intent.source.source_generation
                || r.intent.writer.process == intent.writer.process
        }) {
            return Err(invalid(
                "checkpoint capture already has an immutable intent; inspect the original",
            )
            .into());
        }
        let mut bytes = reserved;
        let mut count = 1u32;
        for r in records.iter().filter(|r| r.phase != Phase::Collected) {
            bytes = bytes
                .checked_add(r.reserved_bytes)
                .ok_or_else(|| invalid("checkpoint quota overflows"))?;
            count = count
                .checked_add(1)
                .ok_or_else(|| invalid("checkpoint count overflows"))?;
        }
        if bytes > self.policy.max_bytes || count > self.policy.max_checkpoints {
            return Err(goldenhoop_protocol::ApiError::new(
                goldenhoop_protocol::ErrorCode::QuotaExceeded,
                "checkpoint capacity is reserved",
            )
            .into());
        }
        if records.len() >= 1024 {
            return Err(
                invalid("checkpoint history is full; no identifier history is evicted").into(),
            );
        }
        let id = intent.source.capture;
        let mutex = self.root.ensure_job_lock(id, &intent.digest()?)?;
        let lease = self.root.job_lock(id, &mutex, &intent.digest()?, true)?;
        let record = Record {
            format: 1,
            store: self.root.nonce(),
            intent,
            mutex,
            producer: Writer::current()?,
            producer_settled: false,
            phase: Phase::Reserved,
            outcome: Outcome::Pending,
            reserved_bytes: reserved,
            manifest: None,
            reference: None,
            objects: Vec::new(),
            error: None,
        };
        record.validate(&self.root)?;
        metadata::initial_json(&self.root.path.join(record_name(id)), &record)?;
        Ok(CaptureSession {
            store: Self {
                root: self.root.duplicate()?,
                policy: self.policy.clone(),
            },
            _mutex: lease,
            record,
        })
    }
    pub(crate) fn verify<T>(
        &self,
        reference: &CheckpointReference,
        inspect: impl FnOnce(&CheckpointManifest, &CheckpointFiles) -> Result<T>,
    ) -> Result<T> {
        let _quota = self.root.quota(false)?;
        let record: Record = self.root.json(&record_name(reference.capture))?;
        record.validate(&self.root)?;
        let _lease = self.root.job_lock(
            reference.capture,
            &record.mutex,
            &record.intent.digest()?,
            false,
        )?;
        drop(_quota);
        if record.phase != Phase::Ready || record.reference.as_ref() != Some(reference) {
            return Err(invalid("checkpoint is not the exact Ready reference").into());
        }
        let files = self.root.verify_objects(&record.objects)?;
        inspect(
            record
                .manifest
                .as_ref()
                .ok_or_else(|| invalid("checkpoint Ready manifest missing"))?,
            &files,
        )
    }
    pub(crate) fn inspect(&self, id: Uuid) -> Result<serde_json::Value> {
        let _quota = self.root.quota(false)?;
        let record: Record = self.root.json(&record_name(id))?;
        record.validate(&self.root)?;
        self.root
            .job_mutex(id, &record.mutex, &record.intent.digest()?, false)?;
        let verified = if record.phase == Phase::Ready {
            let _lease = self
                .root
                .job_lock(id, &record.mutex, &record.intent.digest()?, false)?;
            drop(_quota);
            self.root.verify_objects(&record.objects)?;
            true
        } else {
            false
        };
        Ok(
            serde_json::json!({"capture":id,"phase":record.phase,"capture_outcome":record.outcome,"error":record.error,
            "reserved_bytes":if record.phase==Phase::Collected {0}else{record.reserved_bytes},"reference":record.reference,"manifest":record.manifest,"content_verified":verified}),
        )
    }
    /// Immutable source identity can be read while its original producer owns
    /// the job lease. A pending status never claims verified content.
    pub(crate) fn source(&self, id: Uuid) -> Result<Option<CaptureIdentity>> {
        let _quota = self.root.quota(false)?;
        if let Some(record) = self
            .root
            .records()?
            .into_iter()
            .find(|r| r.intent.source.capture == id)
        {
            self.root
                .job_mutex(id, &record.mutex, &record.intent.digest()?, false)?;
            Ok(Some(record.intent.source))
        } else {
            Ok(None)
        }
    }
    pub(crate) fn reserved_bytes(&self) -> Result<u64> {
        let _quota = self.root.quota(false)?;
        self.root
            .records()?
            .iter()
            .filter(|r| r.phase != Phase::Collected)
            .try_fold(0u64, |n, r| {
                n.checked_add(r.reserved_bytes)
                    .ok_or_else(|| invalid("checkpoint reservation overflow").into())
            })
    }
    pub(crate) fn collect(&self, id: Uuid) -> Result<serde_json::Value> {
        let _quota = self.root.quota(true)?;
        self.root.recover_capture(id)?;
        let mut record: Record = self.root.json(&record_name(id))?;
        record.validate(&self.root)?;
        let _lease = self
            .root
            .job_lock(id, &record.mutex, &record.intent.digest()?, true)?;
        if record.phase != Phase::Collected {
            // Only an acknowledged settled producer may remain alive. An
            // interrupted capture still requires its original process absent.
            if record.outcome != Outcome::Ready && !record.producer_settled {
                record.producer.require_absent()?;
            }
            // Raw state/memory outputs belong to the source jail, which remains
            // charged until the exact original VMM writer is positively absent.
            record.intent.writer.require_absent()?;
            record.intent.source_directory.require_absent()?;
            if record.outcome == Outcome::Pending {
                record.outcome = Outcome::Unconfirmed;
            }
            record.phase = Phase::Collecting;
            record.validate(&self.root)?;
            metadata::atomic_json(&self.root.path.join(record_name(id)), &record)?;
            self.root.collect_objects(id, &record.objects)?;
            record.phase = Phase::Collected;
            metadata::atomic_json(&self.root.path.join(record_name(id)), &record)?;
        }
        // Repeated collection is observed, never inferred from a terminal word.
        self.root.collect_objects(id, &record.objects)?;
        Ok(
            serde_json::json!({"capture":id,"phase":record.phase,"capture_outcome":record.outcome,"error":record.error,"objects_absent":true,"reserved_bytes":0}),
        )
    }
}
impl CaptureSession {
    pub(crate) fn intent(&self) -> &Intent {
        &self.record.intent
    }
    pub(crate) fn reserved_bytes(&self) -> u64 {
        self.record.reserved_bytes
    }
    fn save(&mut self, next: Record) -> Result<()> {
        let _quota = self.store.root.quota(true)?;
        self.store.root.current()?;
        let actual: Record = self
            .store
            .root
            .json(&record_name(self.record.intent.source.capture))?;
        if serde_json::to_vec(&actual)? != serde_json::to_vec(&self.record)?
            || self.record.producer != Writer::current()?
        {
            return Err(invalid("checkpoint producer or record preimage differs").into());
        }
        next.validate(&self.store.root)?;
        metadata::atomic_json(
            &self
                .store
                .root
                .path
                .join(record_name(next.intent.source.capture)),
            &next,
        )?;
        self.record = next;
        Ok(())
    }
    pub(crate) fn begin(&mut self) -> Result<()> {
        if self.record.phase != Phase::Reserved {
            return Err(invalid("checkpoint capture cannot be replayed").into());
        }
        let mut next = self.record.clone();
        next.phase = Phase::Capturing;
        self.save(next)
    }
    pub(crate) fn fail(&mut self, error: &str) -> Result<()> {
        let mut next = self.record.clone();
        next.phase = Phase::Failed;
        next.outcome = Outcome::Failed;
        next.producer_settled = true;
        next.error = Some(error.chars().take(1024).collect());
        self.save(next)
    }
    pub(crate) fn publish(self, staged: StagedCheckpoint) -> Result<CheckpointReference> {
        self.publish_observed(staged, |_| {})
    }
    fn publish_observed(
        mut self,
        staged: StagedCheckpoint,
        observe: impl Fn(&str),
    ) -> Result<CheckpointReference> {
        let result = self.publish_inner(staged, observe);
        if let Err(error) = &result
            && let Err(record_error) = self.fail(&error.to_string())
        {
            return Err(invalid(format!(
                "{error}; publication failure metadata is unconfirmed: {record_error}"
            ))
            .into());
        }
        result
    }
    fn publish_inner(
        &mut self,
        staged: StagedCheckpoint,
        observe: impl Fn(&str),
    ) -> Result<CheckpointReference> {
        if self.record.phase != Phase::Capturing {
            return Err(invalid("checkpoint publication has no original capture").into());
        }
        let (manifest, files) = staged.into_parts();
        let reference = manifest.reference().map_err(invalid)?;
        let receipts = self.store.root.receipts(&manifest, &files)?;
        let mut next = self.record.clone();
        next.phase = Phase::Publishing;
        next.manifest = Some(manifest);
        next.reference = Some(reference.clone());
        next.objects = receipts;
        self.save(next)?;
        observe("objects_declared");
        for (index, file) in [&files.state, &files.memory, &files.disk]
            .into_iter()
            .enumerate()
        {
            self.store
                .root
                .publish_object(file, &self.record.objects[index])?;
            observe(&format!("object_linked_{index}"));
        }
        self.store.root.verify_objects(&self.record.objects)?;
        let mut next = self.record.clone();
        next.phase = Phase::Ready;
        next.outcome = Outcome::Ready;
        next.producer_settled = true;
        self.save(next)?;
        observe("ready_synced");
        Ok(reference)
    }
}
pub fn inspect_store(cfg: &CheckpointProbeConfig) -> Result<serde_json::Value> {
    CheckpointStore::open(cfg)?.inspect(cfg.capture)
}
pub fn collect_store(cfg: &CheckpointProbeConfig) -> Result<serde_json::Value> {
    CheckpointStore::open(cfg)?.collect(cfg.capture)
}

#[cfg(test)]
mod tests;
