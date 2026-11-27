//! A continuation claim is durable and single use, independently of content.
use super::*;
use crate::control::{
    GuestAuthorityInfo, GuestAuthorityTransfer, GuestBarrierInfo, GuestBarrierPhase,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreIntent {
    pub reference: CheckpointReference,
    pub runtime: CheckpointRuntime,
    pub restoration: Uuid,
    pub sandbox: Uuid,
    pub generation: Uuid,
    pub destination: Destination,
}
impl RestoreIntent {
    fn digest(&self) -> Result<String> {
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
    fn validate(&self, record: &Record, root: &Root) -> Result<()> {
        if self.restoration.is_nil()
            || self.sandbox.is_nil()
            || self.generation.is_nil()
            || self.generation == record.intent.source.source_generation
            || self.sandbox == record.intent.source.sandbox
            || record.reference.as_ref() != Some(&self.reference)
            || self.runtime != record.intent.runtime
        {
            return Err(invalid("restore identity, reference or runtime differs").into());
        }
        self.destination
            .validate(self.generation, &root.path, &record.intent.source_directory)
    }
    fn transfer(&self, record: &Record) -> GuestAuthorityTransfer {
        GuestAuthorityTransfer {
            source_generation: record.intent.source.source_generation,
            target_generation: self.generation,
            barrier: record.intent.barrier,
            restoration: self.restoration,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RestorePhase {
    Claimed,
    Allocated,
    Launching,
    Tracked,
    Transferred,
    Activated,
    Failed,
    Closed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RestoreOutcome {
    Pending,
    Activated,
    Failed,
    Unconfirmed,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Restoration {
    intent: RestoreIntent,
    producer: Writer,
    mutex: Identity,
    phase: RestorePhase,
    outcome: RestoreOutcome,
    producer_settled: bool,
    launch_intent: bool,
    directory: Option<SourceDirectory>,
    writer: Option<Writer>,
    error: Option<String>,
}
impl Restoration {
    pub(super) fn validate(&self, record: &Record, root: &Root) -> Result<()> {
        self.intent.validate(record, root)?;
        self.producer.validate()?;
        root.continuation_mutex(
            record.intent.source.capture,
            &self.mutex,
            &self.intent.digest()?,
        )?;
        if record.outcome != Outcome::Ready
            || self.producer.context != record.intent.writer.context
            || self.producer.process.uid != 0
            || self.error.as_ref().is_some_and(|s| s.len() > 2048)
            || self.producer_settled
                && !matches!(
                    self.outcome,
                    RestoreOutcome::Activated | RestoreOutcome::Failed
                )
            || self.launch_intent && self.directory.is_none()
            || self.writer.is_some() && !self.launch_intent
            || matches!(
                self.phase,
                RestorePhase::Tracked | RestorePhase::Transferred | RestorePhase::Activated
            ) && self.writer.is_none()
            || self.phase == RestorePhase::Activated && self.outcome != RestoreOutcome::Activated
            || self.phase == RestorePhase::Closed && self.outcome == RestoreOutcome::Pending
            || self.outcome == RestoreOutcome::Activated
                && (!self.producer_settled || self.error.is_some())
        {
            return Err(invalid("restore durable phase/producer binding differs").into());
        }
        if let Some(directory) = &self.directory {
            self.intent.destination.matches(directory)?;
            directory.validate(self.intent.generation, &root.path)?;
        }
        if let Some(writer) = &self.writer {
            writer.validate()?;
            if writer.context != self.producer.context
                || writer.process.executable_sha256 != self.intent.runtime.firecracker_sha256
                || writer.process.uid != record.intent.writer.process.uid
            {
                return Err(invalid("restore VMM writer identity differs").into());
            }
        }
        Ok(())
    }
    pub(super) fn active_bytes(&self, disk: u64) -> u64 {
        // Capture already reserves two RAM/state copies. A target additionally
        // needs its own mutable drive rather than the sole retained drive copy.
        if self.closed() { 0 } else { disk }
    }
    pub(super) fn closed(&self) -> bool {
        self.phase == RestorePhase::Closed
    }
    fn target_absent(&self) -> Result<()> {
        if let Some(writer) = &self.writer {
            writer.require_absent()?;
        } else if self.launch_intent {
            return Err(invalid(
                "restore launch lacks an acknowledged VMM writer; absence is unconfirmed",
            )
            .into());
        }
        self.intent.destination.require_absent()?;
        if let Some(directory) = &self.directory {
            directory.require_absent()?;
        }
        Ok(())
    }
}

pub(crate) enum RestoreAdmission {
    Existing(serde_json::Value),
    Granted(Box<RestoreSession>),
}
pub(crate) struct RestoreSession {
    store: CheckpointStore,
    _lease: File,
    _continuation_lease: File,
    record: Record,
}
impl CheckpointStore {
    pub(crate) fn claim_restore(&self, intent: RestoreIntent) -> Result<RestoreAdmission> {
        let id = intent.reference.capture;
        let quota = self.root.quota(true)?;
        self.root.recover_capture(id)?;
        let record: Record = self.root.json(&record_name(id))?;
        record.validate(&self.root)?;
        intent.validate(&record, &self.root)?;
        self.root
            .job_mutex(id, &record.mutex, &record.intent.digest()?, false)?;
        if let Some(original) = &record.restoration {
            if original.intent != intent {
                return Err(goldenhoop_protocol::ApiError::new(
                    goldenhoop_protocol::ErrorCode::Conflict,
                    "checkpoint continuation already has a different immutable target",
                )
                .into());
            }
            return Ok(RestoreAdmission::Existing(serde_json::to_value(original)?));
        }
        if record.phase != Phase::Ready {
            return Err(invalid("restore requires Ready content").into());
        }
        let lease = self
            .root
            .job_lock(id, &record.mutex, &record.intent.digest()?, true)?;
        drop(quota);
        self.root.verify_objects(&record.objects)?;
        let _quota = self.root.quota(true)?;
        self.root.current()?;
        let actual: Record = self.root.json(&record_name(id))?;
        if serde_json::to_vec(&actual)? != serde_json::to_vec(&record)? {
            return Err(invalid("restore capture preimage changed").into());
        }
        record.intent.writer.require_absent()?;
        record.intent.source_directory.require_absent()?;
        intent.destination.require_absent()?;
        let records = self.root.records()?;
        if records
            .iter()
            .filter_map(|r| r.restoration.as_ref())
            .any(|r| {
                r.intent.restoration == intent.restoration
                    || r.intent.generation == intent.generation
                    || r.intent.sandbox == intent.sandbox
            })
        {
            return Err(invalid("restore operation or target identifier already consumed").into());
        }
        let bytes = records
            .iter()
            .try_fold(record.intent.disk_bytes, |sum, r| -> Result<u64> {
                sum.checked_add(r.active_bytes()?)
                    .ok_or_else(|| invalid("restore quota overflows").into())
            })?;
        if bytes > self.policy.max_bytes {
            return Err(goldenhoop_protocol::ApiError::new(
                goldenhoop_protocol::ErrorCode::QuotaExceeded,
                "restore target disk capacity is reserved",
            )
            .into());
        }
        let (continuation_lease, mutex) = self.root.new_continuation(id, &intent.digest()?)?;
        let mut next = record;
        next.restoration = Some(Restoration {
            intent,
            producer: Writer::current()?,
            mutex,
            phase: RestorePhase::Claimed,
            outcome: RestoreOutcome::Pending,
            producer_settled: false,
            launch_intent: false,
            directory: None,
            writer: None,
            error: None,
        });
        next.validate(&self.root)?;
        metadata::atomic_json(&self.root.path.join(record_name(id)), &next)?;
        // Readers can continue verifying immutable content during target copies.
        // The global lease prevents GC while this EX-to-SH transition is made.
        fs2::FileExt::unlock(&lease)?;
        fs2::FileExt::try_lock_shared(&lease)?;
        Ok(RestoreAdmission::Granted(Box::new(RestoreSession {
            store: CheckpointStore {
                root: self.root.duplicate()?,
                policy: self.policy.clone(),
            },
            _lease: lease,
            _continuation_lease: continuation_lease,
            record: next,
        })))
    }

    pub(crate) fn close_restore(&self, id: Uuid) -> Result<serde_json::Value> {
        let _quota = self.root.quota(true)?;
        self.root.recover_capture(id)?;
        let mut record: Record = self.root.json(&record_name(id))?;
        record.validate(&self.root)?;
        let _lease = self
            .root
            .job_lock(id, &record.mutex, &record.intent.digest()?, true)?;
        let binding = record
            .restoration
            .as_ref()
            .ok_or_else(|| invalid("restore claim absent"))?;
        let continuation =
            self.root
                .continuation_mutex(id, &binding.mutex, &binding.intent.digest()?)?;
        fs2::FileExt::try_lock_exclusive(&continuation)?;
        let restoration = record
            .restoration
            .as_mut()
            .ok_or_else(|| invalid("restore claim absent"))?;
        if !restoration.closed() {
            if !restoration.producer_settled {
                restoration.producer.require_absent()?;
            }
            restoration.target_absent()?;
            if restoration.outcome == RestoreOutcome::Pending {
                restoration.outcome = RestoreOutcome::Unconfirmed;
            }
            restoration.phase = RestorePhase::Closed;
            record.validate(&self.root)?;
            metadata::atomic_json(&self.root.path.join(record_name(id)), &record)?;
        }
        record
            .restoration
            .as_ref()
            .expect("restore claim")
            .target_absent()?;
        Ok(
            serde_json::json!({"capture":id,"target_absent":true,"target_reserved_bytes":0,"restoration":record.restoration}),
        )
    }
}
impl RestoreSession {
    fn state(&self) -> &Restoration {
        self.record.restoration.as_ref().expect("owned restoration")
    }
    pub(crate) fn intent(&self) -> &RestoreIntent {
        &self.state().intent
    }
    pub(crate) fn manifest(&self) -> &CheckpointManifest {
        self.record.manifest.as_ref().expect("Ready manifest")
    }
    pub(crate) fn transfer(&self) -> GuestAuthorityTransfer {
        self.intent().transfer(&self.record)
    }
    pub(crate) fn source_absent(&self) -> Result<()> {
        self.record.intent.writer.require_absent()?;
        self.record.intent.source_directory.require_absent()
    }
    pub(crate) fn files(&self) -> Result<CheckpointFiles> {
        self.store.root.verify_objects(&self.record.objects)
    }
    fn save(&mut self, next: Restoration) -> Result<()> {
        let _quota = self.store.root.quota(true)?;
        let actual: Record = self
            .store
            .root
            .json(&record_name(self.record.intent.source.capture))?;
        if serde_json::to_vec(&actual)? != serde_json::to_vec(&self.record)?
            || self.state().producer != Writer::current()?
        {
            return Err(invalid("restore producer or durable preimage differs").into());
        }
        let mut record = self.record.clone();
        record.restoration = Some(next);
        record.validate(&self.store.root)?;
        metadata::atomic_json(
            &self
                .store
                .root
                .path
                .join(record_name(record.intent.source.capture)),
            &record,
        )?;
        self.record = record;
        Ok(())
    }
    pub(crate) fn allocated(&mut self) -> Result<()> {
        if self.state().phase != RestorePhase::Claimed {
            return Err(invalid("restore target allocation cannot be replayed").into());
        }
        let mut next = self.state().clone();
        next.directory = Some(next.intent.destination.acknowledge()?);
        next.phase = RestorePhase::Allocated;
        self.save(next)
    }
    pub(crate) fn launching(&mut self) -> Result<()> {
        if self.state().phase != RestorePhase::Allocated {
            return Err(invalid("restore launch has no original allocation").into());
        }
        let mut next = self.state().clone();
        next.directory
            .as_ref()
            .expect("target directory")
            .require_present()?;
        next.launch_intent = true;
        next.phase = RestorePhase::Launching;
        self.save(next)
    }
    pub(crate) fn tracked(&mut self, pid: u32) -> Result<()> {
        if self.state().phase != RestorePhase::Launching {
            return Err(invalid("restore VMM tracking is out of order").into());
        }
        let mut next = self.state().clone();
        next.writer = Some(Writer::observe(pid)?);
        next.phase = RestorePhase::Tracked;
        self.save(next)
    }
    pub(crate) fn transferred(&mut self, info: &GuestAuthorityInfo) -> Result<()> {
        if self.state().phase != RestorePhase::Tracked {
            return Err(invalid("restore authority transition has no tracked target").into());
        }
        info.validate_frozen(&self.transfer()).map_err(invalid)?;
        self.state()
            .writer
            .as_ref()
            .expect("target writer")
            .require_present()?;
        let mut next = self.state().clone();
        next.phase = RestorePhase::Transferred;
        self.save(next)
    }
    pub(crate) fn activated(&mut self, info: &GuestBarrierInfo) -> Result<()> {
        if self.state().phase != RestorePhase::Transferred {
            return Err(invalid("restore thaw has no authority transition").into());
        }
        info.validate(self.intent().generation, self.record.intent.barrier)
            .map_err(invalid)?;
        if info.phase != GuestBarrierPhase::Resumed {
            return Err(invalid("restore workload thaw is unconfirmed").into());
        }
        self.state()
            .writer
            .as_ref()
            .expect("target writer")
            .require_present()?;
        self.record.intent.writer.require_absent()?;
        self.record.intent.source_directory.require_absent()?;
        let mut next = self.state().clone();
        next.phase = RestorePhase::Activated;
        next.outcome = RestoreOutcome::Activated;
        next.producer_settled = true;
        self.save(next)
    }
    pub(crate) fn fail(&mut self, error: &str) -> Result<()> {
        let mut next = self.state().clone();
        next.phase = RestorePhase::Failed;
        next.outcome = RestoreOutcome::Failed;
        next.producer_settled = true;
        next.error = Some(error.chars().take(512).collect());
        self.save(next)
    }
}
