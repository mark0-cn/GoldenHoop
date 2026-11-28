//! Immutable native target intent. The supervisor owns the actual store claim.
use super::*;
use crate::checkpoint::{
    CheckpointReference,
    storage::{
        CheckpointStore,
        restore::{RestoreAdmission, RestoreIntent, RestoreSession},
    },
};
use goldenhoop_runtime::RuntimeHandle;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRestoreRequest {
    pub sandbox: Sandbox,
    pub request: CreateSandbox,
    pub reference: CheckpointReference,
    pub restoration: Uuid,
    /// Public restoration binds the exact captured source generation. Legacy
    /// private requests remain readable, but never acquire this stronger proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_source: Option<RuntimeHandle>,
}
impl ManagedRestoreRequest {
    pub(crate) fn digest(&self) -> Result<String> {
        if self.restoration.is_nil()
            || self.reference.capture.is_nil()
            || self.reference.installation.is_nil()
            || self.sandbox.id.is_nil()
        {
            return Err(invalid("native restoration identity is nil").into());
        }
        let mut hash = Sha256::new();
        hash.update(b"goldenhoop.native-restoration-request.v1\0");
        hash.update(serde_json::to_vec(&(
            &self.request,
            &self.reference,
            self.restoration,
            self.sandbox.id,
            self.sandbox.created_at,
            self.sandbox.expires_at,
        ))?);
        if let Some(source) = &self.expected_source {
            if source.sandbox_id.is_nil()
                || source.sandbox_id == self.sandbox.id
                || source.profile != PROFILE
                || source.backend_ref.is_empty()
            {
                return Err(invalid("native expected restoration source differs").into());
            }
            hash.update(b"\0expected-source.v1\0");
            hash.update(serde_json::to_vec(source)?);
        }
        Ok(format!("{:x}", hash.finalize()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreBinding {
    pub intent: RestoreIntent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_source: Option<RuntimeHandle>,
}
impl RestoreBinding {
    pub(crate) fn validate(&self, cfg: &DriverConfig, record: &VmJournal) -> Result<()> {
        let intent = &self.intent;
        let runtime = &intent.runtime;
        if let Some(source) = &self.expected_source {
            let generation = source
                .backend_ref
                .rsplit(':')
                .next()
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or_else(|| invalid("native restore expected source generation is missing"))?;
            if generation.is_nil()
                || source.sandbox_id.is_nil()
                || source.sandbox_id == record.owner.sandbox_id
                || source
                    != &driver::native_handle(cfg.installation_id, source.sandbox_id, generation)
            {
                return Err(
                    invalid("native restore expected source journal binding differs").into(),
                );
            }
        }
        if cfg.checkpoints.is_none()
            || intent.reference.installation != cfg.installation_id
            || intent.reference.capture.is_nil()
            || intent.reference.manifest_sha256.len() != 64
            || !intent
                .reference
                .manifest_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || intent.restoration.is_nil()
            || intent.sandbox != record.owner.sandbox_id
            || intent.generation != record.owner.generation
            || intent.destination.path() != cfg.paths(record.owner.generation)?.root
            || runtime.firecracker_version != crate::api::SUPPORTED_VMM_VERSION
            || runtime.firecracker_sha256 != record.artifacts.firecracker.sha256
            || runtime.jailer_sha256 != record.artifacts.jailer.sha256
            || runtime.kernel_sha256 != record.artifacts.kernel.sha256
            || runtime.architecture != std::env::consts::ARCH
        {
            return Err(
                invalid("native restore journal differs from its original target/runtime").into(),
            );
        }
        Ok(())
    }

    pub(crate) fn claim(&self, cfg: &DriverConfig) -> Result<Box<RestoreSession>> {
        let checkpoint = cfg.checkpoint_config(self.intent.reference.capture)?;
        let store = CheckpointStore::open_or_initialize(&checkpoint)?;
        match store.claim_restore(self.intent.clone())? {
            RestoreAdmission::Granted(session) => Ok(session),
            RestoreAdmission::Existing(_) => Err(invalid(
                "original restore claim already exists; another supervisor cannot relaunch it",
            )
            .into()),
        }
    }
}

/// A native collector's identity-bound acknowledgement. This grants no launch
/// authority. Fresh namespace, producer, directory and cgroup checks remain
/// mandatory when it is used to close a claim whose writer acknowledgement died.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CollectedNativeRestore {
    intent: RestoreIntent,
    producer: ProcessIdentity,
    directory: root::CollectedDirectory,
    groups: [(PathBuf, recovery::PathIdentity); 2],
    vmm: Option<ProcessIdentity>,
}
impl CollectedNativeRestore {
    pub(crate) fn observe(cfg: &DriverConfig, record: &VmJournal) -> Result<Self> {
        record.validate(cfg, record.owner.sandbox_id)?;
        if !["vm_collected", "collected"].contains(&record.phase.as_str())
            || !record.root_collection_started
        {
            return Err(invalid(
                "native target collection has no completed collector acknowledgement",
            )
            .into());
        }
        let binding = record
            .restore
            .as_ref()
            .ok_or_else(|| invalid("native restore binding absent"))?;
        let producer = record
            .supervisor
            .clone()
            .ok_or_else(|| invalid("native restore supervisor absent"))?;
        let paths = cfg.paths(record.owner.generation)?;
        let directory = record
            .vm_root
            .as_ref()
            .ok_or_else(|| invalid("native restore root receipt absent"))?
            .confirm_collected(&paths.root, record.owner.generation, &producer)?;
        let result = Self {
            intent: binding.intent.clone(),
            producer,
            directory,
            groups: [
                (
                    paths.vm_cgroup,
                    record
                        .vm_cgroup_identity
                        .clone()
                        .ok_or_else(|| invalid("native restore VM group receipt absent"))?,
                ),
                (
                    paths.supervisor_cgroup,
                    record
                        .supervisor_cgroup_identity
                        .clone()
                        .ok_or_else(|| invalid("native restore supervisor group receipt absent"))?,
                ),
            ],
            vmm: record.process.as_ref().map(|p| ProcessIdentity {
                pid: p.pid,
                start_ticks: p.start_ticks,
                boot_id: p.boot_id.clone(),
                executable_sha256: p.executable_sha256.clone(),
                uid: p.uid,
            }),
        };
        result.require_absent()?;
        Ok(result)
    }
    pub(crate) fn matches(&self, intent: &RestoreIntent, producer: &ProcessIdentity) -> Result<()> {
        let suffix = format!(
            "{}-{}",
            intent.reference.installation.simple(),
            intent.generation.simple()
        );
        if self.intent != *intent
            || self.producer != *producer
            || !self.directory.binding_matches(
                intent.destination.path(),
                intent.generation,
                producer,
            )
            || self.groups[0].0 != Path::new("/sys/fs/cgroup").join(format!("ghv-{suffix}"))
            || self.groups[1].0 != Path::new("/sys/fs/cgroup").join(format!("ghs-{suffix}"))
            || self
                .groups
                .iter()
                .any(|(_, identity)| identity.device_inode().1 == 0)
            || self.vmm.as_ref().is_some_and(|p| {
                p.boot_id != producer.boot_id
                    || p.pid <= 1
                    || p.start_ticks == 0
                    || p.executable_sha256 != intent.runtime.firecracker_sha256
            })
        {
            return Err(invalid("native collected target identity differs").into());
        }
        Ok(())
    }
    pub(crate) fn directory(&self) -> &root::CollectedDirectory {
        &self.directory
    }
    pub(crate) fn require_absent(&self) -> Result<()> {
        self.matches(&self.intent, &self.producer)?;
        self.directory.verify()?;
        let root = Path::new("/sys/fs/cgroup");
        let metadata = std::fs::symlink_metadata(root)?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        let name = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())?;
        if std::fs::canonicalize(root)? != root
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || unsafe { libc::statfs(name.as_ptr(), &mut filesystem) } != 0
            || i128::from(filesystem.f_type) != i128::from(libc::CGROUP2_SUPER_MAGIC)
            || self
                .groups
                .iter()
                .any(|(_, identity)| identity.device_inode().0 != metadata.dev())
        {
            return Err(invalid("native collected cgroup observer hierarchy differs").into());
        }
        for (path, _) in &self.groups {
            if !recovery::absent(path)? {
                return Err(invalid("native collected cgroup path was replaced or remains").into());
            }
        }
        if let Some(vmm) = &self.vmm
            && !reaper::process_absent(vmm)?
        {
            return Err(invalid("native collected VMM identity remains").into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{CheckpointStorePolicy, storage::Destination};
    use goldenhoop_runtime::RuntimeDriver;

    #[tokio::test]
    async fn actual_completed_native_intent_retry_never_recreates_a_target_or_reopens_content() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let directory = tempfile::Builder::new()
            .prefix("grr-")
            .tempdir_in("/var/lib")
            .unwrap();
        let binary = PathBuf::from("/usr/bin/true");
        let (sha256, size) = digest(trusted_file(&binary).unwrap()).unwrap();
        let artifact = Artifact {
            path: binary,
            sha256,
            size,
        };
        let resources = ResourceLimits {
            cpu_millis: 500,
            memory_bytes: 256 * MIB,
            pids: 32,
        };
        let cfg = DriverConfig {
            installation_id: Uuid::new_v4(),
            data_root: directory.path().join("d"),
            artifacts: BootInput {
                firecracker: artifact.clone(),
                jailer: artifact.clone(),
                kernel: artifact.clone(),
                rootfs: artifact.clone(),
            },
            supervisor: artifact.clone(),
            image: format!("sha256:{}", artifact.sha256),
            prepared_images: None,
            checkpoints: Some(CheckpointStorePolicy {
                max_bytes: 3 * 1024 * MIB,
                max_checkpoints: 2,
            }),
            max_resources: resources.clone(),
            capacity: HostCapacity::default(),
            max_ttl_seconds: 300,
        };
        let lease = metadata::claim_installation(&cfg.data_root, cfg.installation_id).unwrap();
        let engine = driver::NativeEngine::connect(cfg.clone(), lease).unwrap();
        let mut closed_intents = Vec::new();
        for expired in [false, true] {
            let now = Utc::now();
            let created = now - chrono::Duration::seconds(if expired { 120 } else { 0 });
            let mut request = CreateSandbox::new(PROFILE, cfg.image.clone());
            request.resources = resources.clone();
            request.ttl_seconds = 60;
            let sandbox = Sandbox {
                id: Uuid::new_v4(),
                profile: PROFILE.into(),
                image: cfg.image.clone(),
                state: SandboxState::Pending,
                desired_state: DesiredState::Running,
                cleanup: CleanupState::Pending,
                created_at: created,
                expires_at: created + chrono::Duration::seconds(60),
                observed_at: None,
                resources: resources.clone(),
                metadata: Default::default(),
                reason: None,
            };
            let operation = ManagedRestoreRequest {
                sandbox,
                request,
                reference: CheckpointReference {
                    installation: cfg.installation_id,
                    capture: Uuid::new_v4(),
                    manifest_sha256: "a".repeat(64),
                },
                restoration: Uuid::new_v4(),
                expected_source: expired.then(|| {
                    driver::native_handle(cfg.installation_id, Uuid::new_v4(), Uuid::new_v4())
                }),
            };
            let generation = Uuid::new_v4();
            let paths = cfg.paths(generation).unwrap();
            let binding = RestoreBinding {
                expected_source: operation.expected_source.clone(),
                intent: RestoreIntent {
                    reference: operation.reference.clone(),
                    runtime: crate::checkpoint::CheckpointRuntime {
                        firecracker_version: crate::api::SUPPORTED_VMM_VERSION.into(),
                        firecracker_sha256: artifact.sha256.clone(),
                        jailer_sha256: artifact.sha256.clone(),
                        kernel_sha256: artifact.sha256.clone(),
                        architecture: std::env::consts::ARCH.into(),
                        host_compatibility_sha256: "b".repeat(64),
                    },
                    restoration: operation.restoration,
                    sandbox: operation.sandbox.id,
                    generation,
                    destination: Destination::observe(&paths.root, generation).unwrap(),
                },
            };
            let record = VmJournal {
                format: 1,
                owner: VmOwner {
                    installation_id: cfg.installation_id,
                    sandbox_id: operation.sandbox.id,
                    generation,
                    request_sha256: operation.digest().unwrap(),
                    expires_at: operation.sandbox.expires_at,
                    host_boot_id: boot_id().unwrap(),
                    boot_deadline_ns: if expired {
                        1
                    } else {
                        boottime_ns().unwrap() + 60_000_000_000
                    },
                },
                artifacts: cfg.artifacts.clone(),
                selected_image: None,
                profile_probe_context_sha256: None,
                capture_hold: None,
                restore: Some(binding),
                resources: resources.clone(),
                supervisor: None,
                supervisor_cgroup_identity: None,
                vm_cgroup_identity: None,
                vm_root: None,
                root_collection_started: false,
                supervisor_artifact: artifact.clone(),
                original_cgroup: PathBuf::from("/sys/fs/cgroup"),
                process: None,
                phase: "collected".into(),
                ever_ready: false,
                error: Some("original prelaunch refusal".into()),
                console_tail: String::new(),
                supervisor_stderr_tail: String::new(),
                supervisor_cgroup_events: Default::default(),
            };
            record.validate(&cfg, operation.sandbox.id).unwrap();
            let path = cfg.record_path(operation.sandbox.id);
            atomic_json(&path, &record).unwrap();
            let original = std::fs::read(&path).unwrap();
            let handle = engine.checkpoint_restore(&operation).await.unwrap();
            assert_eq!(handle.sandbox_id, operation.sandbox.id);
            assert!(handle.backend_ref.ends_with(&generation.to_string()));
            let mut changed = operation.clone();
            changed.expected_source = Some(driver::native_handle(
                cfg.installation_id,
                Uuid::new_v4(),
                Uuid::new_v4(),
            ));
            assert_ne!(changed.digest().unwrap(), operation.digest().unwrap());
            assert_eq!(
                engine.checkpoint_restore(&changed).await.unwrap_err().code,
                ErrorCode::Conflict
            );
            assert_eq!(
                engine
                    .checkpoint_restore_collect(&changed)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::Conflict
            );
            assert_eq!(std::fs::read(&path).unwrap(), original);
            changed = operation.clone();
            changed.restoration = Uuid::new_v4();
            assert_eq!(
                engine.checkpoint_restore(&changed).await.unwrap_err().code,
                ErrorCode::Conflict
            );
            assert!(
                engine
                    .create(&operation.sandbox, &operation.request)
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read(&path).unwrap(), original);
            assert!(
                !paths.root.exists()
                    && !paths.vm_cgroup.exists()
                    && !paths.supervisor_cgroup.exists()
            );
            for suffix in [
                format!("capture-{}.json", operation.reference.capture),
                format!("continuation-{}.lock", operation.reference.capture),
            ] {
                assert!(!cfg.data_root.join("checkpoints").join(suffix).exists());
            }
            engine.checkpoint_restore_collect(&operation).await.unwrap();
            let closure = cfg
                .data_root
                .join("restore-closures")
                .join(format!("{}.json", operation.sandbox.id));
            let original_closure = std::fs::read(&closure).unwrap();
            engine.checkpoint_restore_collect(&operation).await.unwrap();
            assert_eq!(std::fs::read(&closure).unwrap(), original_closure);
            assert_eq!(
                engine
                    .checkpoint_restore_collect(&changed)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::Conflict
            );
            assert_eq!(
                engine
                    .checkpoint_restore(&operation)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidState
            );
            assert_eq!(std::fs::read(&path).unwrap(), original);
            let mut never_dispatched = operation.clone();
            never_dispatched.sandbox.id = Uuid::new_v4();
            never_dispatched.restoration = Uuid::new_v4();
            engine
                .checkpoint_restore_collect(&never_dispatched)
                .await
                .unwrap();
            assert!(!cfg.record_path(never_dispatched.sandbox.id).exists());
            assert_eq!(
                engine
                    .checkpoint_restore(&never_dispatched)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidState
            );
            assert_eq!(
                engine
                    .create(&never_dispatched.sandbox, &never_dispatched.request)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidState
            );
            closed_intents.push(never_dispatched);
        }
        drop(engine);
        let lease = metadata::claim_installation(&cfg.data_root, cfg.installation_id).unwrap();
        let reopened = driver::NativeEngine::connect(cfg.clone(), lease).unwrap();
        for intent in closed_intents {
            reopened.checkpoint_restore_collect(&intent).await.unwrap();
            assert_eq!(
                reopened.checkpoint_restore(&intent).await.unwrap_err().code,
                ErrorCode::InvalidState
            );
            assert!(!cfg.record_path(intent.sandbox.id).exists());
        }
        drop(reopened);
        let path = directory.path().to_owned();
        directory.close().unwrap();
        assert!(!path.exists());
    }
}
