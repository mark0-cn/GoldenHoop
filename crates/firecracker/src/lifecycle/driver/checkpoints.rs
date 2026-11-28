//! Manager-owned capture jobs. Client IPC never owns the source or I/O leases.
use super::*;
use crate::checkpoint::{CheckpointProbeConfig, storage::CheckpointStore};

impl DriverConfig {
    pub(crate) fn checkpoint_config(&self, capture: Uuid) -> Result<CheckpointProbeConfig> {
        if capture.is_nil() {
            return Err(ApiError::new(ErrorCode::InvalidRequest, "checkpoint ID is nil").into());
        }
        Ok(CheckpointProbeConfig {
            root: self.data_root.join("checkpoints"),
            installation: self.installation_id,
            capture,
            policy: self.checkpoints.clone().ok_or_else(|| {
                ApiError::new(
                    ErrorCode::UnsupportedCapability,
                    "native checkpoints are disabled",
                )
            })?,
        })
    }
}

impl NativeEngine {
    /// Legacy raw submission keeps its previous error contract. The worker's
    /// observed submission may instead return a durable pre-reservation refusal.
    pub(in crate::lifecycle) async fn checkpoint_capture_observed(
        &self,
        handle: &RuntimeHandle,
        capture: Uuid,
    ) -> std::result::Result<serde_json::Value, ApiError> {
        match self.start_capture(handle, capture).await {
            Ok(value) => Ok(value),
            Err(error) => {
                let original = error
                    .downcast_ref::<ApiError>()
                    .cloned()
                    .unwrap_or_else(|| unavailable(error));
                self.reconcile_capture(handle, capture, original.clone())
                    .await
                    .or(Err(original))
            }
        }
    }
    pub(in crate::lifecycle) async fn checkpoint_reconcile_bound(
        &self,
        handle: &RuntimeHandle,
        capture: Uuid,
    ) -> std::result::Result<serde_json::Value, ApiError> {
        self.reconcile_capture(
            handle,
            capture,
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "capture intent was not visible at reconciliation",
            ),
        )
        .await
    }
    async fn reconcile_capture(
        &self,
        handle: &RuntimeHandle,
        capture: Uuid,
        reason: ApiError,
    ) -> std::result::Result<serde_json::Value, ApiError> {
        let result = async {
            let cfg = self.inner.cfg.checkpoint_config(capture)?;
            let store = CheckpointStore::open_or_initialize(&cfg)?;
            let before = self.for_handle(handle)?;
            if let Some(value) = self.original_capture(&store, &before, capture).await? {
                return Ok(value);
            }
            let _guard = self.vm_lock(handle.sandbox_id).await.lock_owned().await;
            let current = self.for_handle(handle)?;
            if current.owner != before.owner {
                return Err(invalid("capture source changed during reconciliation").into());
            }
            if let Some(value) = self.original_capture(&store, &current, capture).await? {
                return Ok(value);
            }
            if current.capture_hold == Some(capture) {
                return Err(invalid(
                    "capture hold exists without its acknowledged reservation; refusal is unproven",
                )
                .into());
            }
            let source = crate::checkpoint::CaptureIdentity {
                installation: current.owner.installation_id,
                sandbox: current.owner.sandbox_id,
                source_generation: current.owner.generation,
                capture,
                request_sha256: current.owner.request_sha256,
            };
            let outcome =
                tokio::task::spawn_blocking(move || store.close_unstarted(source, &reason))
                    .await??;
            match outcome {
                Some(value) => Ok(value),
                None => self
                    .checkpoint_read_bound(handle, capture, false)
                    .await
                    .map_err(Into::into),
            }
        }
        .await;
        result.map_err(|error: Box<dyn std::error::Error + Send + Sync>| {
            error
                .downcast_ref::<ApiError>()
                .cloned()
                .unwrap_or_else(|| unavailable(error))
        })
    }
    pub(in crate::lifecycle) async fn checkpoint_capture(
        &self,
        handle: &RuntimeHandle,
        capture: Uuid,
    ) -> std::result::Result<serde_json::Value, ApiError> {
        self.start_capture(handle, capture).await.map_err(|error| {
            error
                .downcast_ref::<ApiError>()
                .cloned()
                .unwrap_or_else(|| unavailable(error))
        })
    }

    async fn original_capture(
        &self,
        store: &CheckpointStore,
        record: &VmJournal,
        capture: Uuid,
    ) -> Result<Option<serde_json::Value>> {
        if let Some(source) = store.source(capture)? {
            if source.installation != record.owner.installation_id
                || source.sandbox != record.owner.sandbox_id
                || source.source_generation != record.owner.generation
                || source.request_sha256 != record.owner.request_sha256
            {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "checkpoint ID belongs to a different source intent",
                )
                .into());
            }
            return self
                .checkpoint_read(capture, false)
                .await
                .map(Some)
                .map_err(Into::into);
        }
        Ok(None)
    }

    async fn start_capture(
        &self,
        handle: &RuntimeHandle,
        capture: Uuid,
    ) -> Result<serde_json::Value> {
        let cfg = self.inner.cfg.checkpoint_config(capture)?;
        let store = CheckpointStore::open_or_initialize(&cfg)?;
        // Read the original immutable intent before waiting for the VM lease:
        // exact retries remain useful while its first capture is in progress.
        let record = self.for_handle(handle)?;
        if let Some(status) = self.original_capture(&store, &record, capture).await? {
            return Ok(status);
        }
        let guard = self.vm_lock(handle.sandbox_id).await.lock_owned().await;
        let record = self.for_handle(handle)?;
        if let Some(status) = self.original_capture(&store, &record, capture).await? {
            return Ok(status);
        }
        let permit = self
            .inner
            .capture_slot
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "native capture worker is reserved",
                )
            })?;
        self.live_agent(&record).await?;
        let machine = Machine::recover(&self.inner.cfg, self.load(handle.sandbox_id)?)?;
        let input = record.artifacts.clone();
        let mut session = machine.reserve_capture(&input, &cfg).await?;
        let accepted = serde_json::json!({"capture":capture,"phase":"reserved","capture_outcome":"pending",
            "reserved_bytes":session.reserved_bytes(),"reference":null,"manifest":null,"content_verified":false,"error":null});
        let actor = self.clone();
        // The blocking worker owns every lease, including while async VMM calls
        // run on its private reactor. Aborting a client future cannot drop those
        // leases while a detached copy continues writing.
        let task = tokio::task::spawn_blocking(move || {
            let _source_guard = guard;
            let _permit = permit;
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    session.fail(&error.to_string())?;
                    return Err(error.into());
                }
            };
            runtime.block_on(async move {
                if let Err(error) = actor
                    .supervisor_call(&record, SupervisorOperation::CaptureHold { capture })
                    .await
                {
                    session.fail(&error.to_string())?;
                    return Err(error);
                }
                // This recovered view never writes the supervisor's journal.
                // The supervisor keeps servicing expiry independently of copies.
                machine.capture_reserved(&input, &cfg, session).await?;
                Ok(())
            })
        });
        self.inner
            .capture_tasks
            .lock()
            .map_err(|_| invalid("capture task registry poisoned"))?
            .push(task);
        Ok(accepted)
    }

    pub(in crate::lifecycle) async fn checkpoint_read(
        &self,
        capture: Uuid,
        collect: bool,
    ) -> std::result::Result<serde_json::Value, ApiError> {
        let result = async {
            let cfg = self.inner.cfg.checkpoint_config(capture)?;
            tokio::task::spawn_blocking(move || {
                let store = CheckpointStore::open_or_initialize(&cfg)?;
                if collect {
                    store.collect(capture)
                } else {
                    store.inspect(capture)
                }
            })
            .await?
        }
        .await;
        result.map_err(|error: Box<dyn std::error::Error + Send + Sync>| {
            error
                .downcast_ref::<ApiError>()
                .cloned()
                .unwrap_or_else(|| unavailable(error))
        })
    }

    /// A capture UUID alone is not source-generation authority. This read/GC
    /// path never calls capture, including when the original record is absent.
    pub(in crate::lifecycle) async fn checkpoint_read_bound(
        &self,
        handle: &RuntimeHandle,
        capture: Uuid,
        collect: bool,
    ) -> std::result::Result<serde_json::Value, ApiError> {
        let result = async {
            let cfg = self.inner.cfg.checkpoint_config(capture)?;
            let original = self.for_handle(handle)?.owner;
            tokio::task::spawn_blocking(move || {
                let store = CheckpointStore::open_or_initialize(&cfg)?;
                let source = store.source(capture)?.ok_or_else(|| {
                    ApiError::new(ErrorCode::NotFound, "original checkpoint intent is absent; no capture was dispatched by this inspection")
                })?;
                if source.installation != original.installation_id
                    || source.sandbox != original.sandbox_id
                    || source.source_generation != original.generation
                    || source.request_sha256 != original.request_sha256
                {
                    return Err(ApiError::new(ErrorCode::Conflict, "checkpoint belongs to a different original source generation").into());
                }
                if collect { store.collect(capture) } else { store.inspect(capture) }
            }).await?
        }.await;
        result.map_err(|error: Box<dyn std::error::Error + Send + Sync>| {
            error
                .downcast_ref::<ApiError>()
                .cloned()
                .unwrap_or_else(|| unavailable(error))
        })
    }

    pub(in crate::lifecycle) fn reap_capture_tasks(&self) {
        if let Ok(mut tasks) = self.inner.capture_tasks.lock() {
            // The durable capture record, not this disposable join handle, is
            // authoritative for success, failure and outstanding reservations.
            tasks.retain(|task| !task.is_finished());
        }
    }

    pub(in crate::lifecycle) async fn drain_capture_tasks(&self) -> Result<()> {
        let tasks = std::mem::take(
            &mut *self
                .inner
                .capture_tasks
                .lock()
                .map_err(|_| invalid("capture task registry poisoned"))?,
        );
        for task in tasks {
            // A known capture failure is retained in its journal. A panicked
            // worker never becomes a positive settlement acknowledgement.
            let _ = task.await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_budget_is_reserved_in_capacity_and_disabled_configuration_bytes_stay_compatible() {
        let artifact = Artifact {
            path: "/operator/artifact".into(),
            sha256: "a".repeat(64),
            size: 1,
        };
        let mut cfg = DriverConfig {
            installation_id: Uuid::new_v4(),
            data_root: "/var/lib/gh-test".into(),
            artifacts: BootInput {
                firecracker: artifact.clone(),
                jailer: artifact.clone(),
                kernel: artifact.clone(),
                rootfs: artifact.clone(),
            },
            supervisor: artifact,
            image: format!("sha256:{}", "a".repeat(64)),
            prepared_images: None,
            checkpoints: None,
            max_resources: ResourceLimits {
                cpu_millis: 1000,
                memory_bytes: 256 * MIB,
                pids: 32,
            },
            capacity: HostCapacity {
                cpu_millis: 1000,
                memory_bytes: 1152 * MIB,
                max_vms: 1,
            },
            max_ttl_seconds: 300,
        };
        cfg.validate().unwrap();
        assert!(
            serde_json::to_value(&cfg)
                .unwrap()
                .get("checkpoints")
                .is_none()
        );
        assert_eq!(
            cfg.checkpoint_config(Uuid::new_v4())
                .unwrap_err()
                .downcast_ref::<ApiError>()
                .unwrap()
                .code,
            ErrorCode::UnsupportedCapability
        );
        cfg.checkpoints = Some(crate::checkpoint::CheckpointStorePolicy {
            max_bytes: 2 * 1024 * MIB,
            max_checkpoints: 1,
        });
        assert!(
            cfg.validate().is_err(),
            "enabled capture requires accounted host memory"
        );
        cfg.capacity.memory_bytes += 128 * MIB;
        cfg.validate().unwrap();
        assert!(cfg.checkpoint_config(Uuid::nil()).is_err());
        let scoped = cfg.checkpoint_config(Uuid::new_v4()).unwrap();
        assert_eq!(scoped.root, cfg.data_root.join("checkpoints"));
        assert_eq!(scoped.installation, cfg.installation_id);
        cfg.checkpoints.as_mut().unwrap().max_checkpoints = 0;
        assert!(cfg.validate().is_err());
    }
}
