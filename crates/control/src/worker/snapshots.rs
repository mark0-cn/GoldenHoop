//! Source-serialized capture admission and backend-observed reconciliation.
use super::*;
use crate::InternalSnapshotCall;
use goldenhoop_store::StoredSnapshot;

fn inconsistent() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "snapshot observation differs from its original source binding",
    )
}
fn request(stored: &StoredSnapshot, source: &StoredSandbox) -> MemoryCaptureRequest {
    MemoryCaptureRequest {
        id: stored.snapshot.id,
        source: source.sandbox.clone(),
        handle: stored.source_handle.clone(),
        created_at: stored.snapshot.created_at,
    }
}
fn observation_matches(
    value: &MemoryCaptureObservation,
    stored: &StoredSnapshot,
) -> Result<(), ApiError> {
    if value.id != stored.snapshot.id
        || value.source.sandbox_id != stored.source_handle.sandbox_id
        || value.source.profile != stored.source_handle.profile
        || value.source.backend_ref != stored.source_handle.backend_ref
    {
        return Err(inconsistent());
    }
    Ok(())
}

pub(super) async fn create(
    State(worker): State<Arc<Worker>>,
    ApiJson(call): ApiJson<InternalSnapshotCall>,
) -> Result<Json<SnapshotCreated>, HttpError> {
    worker
        .admit_snapshot(call.sandbox_id, &call.request, &call.idempotency_key)
        .await
        .map(Json)
        .map_err(Into::into)
}

impl Worker {
    /// The first fence is created while holding the same lock as command/file
    /// dispatch. Already accepted effects finish before admission, and normal
    /// reconciliation never encounters a newly created fence halfway through RPC.
    pub(super) async fn admit_snapshot(
        &self,
        source: Uuid,
        intent: &CreateSnapshot,
        key: &str,
    ) -> Result<SnapshotCreated, ApiError> {
        if let Some(previous) = self
            .store
            .prior_snapshot_request(source, intent, key)
            .await?
        {
            return Ok(previous);
        }
        let _guard = self.lock(source).await.lock_owned().await;
        if let Some(previous) = self
            .store
            .prior_snapshot_request(source, intent, key)
            .await?
        {
            return Ok(previous);
        }
        let original = self.store.sandbox(source).await?;
        let profile = self
            .registration
            .profiles
            .iter()
            .find(|p| p.id == original.sandbox.profile)
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::BackendUnavailable,
                    "snapshot source profile is unavailable",
                )
            })?;
        require_capability(profile, Capability::MemorySnapshot)?;
        let driver = self.drivers.get(&original.sandbox.profile).ok_or_else(|| {
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "snapshot source driver is unavailable",
            )
        })?;
        let handle = original.handle.clone().ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidState,
                "snapshot source has no observed runtime",
            )
        })?;
        // Pure local validation, before either a source fence or dispatch marker.
        driver.validate_memory_capture(&MemoryCaptureRequest {
            id: Uuid::new_v4(),
            source: original.sandbox,
            handle,
            created_at: Utc::now(),
        })?;
        self.store
            .create_snapshot(profile, source, intent, key)
            .await
    }

    pub(super) async fn schedule_snapshot_work(
        self: &Arc<Self>,
        tasks: &mut JoinSet<()>,
        offset: &mut usize,
    ) -> Result<(), ApiError> {
        let mut work = self.store.snapshot_work().await?;
        // A Pending acknowledgement releases this RPC task's permit while the
        // native producer still owns its copy worker. Keep later capture
        // intents queued until the original in-flight capture is settled.
        let occupied: std::collections::HashSet<_> = work
            .iter()
            .filter(|s| {
                s.dispatched
                    && (matches!(
                        s.snapshot.state,
                        SnapshotState::Capturing | SnapshotState::Unknown
                    ) || s.snapshot.state == SnapshotState::Failed && !s.source_collected)
            })
            .map(|s| s.source_handle.profile.clone())
            .collect();
        if !work.is_empty() {
            let start = *offset % work.len();
            work.rotate_left(start);
            *offset = offset.wrapping_add(1);
        }
        for stored in work {
            if stored.snapshot.state == SnapshotState::Pending
                && occupied.contains(&stored.source_handle.profile)
            {
                continue;
            }
            if stored.snapshot.state == SnapshotState::Ready
                || stored.snapshot.cleanup == CleanupState::Complete
            {
                continue;
            }
            let Ok(capture_permit) = self.snapshot_concurrency.clone().try_acquire_owned() else {
                break;
            };
            let Ok(permit) = self.concurrency.clone().try_acquire_owned() else {
                break;
            };
            let Ok(guard) = self
                .lock(stored.snapshot.source_sandbox_id)
                .await
                .try_lock_owned()
            else {
                continue;
            };
            let worker = self.clone();
            let id = stored.snapshot.id;
            tasks.spawn(async move {
                let (_guard, _permit, _capture_permit) = (guard, permit, capture_permit);
                if let Err(error) = worker.reconcile_snapshot(id).await {
                    if let Err(persist) = worker.snapshot_error(id, &error).await {
                        report("snapshot_error_persist_failed", &persist);
                    }
                    report("snapshot_reconciliation_failed", &error);
                }
            });
        }
        Ok(())
    }

    /// Caller owns the source-sandbox lock. A prior dispatch only inspects; an
    /// absent/uncertain backend reply can never create a second capture permit.
    pub(super) async fn reconcile_snapshot(&self, id: Uuid) -> Result<(), ApiError> {
        let mut stored = self.store.snapshot(id).await?;
        if stored.snapshot.state == SnapshotState::Ready
            || stored.snapshot.cleanup == CleanupState::Complete
        {
            return Ok(());
        }
        let mut source = self
            .store
            .sandbox(stored.snapshot.source_sandbox_id)
            .await?;
        // Snapshot polling must not starve explicit termination or expiry of
        // the same source by taking its mutex before ordinary reconciliation.
        if source.sandbox.cleanup != CleanupState::Complete
            && self.store.effective_desired(source.sandbox.id).await? == DesiredState::Terminated
        {
            self.reconcile(source.sandbox.id).await?;
            source = self.store.sandbox(source.sandbox.id).await?;
            stored = self.store.snapshot(id).await?;
        }
        let driver = self
            .drivers
            .get(&stored.source_handle.profile)
            .map(Arc::as_ref)
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::BackendUnavailable,
                    "original snapshot driver is unavailable",
                )
            })?;
        if stored.snapshot.state == SnapshotState::Failed {
            return self.collect_failed_snapshot(stored, source, driver).await;
        }
        let capture = request(&stored, &source);
        if !stored.dispatched {
            driver.validate_memory_capture(&capture)?;
        }
        let dispatch = self
            .store
            .begin_snapshot_capture(id, &stored.source_handle)
            .await?;
        let observation = if dispatch.first_dispatch {
            driver.capture_memory(&capture).await?
        } else {
            driver.inspect_memory_capture(&capture).await?
        };
        observation_matches(&observation, &stored)?;
        match observation.state {
            MemoryCaptureState::Pending => Ok(()),
            MemoryCaptureState::Ready {
                manifest,
                reference,
            } => {
                if !stored.source_collected {
                    match driver.inspect(&stored.source_handle).await?.state {
                        ObservedState::Paused => {
                            if source.sandbox.state == SandboxState::Running {
                                source = self
                                    .save(
                                        source,
                                        SandboxState::Pausing,
                                        CleanupState::Pending,
                                        Some("memory snapshot source pause observed".into()),
                                    )
                                    .await?;
                            }
                            self.save(
                                source,
                                SandboxState::Paused,
                                CleanupState::Pending,
                                Some("source held by memory snapshot capture".into()),
                            )
                            .await?;
                        }
                        ObservedState::Missing | ObservedState::Exited => {
                            self.store
                                .set_desired(
                                    source.sandbox.id,
                                    DesiredState::Terminated,
                                    &format!("snapshot-source-absent-{id}"),
                                )
                                .await?;
                            self.stop(
                                self.store.sandbox(source.sandbox.id).await?,
                                driver,
                                "snapshot source is already absent; confirming original collection",
                                ExecutionState::Cancelled,
                            )
                            .await?;
                        }
                        _ => {
                            return Err(ApiError::new(
                                ErrorCode::BackendUnavailable,
                                "captured source is not positively paused or collected",
                            ));
                        }
                    }
                }
                self.store
                    .snapshot_capture_ready(id, &stored.source_handle, &manifest, &reference)
                    .await
            }
            MemoryCaptureState::Failed(error) => {
                self.store
                    .snapshot_capture_failed(id, &stored.source_handle, &error)
                    .await?;
                self.collect_failed_snapshot(self.store.snapshot(id).await?, source, driver)
                    .await
            }
            MemoryCaptureState::Collected => {
                let error = ApiError::new(
                    ErrorCode::InvalidState,
                    "capture objects were collected before public Ready publication",
                );
                self.store
                    .snapshot_capture_failed(id, &stored.source_handle, &error)
                    .await?;
                self.collect_failed_snapshot(self.store.snapshot(id).await?, source, driver)
                    .await
            }
        }
    }

    async fn collect_failed_snapshot(
        &self,
        stored: StoredSnapshot,
        mut source: StoredSandbox,
        driver: &dyn WorkerDriver,
    ) -> Result<(), ApiError> {
        let capture = request(&stored, &source);
        if source.sandbox.cleanup != CleanupState::Complete {
            self.store
                .set_desired(
                    source.sandbox.id,
                    DesiredState::Terminated,
                    &format!("snapshot-failed-source-{}", stored.snapshot.id),
                )
                .await?;
            source = self.store.sandbox(source.sandbox.id).await?;
            self.stop(
                source,
                driver,
                "failed memory capture requires original source collection",
                ExecutionState::Failed,
            )
            .await?;
        }
        if !self
            .store
            .snapshot(stored.snapshot.id)
            .await?
            .source_collected
        {
            return Err(inconsistent());
        }
        let observed = driver.collect_memory_capture(&capture).await?;
        observation_matches(&observed, &stored)?;
        if !matches!(observed.state, MemoryCaptureState::Collected) {
            return Err(inconsistent());
        }
        self.store
            .snapshot_capture_collected(stored.snapshot.id, &stored.source_handle)
            .await
    }

    async fn snapshot_error(&self, id: Uuid, error: &ApiError) -> Result<(), ApiError> {
        let stored = self.store.snapshot(id).await?;
        match stored.snapshot.state {
            SnapshotState::Pending if !stored.dispatched => {
                self.store.fail_unstarted_snapshot(id, error).await
            }
            SnapshotState::Capturing | SnapshotState::Unknown => {
                self.store.snapshot_capture_unknown(id, error).await
            }
            SnapshotState::Failed if stored.snapshot.cleanup != CleanupState::Complete => {
                self.store.snapshot_cleanup_unknown(id).await
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests;
