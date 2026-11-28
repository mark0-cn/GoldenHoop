//! Public intent selects exactly one native target; retained jobs are inspected, never started.
use super::*;
use goldenhoop_store::StoredRestoration;
#[cfg(test)]
mod tests;

pub(super) async fn create(
    State(worker): State<Arc<Worker>>,
    ApiJson(call): ApiJson<crate::InternalRestoreCall>,
) -> Result<Json<SnapshotRestored>, HttpError> {
    Ok(Json(
        worker
            .admit_restoration(call.snapshot_id, &call.request, &call.idempotency_key)
            .await?,
    ))
}
impl Worker {
    async fn restoration_request(
        &self,
        r: &StoredRestoration,
    ) -> Result<MemoryRestoreRequest, ApiError> {
        let snapshot = self.store.snapshot(r.snapshot_id).await?;
        let target = self.store.sandbox(r.target.id).await?;
        Ok(MemoryRestoreRequest {
            snapshot_id: r.snapshot_id,
            restoration: r.operation_id,
            source: snapshot.source_handle,
            target: r.target.clone(),
            request: target.request,
            manifest: snapshot.snapshot.manifest.ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Conflict,
                    "restoration lost its original public manifest",
                )
            })?,
            reference: snapshot.runtime_reference.ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Conflict,
                    "restoration lost its retained backend reference",
                )
            })?,
        })
    }
    pub(super) async fn admit_restoration(
        &self,
        id: Uuid,
        request: &RestoreSnapshot,
        key: &str,
    ) -> Result<SnapshotRestored, ApiError> {
        if let Some(previous) = self.store.prior_restoration(id, request, key).await? {
            return Ok(previous);
        }
        let snapshot = self.store.snapshot(id).await?;
        let _guard = self
            .lock(snapshot.snapshot.source_sandbox_id)
            .await
            .lock_owned()
            .await;
        if let Some(previous) = self.store.prior_restoration(id, request, key).await? {
            return Ok(previous);
        }
        let profile = self
            .registration
            .profiles
            .iter()
            .find(|p| p.id == request.target.profile)
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::BackendUnavailable,
                    "restoration profile is unavailable",
                )
            })?;
        require_capability(profile, Capability::MemorySnapshot)?;
        goldenhoop_core::validate_create(profile, &request.target)?;
        if !(1..=86400).contains(&request.target.ttl_seconds) {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "restoration lifetime quota exceeded",
            ));
        }
        let driver = self.drivers.get(&profile.id).ok_or_else(|| {
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "restoration driver is unavailable",
            )
        })?;
        let source = self
            .store
            .sandbox(snapshot.snapshot.source_sandbox_id)
            .await?;
        let now = Utc::now();
        let provisional = Sandbox {
            id: Uuid::new_v4(),
            profile: request.target.profile.clone(),
            image: request.target.image.clone(),
            resources: request.target.resources.clone(),
            state: SandboxState::Pending,
            desired_state: DesiredState::Running,
            cleanup: CleanupState::Pending,
            created_at: now,
            expires_at: now
                .checked_add_signed(chrono::Duration::seconds(
                    i64::try_from(request.target.ttl_seconds).map_err(|_| {
                        ApiError::new(ErrorCode::InvalidRequest, "restoration TTL is too large")
                    })?,
                ))
                .ok_or_else(|| {
                    ApiError::new(ErrorCode::InvalidRequest, "restoration TTL is too large")
                })?,
            observed_at: None,
            metadata: request.target.metadata.clone(),
            reason: None,
        };
        let preflight = MemoryRestoreRequest {
            snapshot_id: id,
            restoration: Uuid::new_v4(),
            source: snapshot.source_handle,
            target: provisional,
            request: request.target.clone(),
            manifest: snapshot.snapshot.manifest.ok_or_else(|| {
                ApiError::new(ErrorCode::InvalidState, "snapshot has no Ready manifest")
            })?,
            reference: snapshot.runtime_reference.ok_or_else(|| {
                ApiError::new(ErrorCode::InvalidState, "snapshot has no retained content")
            })?,
        };
        if source.sandbox.resources != request.target.resources {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "memory continuation resources must match the source",
            ));
        }
        driver.validate_memory_restore(&preflight)?;
        self.store
            .create_restoration(profile, id, request, key)
            .await
    }
    pub(super) async fn collect_restoration(
        &self,
        id: Uuid,
        driver: &dyn WorkerDriver,
    ) -> Result<(), ApiError> {
        let Some(r) = self.store.restoration(id).await? else {
            return Ok(());
        };
        if !r.collected {
            driver
                .collect_memory_restore(&self.restoration_request(&r).await?)
                .await?;
            self.store.restoration_collected(id).await?;
        }
        Ok(())
    }
    pub(super) async fn reconcile_restoration(
        &self,
        stored: StoredSandbox,
        r: StoredRestoration,
        driver: &dyn WorkerDriver,
    ) -> Result<(), ApiError> {
        let id = stored.sandbox.id;
        let op = self.store.operation(r.operation_id).await?;
        let failed =
            stored.sandbox.state == SandboxState::Failed || op.state == OperationState::Failed;
        if r.collected
            || failed
            || self.store.effective_desired(id).await? == DesiredState::Terminated
        {
            return self
                .stop(
                    stored,
                    driver,
                    "restoration target closed before activation",
                    if failed {
                        ExecutionState::Failed
                    } else {
                        ExecutionState::Cancelled
                    },
                )
                .await;
        }
        let result: Result<(), ApiError> = async {
            self.store.begin_restoration(id).await?;
            self.save(
                stored.clone(),
                SandboxState::Starting,
                CleanupState::Pending,
                None,
            )
            .await?;
            let request = self.restoration_request(&r).await?;
            let handle = match &r.handle {
                Some(handle) => handle.clone(),
                None => driver.restore_memory(&request).await?,
            };
            self.store.bind_restoration_handle(id, &handle).await?;
            if driver.inspect(&handle).await?.state != ObservedState::Running {
                return Err(ApiError::new(
                    ErrorCode::InvalidState,
                    "restoration target has no observed running generation",
                ));
            }
            for execution in self.store.execution_work(id).await? {
                let binding = self
                    .store
                    .restored_execution_binding(execution.execution.id)
                    .await?
                    .ok_or_else(|| {
                        ApiError::new(
                            ErrorCode::Conflict,
                            "restoration execution has no retained binding",
                        )
                    })?;
                let AgentResponse::Execution(actual) = self
                    .rpc(
                        driver,
                        &handle,
                        &AgentRequest::Inspect {
                            id: binding.agent_id,
                        },
                    )
                    .await?
                else {
                    return Err(ApiError::new(
                        ErrorCode::BackendUnavailable,
                        "retained execution inspection reply differs",
                    ));
                };
                super::executions::normalize(actual, &execution, Some(&binding))?;
            }
            self.store.activate_restoration(id, &handle).await
        }
        .await;
        if let Err(error) = result {
            if matches!(
                error.code,
                ErrorCode::InvalidRequest
                    | ErrorCode::InvalidState
                    | ErrorCode::UnsupportedCapability
                    | ErrorCode::Forbidden
                    | ErrorCode::Conflict
                    | ErrorCode::NotFound
            ) {
                self.store.restoration_failed(id,&ApiError::new(error.code,"restoration refused or retained execution binding is absent; target requires collection")).await?;
                return self
                    .stop(
                        self.store.sandbox(id).await?,
                        driver,
                        "restoration failed without replaying retained commands",
                        ExecutionState::Failed,
                    )
                    .await;
            }
            let reason = if error.code == ErrorCode::QuotaExceeded {
                "restoration capacity is temporarily reserved; retry the original target and retain its references"
            } else {
                "restoration transport is unconfirmed; retain the original target and references"
            };
            self.save(
                self.store.sandbox(id).await?,
                SandboxState::Unknown,
                CleanupState::Unknown,
                Some(reason.into()),
            )
            .await?;
            report("restoration_reconciliation_unconfirmed", &error);
        }
        Ok(())
    }
}
