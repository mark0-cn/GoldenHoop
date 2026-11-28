//! Durable snapshot intent and source admission fence. Runtime effects and
//! physical collection are independently observed by a backend worker.
use super::*;
mod collection;

/// Private worker metadata. Only `snapshot` is a public resource.
#[derive(Debug, Clone)]
pub struct StoredSnapshot {
    pub snapshot: Snapshot,
    pub request: CreateSnapshot,
    pub source_handle: RuntimeHandle,
    pub create_operation: Uuid,
    pub dispatched: bool,
    pub source_fenced: bool,
    pub source_collected: bool,
    pub runtime_reference: Option<serde_json::Value>,
    pub capture_refusal: Option<serde_json::Value>,
    pub collect_operation: Option<Uuid>,
}
/// A first dispatch and an uncertain prior dispatch are deliberately distinct.
/// An existing dispatch is queried/reconciled, never treated as a fresh permit.
#[derive(Debug, Clone)]
pub struct SnapshotCaptureDispatch {
    pub snapshot: StoredSnapshot,
    pub first_dispatch: bool,
}
/// The source's durable admission view. A later restore must independently bind
/// these IDs to actual retained agent state and new public IDs; never Start.
#[derive(Debug, Clone)]
pub struct SnapshotExecutionCandidate {
    pub execution: Execution,
    pub spec: CommandSpec,
    pub cursor: u64,
}

fn row(value: &sqlx::sqlite::SqliteRow) -> Result<StoredSnapshot, ApiError> {
    Ok(StoredSnapshot {
        snapshot: decode(value.try_get("payload").map_err(db)?)?,
        request: decode(value.try_get("request").map_err(db)?)?,
        source_handle: decode(value.try_get("source_handle").map_err(db)?)?,
        create_operation: Uuid::parse_str(value.try_get("create_operation").map_err(db)?)
            .map_err(|_| internal())?,
        dispatched: value.try_get("dispatched").map_err(db)?,
        source_fenced: value.try_get("source_fenced").map_err(db)?,
        source_collected: value.try_get("source_collected").map_err(db)?,
        runtime_reference: value
            .try_get::<Option<&str>, _>("runtime_reference")
            .map_err(db)?
            .map(decode)
            .transpose()?,
        capture_refusal: value
            .try_get::<Option<&str>, _>("capture_refusal")
            .map_err(db)?
            .map(decode)
            .transpose()?,
        collect_operation: value
            .try_get::<Option<&str>, _>("collect_operation")
            .map_err(db)?
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| internal())?,
    })
}
async fn load(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<StoredSnapshot, ApiError> {
    row(&sqlx::query("SELECT * FROM snapshots WHERE id=?")
        .bind(id.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("snapshot"))?)
}
async fn save(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    record: &StoredSnapshot,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE snapshots SET state=?,payload=?,dispatched=?,source_fenced=?,runtime_reference=?,capture_refusal=?,collect_operation=? WHERE id=?")
        .bind(tag(&record.snapshot.state)?).bind(encode(&record.snapshot)?).bind(record.dispatched).bind(record.source_fenced)
        .bind(record.runtime_reference.as_ref().map(encode).transpose()?).bind(record.capture_refusal.as_ref().map(encode).transpose()?).bind(record.collect_operation.map(|id|id.to_string())).bind(record.snapshot.id.to_string()).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
async fn operation(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    state: OperationState,
    error: Option<ApiError>,
) -> Result<(), ApiError> {
    let payload: String =
        sqlx::query_scalar("SELECT payload FROM operations WHERE id=? AND kind='snapshot_capture'")
            .bind(id.to_string())
            .fetch_one(&mut **tx)
            .await
            .map_err(db)?;
    let mut value: Operation = decode(&payload)?;
    if value.state.is_terminal() {
        return Ok(());
    }
    value.state = state;
    value.finished_at = state.is_terminal().then(Utc::now);
    value.error = error;
    sqlx::query("UPDATE operations SET state=?,payload=? WHERE id=?")
        .bind(tag(&state)?)
        .bind(encode(&value)?)
        .bind(id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
pub(super) async fn require_dispatch(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    sandbox: Uuid,
) -> Result<(), ApiError> {
    let fenced: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM snapshots WHERE source_sandbox_id=? AND source_fenced=1)",
    )
    .bind(sandbox.to_string())
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if fenced {
        return Err(ApiError::new(
            ErrorCode::InvalidState,
            "sandbox is held by a snapshot capture",
        ));
    }
    Ok(())
}
fn same_handle(left: &RuntimeHandle, right: &RuntimeHandle) -> bool {
    left.sandbox_id == right.sandbox_id
        && left.profile == right.profile
        && left.backend_ref == right.backend_ref
}
pub(super) async fn observe_source(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    previous: &StoredSandbox,
    reported: &StoredSandbox,
) -> Result<(), ApiError> {
    let rows = sqlx::query("SELECT * FROM snapshots WHERE source_sandbox_id=? AND source_fenced=1")
        .bind(previous.sandbox.id.to_string())
        .fetch_all(&mut **tx)
        .await
        .map_err(db)?;
    for value in rows {
        let stored = row(&value)?;
        if !previous
            .handle
            .as_ref()
            .is_some_and(|h| same_handle(h, &stored.source_handle))
            || reported
                .handle
                .as_ref()
                .is_some_and(|h| !same_handle(h, &stored.source_handle))
            || reported.handle.is_none() && reported.sandbox.cleanup != CleanupState::Complete
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "captured source runtime identity cannot be replaced or erased before collection",
            ));
        }
        if reported.sandbox.cleanup == CleanupState::Complete {
            sqlx::query("UPDATE snapshots SET source_fenced=0,source_collected=1 WHERE id=?")
                .bind(stored.snapshot.id.to_string())
                .execute(&mut **tx)
                .await
                .map_err(db)?;
        }
    }
    Ok(())
}

impl Store {
    /// Read-only idempotent retry, including when the source/backend is no
    /// longer available. A miss grants no dispatch or resource reservation.
    pub async fn prior_snapshot_request(
        &self,
        source: Uuid,
        request: &CreateSnapshot,
        key: &str,
    ) -> Result<Option<SnapshotCreated>, ApiError> {
        goldenhoop_core::validate_idempotency_key(key)?;
        let value = sqlx::query(
            "SELECT fingerprint,resource_id FROM idempotency WHERE scope=? AND client_key=?",
        )
        .bind(format!("sandboxes:{source}:snapshots:create"))
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        let Some(value) = value else {
            return Ok(None);
        };
        if value.try_get::<&str, _>("fingerprint").map_err(db)? != fingerprint(request)? {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "idempotency key has different request content",
            ));
        }
        let id =
            Uuid::parse_str(value.try_get("resource_id").map_err(db)?).map_err(|_| internal())?;
        self.snapshot_created(id).await.map(Some)
    }
    pub async fn snapshot(&self, id: Uuid) -> Result<StoredSnapshot, ApiError> {
        row(&sqlx::query("SELECT * FROM snapshots WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("snapshot"))?)
    }
    pub async fn snapshot_created(&self, id: Uuid) -> Result<SnapshotCreated, ApiError> {
        let stored = self.snapshot(id).await?;
        Ok(SnapshotCreated {
            snapshot: stored.snapshot,
            operation: self.operation(stored.create_operation).await?,
        })
    }
    pub async fn snapshot_source_fenced(&self, sandbox: Uuid) -> Result<bool, ApiError> {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM snapshots WHERE source_sandbox_id=? AND source_fenced=1)",
        )
        .bind(sandbox.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(db)
    }
    pub async fn require_snapshot_dispatch(&self, sandbox: Uuid) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        require_dispatch(&mut tx, sandbox).await?;
        tx.commit().await.map_err(db)
    }
    pub async fn create_snapshot(
        &self,
        profile: &RuntimeProfile,
        source: Uuid,
        request: &CreateSnapshot,
        key: &str,
    ) -> Result<SnapshotCreated, ApiError> {
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(existing) = reserve(
            &mut tx,
            &format!("sandboxes:{source}:snapshots:create"),
            key,
            &fingerprint(request)?,
            id,
        )
        .await?
        {
            tx.commit().await.map_err(db)?;
            return self.snapshot_created(existing).await;
        }
        if request.kind != SnapshotKind::MemoryAndDisk {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "this capture path requires explicit memory_and_disk kind",
            ));
        }
        goldenhoop_core::require_capability(profile, Capability::MemorySnapshot)?;
        if profile.availability != Availability::Available {
            return Err(ApiError::new(
                ErrorCode::BackendUnavailable,
                "snapshot runtime profile has no current availability proof",
            ));
        }
        super::isolated::require_work(&mut tx, source, Capability::MemorySnapshot).await?;
        let original = super::isolated::source(&mut tx, source).await?;
        if original.sandbox.profile != profile.id || !original.ever_running {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "snapshot source has no matching observed runtime",
            ));
        }
        let handle = original.handle.ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidState,
                "snapshot source runtime handle is absent",
            )
        })?;
        if handle.sandbox_id != source
            || handle.profile != profile.id
            || handle.backend_ref.is_empty()
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "snapshot source runtime handle differs",
            ));
        }
        // Initial native memory capture supports commands. Native PTY/context/
        // child profiles remain unavailable and cannot silently lose their state.
        let scope = super::isolated::scope(&mut tx, source).await?;
        let children: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sandbox_scopes s JOIN sandboxes b ON b.id=s.sandbox_id WHERE s.parent_id=? AND b.cleanup!='complete')")
                .bind(source.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        let contexts: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM code_contexts WHERE sandbox_id=? AND cleanup!='complete')",
        )
        .bind(source.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        let sessions:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions s JOIN executions e ON e.id=s.execution_id WHERE e.sandbox_id=? AND e.state NOT IN('succeeded','failed','cancelled','timed_out'))").bind(source.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
        if scope.parent_id.is_some()
            || scope.child_budget.is_some()
            || children
            || contexts
            || sessions
        {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "snapshot source has state whose continuation is not implemented by this capture path",
            ));
        }
        let unsettled:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM executions WHERE sandbox_id=? AND (state IN('pending','unknown') OR (state='running' AND (json_extract(payload,'$.started_at') IS NULL OR cancel_requested=1))))").bind(source.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
        if unsettled {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "snapshot capture requires settled command dispatch and cancellation",
            ));
        }
        let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM snapshots WHERE NOT(state IN('collected','failed') AND json_extract(payload,'$.cleanup')='complete')").fetch_one(&mut *tx).await.map_err(db)?;
        if count >= 256 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "installation snapshot history limit reached",
            ));
        }
        let now = Utc::now();
        let snapshot = Snapshot {
            id,
            source_sandbox_id: source,
            kind: request.kind,
            state: SnapshotState::Pending,
            cleanup: CleanupState::Pending,
            created_at: now,
            observed_at: None,
            manifest: None,
            error: None,
        };
        let op = Operation {
            id: Uuid::new_v4(),
            resource_id: id,
            state: OperationState::Pending,
            created_at: now,
            finished_at: None,
            error: None,
        };
        sqlx::query("INSERT INTO snapshots(id,source_sandbox_id,state,payload,request,source_handle,create_operation) VALUES(?,?,'pending',?,?,?,?)")
            .bind(id.to_string()).bind(source.to_string()).bind(encode(&snapshot)?).bind(encode(request)?).bind(encode(&handle)?).bind(op.id.to_string()).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("INSERT INTO operations(id,resource_id,kind,state,payload) VALUES(?,?,'snapshot_capture','pending',?)").bind(op.id.to_string()).bind(id.to_string()).bind(encode(&op)?).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("INSERT INTO snapshot_execution_candidates(snapshot_id,source_execution_id,payload,spec,cursor) SELECT ?,id,payload,spec,cursor FROM executions WHERE sandbox_id=? AND state='running'")
            .bind(id.to_string()).bind(source.to_string()).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(SnapshotCreated {
            snapshot,
            operation: op,
        })
    }
    pub async fn begin_snapshot_capture(
        &self,
        id: Uuid,
        source: &RuntimeHandle,
    ) -> Result<SnapshotCaptureDispatch, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        if !same_handle(source, &stored.source_handle)
            || !stored.source_fenced && !stored.dispatched
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "snapshot dispatch differs from its original source",
            ));
        }
        if !matches!(
            stored.snapshot.state,
            SnapshotState::Pending | SnapshotState::Capturing | SnapshotState::Unknown
        ) {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "snapshot capture is already settled",
            ));
        }
        let current = super::isolated::source(&mut tx, source.sandbox_id).await?;
        if !stored.source_collected
            && !current
                .handle
                .as_ref()
                .is_some_and(|h| same_handle(h, source))
            || (!stored.dispatched
                && (current.sandbox.desired_state != DesiredState::Running
                    || current.sandbox.state != SandboxState::Running
                    || goldenhoop_core::expired(&current.sandbox, Utc::now())))
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "snapshot source changed before dispatch",
            ));
        }
        let first = !stored.dispatched;
        if first {
            stored.dispatched = true;
            stored.snapshot.state = SnapshotState::Capturing;
            stored.snapshot.observed_at = Some(Utc::now());
            save(&mut tx, &stored).await?;
            operation(
                &mut tx,
                stored.create_operation,
                OperationState::Running,
                None,
            )
            .await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(SnapshotCaptureDispatch {
            snapshot: stored,
            first_dispatch: first,
        })
    }
    /// A definitive refusal before the durable dispatch marker has no external
    /// capture authority. An uncertain dispatched call must use Unknown instead.
    pub async fn fail_unstarted_snapshot(
        &self,
        id: Uuid,
        error: &ApiError,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        if stored.dispatched || stored.snapshot.state != SnapshotState::Pending {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "dispatched snapshot cannot be declared effect-free",
            ));
        }
        stored.snapshot.state = SnapshotState::Failed;
        stored.snapshot.cleanup = CleanupState::Complete;
        stored.snapshot.error = Some(error.clone());
        stored.snapshot.observed_at = Some(Utc::now());
        stored.source_fenced = false;
        save(&mut tx, &stored).await?;
        operation(
            &mut tx,
            stored.create_operation,
            OperationState::Failed,
            Some(error.clone()),
        )
        .await?;
        tx.commit().await.map_err(db)
    }
    pub async fn snapshot_capture_unknown(
        &self,
        id: Uuid,
        error: &ApiError,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        if !stored.dispatched
            || stored.capture_refusal.is_some()
            || !matches!(
                stored.snapshot.state,
                SnapshotState::Capturing | SnapshotState::Unknown
            )
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "snapshot is not an uncertain capture",
            ));
        }
        stored.snapshot.state = SnapshotState::Unknown;
        stored.snapshot.cleanup = CleanupState::Unknown;
        stored.snapshot.error = Some(error.clone());
        stored.snapshot.observed_at = Some(Utc::now());
        save(&mut tx, &stored).await?;
        tx.commit().await.map_err(db)
    }
    /// Store a validated backend reference. The worker must obtain actual Ready
    /// evidence; this transaction checks identity and never reads host paths.
    pub async fn snapshot_capture_ready(
        &self,
        id: Uuid,
        source: &RuntimeHandle,
        manifest: &SnapshotManifest,
        reference: &serde_json::Value,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        let original = super::isolated::source(&mut tx, stored.snapshot.source_sandbox_id).await?;
        if !stored.dispatched
            || stored.capture_refusal.is_some()
            || !same_handle(source, &stored.source_handle)
            || manifest.format_version != 1
            || manifest.id != id
            || manifest.source_sandbox_id != source.sandbox_id
            || manifest.kind != stored.snapshot.kind
            || manifest.driver != source.profile
            || manifest.image_digest != original.sandbox.image
            || manifest.runtime_version.is_empty()
            || manifest.runtime_version.len() > 64
            || manifest.architecture.is_empty()
            || manifest.architecture.len() > 64
            || manifest.objects.len() != 3
            || ["state", "memory", "disk"].iter().any(|role| {
                !manifest.objects.get(*role).is_some_and(|value| {
                    value.strip_prefix("sha256:").is_some_and(|sha| {
                        sha.len() == 64
                            && sha
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                })
            })
            || !reference.as_object().is_some_and(|r| !r.is_empty())
            || encode(reference)?.len() > 65536
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "Ready snapshot differs from its original capture binding",
            ));
        }
        if stored.snapshot.state == SnapshotState::Ready {
            if stored
                .snapshot
                .manifest
                .as_ref()
                .map(encode)
                .transpose()?
                .as_deref()
                != Some(encode(manifest)?.as_str())
                || stored.runtime_reference.as_ref() != Some(reference)
            {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "Ready snapshot reference is immutable",
                ));
            }
            tx.commit().await.map_err(db)?;
            return Ok(());
        }
        if !matches!(
            stored.snapshot.state,
            SnapshotState::Capturing | SnapshotState::Unknown
        ) {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "snapshot cannot become Ready from this state",
            ));
        }
        stored.snapshot.state = SnapshotState::Ready;
        stored.snapshot.manifest = Some(manifest.clone());
        stored.snapshot.error = None;
        stored.snapshot.observed_at = Some(Utc::now());
        stored.snapshot.cleanup = CleanupState::Pending;
        stored.runtime_reference = Some(reference.clone());
        save(&mut tx, &stored).await?;
        operation(
            &mut tx,
            stored.create_operation,
            OperationState::Succeeded,
            None,
        )
        .await?;
        tx.commit().await.map_err(db)
    }
    pub async fn snapshot_work(&self) -> Result<Vec<StoredSnapshot>, ApiError> {
        sqlx::query("SELECT * FROM snapshots WHERE state IN('pending','capturing','unknown','collecting') OR source_fenced=1 OR (state='failed' AND json_extract(payload,'$.cleanup')!='complete') ORDER BY id LIMIT 256").fetch_all(&self.pool).await.map_err(db)?.iter().map(row).collect()
    }
    /// Only a positively validated durable backend refusal grants this release.
    /// A timeout or NotFound must use Unknown, even if nothing appears allocated.
    pub async fn snapshot_capture_refused(
        &self,
        id: Uuid,
        source: &RuntimeHandle,
        reason: &ApiError,
        receipt: &serde_json::Value,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        if !stored.dispatched
            || !same_handle(source, &stored.source_handle)
            || !receipt.as_object().is_some_and(|o| !o.is_empty())
            || encode(receipt)?.len() > 65536
            || stored.runtime_reference.is_some()
            || stored.snapshot.manifest.is_some()
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "capture refusal differs from its dispatched source binding",
            ));
        }
        if let Some(previous) = &stored.capture_refusal {
            if previous != receipt
                || stored.snapshot.state != SnapshotState::Failed
                || stored.snapshot.cleanup != CleanupState::Complete
                || stored
                    .snapshot
                    .error
                    .as_ref()
                    .map(encode)
                    .transpose()?
                    .as_deref()
                    != Some(encode(reason)?.as_str())
            {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "durable capture refusal is immutable",
                ));
            }
            tx.commit().await.map_err(db)?;
            return Ok(());
        }
        if !matches!(
            stored.snapshot.state,
            SnapshotState::Capturing | SnapshotState::Unknown
        ) {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "snapshot has no uncertain capture to close",
            ));
        }
        stored.snapshot.state = SnapshotState::Failed;
        stored.snapshot.cleanup = CleanupState::Complete;
        stored.snapshot.observed_at = Some(Utc::now());
        stored.snapshot.error = Some(reason.clone());
        stored.capture_refusal = Some(receipt.clone());
        stored.source_fenced = false;
        save(&mut tx, &stored).await?;
        operation(
            &mut tx,
            stored.create_operation,
            OperationState::Failed,
            Some(reason.clone()),
        )
        .await?;
        tx.commit().await.map_err(db)
    }
    /// A positively observed backend failure settles business state while
    /// preserving its independent physical cleanup obligation and source fence.
    pub async fn snapshot_capture_failed(
        &self,
        id: Uuid,
        source: &RuntimeHandle,
        error: &ApiError,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        if !stored.dispatched
            || !same_handle(source, &stored.source_handle)
            || !matches!(
                stored.snapshot.state,
                SnapshotState::Capturing | SnapshotState::Unknown | SnapshotState::Failed
            )
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "backend failure differs from its dispatched capture",
            ));
        }
        if stored.snapshot.state == SnapshotState::Failed {
            tx.commit().await.map_err(db)?;
            return Ok(());
        }
        stored.snapshot.state = SnapshotState::Failed;
        stored.snapshot.cleanup = CleanupState::Pending;
        stored.snapshot.error = Some(error.clone());
        stored.snapshot.observed_at = Some(Utc::now());
        save(&mut tx, &stored).await?;
        operation(
            &mut tx,
            stored.create_operation,
            OperationState::Failed,
            Some(error.clone()),
        )
        .await?;
        tx.commit().await.map_err(db)
    }
    pub async fn snapshot_cleanup_unknown(&self, id: Uuid) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        if stored.snapshot.state != SnapshotState::Failed
            || !stored.dispatched
            || stored.snapshot.cleanup == CleanupState::Complete
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "snapshot has no outstanding failed-capture cleanup",
            ));
        }
        stored.snapshot.cleanup = CleanupState::Unknown;
        stored.snapshot.observed_at = Some(Utc::now());
        save(&mut tx, &stored).await?;
        tx.commit().await.map_err(db)
    }
    /// The worker must supply a source-bound positive backend collection
    /// observation. This also requires the original source's durable collection.
    pub async fn snapshot_capture_collected(
        &self,
        id: Uuid,
        source: &RuntimeHandle,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        if !stored.dispatched
            || !stored.source_collected
            || stored.source_fenced
            || !same_handle(source, &stored.source_handle)
            || stored.snapshot.state != SnapshotState::Failed
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "snapshot collection lacks its original source collection binding",
            ));
        }
        stored.snapshot.cleanup = CleanupState::Complete;
        stored.snapshot.observed_at = Some(Utc::now());
        save(&mut tx, &stored).await?;
        tx.commit().await.map_err(db)
    }
    pub async fn snapshot_execution_candidates(
        &self,
        id: Uuid,
    ) -> Result<Vec<SnapshotExecutionCandidate>, ApiError> {
        let snapshot = self.snapshot(id).await?;
        sqlx::query("SELECT * FROM snapshot_execution_candidates WHERE snapshot_id=? ORDER BY source_execution_id").bind(id.to_string()).fetch_all(&self.pool).await.map_err(db)?.iter().map(|row| {
            let execution:Execution=decode(row.try_get("payload").map_err(db)?)?;
            let stored_id:Uuid=Uuid::parse_str(row.try_get("source_execution_id").map_err(db)?).map_err(|_|internal())?;
            if execution.id!=stored_id || execution.sandbox_id!=snapshot.snapshot.source_sandbox_id || execution.state!=ExecutionState::Running || execution.started_at.is_none() { return Err(internal()); }
            Ok(SnapshotExecutionCandidate{execution,spec:decode(row.try_get("spec").map_err(db)?)?,cursor:row.try_get::<i64,_>("cursor").map_err(db)?.try_into().map_err(|_|internal())?})
        }).collect()
    }
}
