//! One durable target per memory snapshot; retained agent IDs never become Start permits.
use super::*;

#[derive(Debug, Clone)]
pub struct StoredRestoration {
    pub snapshot_id: Uuid,
    pub target: Sandbox,
    pub operation_id: Uuid,
    pub dispatched: bool,
    pub active: bool,
    pub collected: bool,
    pub handle: Option<RuntimeHandle>,
}
#[derive(Debug, Clone)]
pub struct RestoredExecutionBinding {
    pub target_id: Uuid,
    pub source_execution_id: Uuid,
    pub agent_id: Uuid,
    pub agent_sandbox_id: Uuid,
    pub event_offset: u64,
}
fn conflict(message: &str) -> ApiError {
    ApiError::new(ErrorCode::Conflict, message)
}
fn uuid(row: &sqlx::sqlite::SqliteRow, name: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(row.try_get(name).map_err(db)?).map_err(|_| internal())
}
fn row(value: &sqlx::sqlite::SqliteRow) -> Result<StoredRestoration, ApiError> {
    let target: Sandbox = decode(value.try_get("target_payload").map_err(db)?)?;
    if target.id != uuid(value, "target_id")? {
        return Err(internal());
    }
    Ok(StoredRestoration {
        snapshot_id: uuid(value, "snapshot_id")?,
        target,
        operation_id: uuid(value, "operation_id")?,
        dispatched: value.try_get("dispatched").map_err(db)?,
        active: value.try_get("active").map_err(db)?,
        collected: value.try_get("collected").map_err(db)?,
        handle: value
            .try_get::<Option<&str>, _>("runtime_handle")
            .map_err(db)?
            .map(decode)
            .transpose()?,
    })
}
async fn load(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    target: Uuid,
) -> Result<StoredRestoration, ApiError> {
    row(
        &sqlx::query("SELECT * FROM snapshot_restorations WHERE target_id=?")
            .bind(target.to_string())
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("restoration"))?,
    )
}
fn binding(value: &sqlx::sqlite::SqliteRow) -> Result<RestoredExecutionBinding, ApiError> {
    Ok(RestoredExecutionBinding {
        target_id: uuid(value, "target_id")?,
        source_execution_id: uuid(value, "source_execution_id")?,
        agent_id: uuid(value, "agent_id")?,
        agent_sandbox_id: uuid(value, "agent_sandbox_id")?,
        event_offset: value
            .try_get::<i64, _>("event_offset")
            .map_err(db)?
            .try_into()
            .map_err(|_| internal())?,
    })
}
async fn settle(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    r: &StoredRestoration,
    state: OperationState,
    error: Option<ApiError>,
) -> Result<(), ApiError> {
    let value: String = sqlx::query_scalar(
        "SELECT payload FROM operations WHERE id=? AND kind='snapshot_restore' AND resource_id=?",
    )
    .bind(r.operation_id.to_string())
    .bind(r.target.id.to_string())
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    let mut op: Operation = decode(&value)?;
    if op.state.is_terminal() {
        return Ok(());
    }
    op.state = state;
    op.error = error;
    op.finished_at = state.is_terminal().then(Utc::now);
    sqlx::query("UPDATE operations SET state=?,payload=? WHERE id=?")
        .bind(tag(&op.state)?)
        .bind(encode(&op)?)
        .bind(op.id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
fn same(a: &RuntimeHandle, b: &RuntimeHandle) -> bool {
    a.sandbox_id == b.sandbox_id && a.profile == b.profile && a.backend_ref == b.backend_ref
}

pub(super) async fn require_unreferenced(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    snapshot: Uuid,
) -> Result<(), ApiError> {
    let retained: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM snapshot_restorations WHERE snapshot_id=? AND collected=0)",
    )
    .bind(snapshot.to_string())
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if retained {
        return Err(ApiError::new(
            ErrorCode::InvalidState,
            "snapshot content is retained by its original restoration target",
        ));
    }
    Ok(())
}
pub(super) async fn observe(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    stored: &StoredSandbox,
) -> Result<(), ApiError> {
    let Some(value) = sqlx::query("SELECT * FROM snapshot_restorations WHERE target_id=?")
        .bind(stored.sandbox.id.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?
    else {
        return Ok(());
    };
    let r = row(&value)?;
    if stored.sandbox.cleanup == CleanupState::Complete && !r.collected
        || stored.sandbox.state == SandboxState::Running && !r.active
        || r.handle.as_ref().is_some_and(|handle| {
            !r.collected
                && stored
                    .handle
                    .as_ref()
                    .is_none_or(|reported| !same(handle, reported))
        })
        || stored.handle.as_ref().is_some_and(|handle| {
            r.handle
                .as_ref()
                .is_none_or(|original| !same(handle, original))
        })
    {
        return Err(conflict(
            "restored runtime authority requires its original binding and positive collection",
        ));
    }
    Ok(())
}

impl Store {
    pub async fn restoration(&self, target: Uuid) -> Result<Option<StoredRestoration>, ApiError> {
        sqlx::query("SELECT * FROM snapshot_restorations WHERE target_id=?")
            .bind(target.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .as_ref()
            .map(row)
            .transpose()
    }
    pub async fn restored_execution_binding(
        &self,
        id: Uuid,
    ) -> Result<Option<RestoredExecutionBinding>, ApiError> {
        sqlx::query("SELECT * FROM restored_execution_bindings WHERE execution_id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .as_ref()
            .map(binding)
            .transpose()
    }
    pub async fn prior_restoration(
        &self,
        snapshot: Uuid,
        request: &RestoreSnapshot,
        key: &str,
    ) -> Result<Option<SnapshotRestored>, ApiError> {
        match self
            .idempotent_resource(
                &format!("snapshots:{snapshot}:restore"),
                key,
                &fingerprint(request)?,
            )
            .await?
        {
            Some(target) => self.restored(target).await.map(Some),
            None => Ok(None),
        }
    }
    pub async fn restored(&self, target: Uuid) -> Result<SnapshotRestored, ApiError> {
        let r = self
            .restoration(target)
            .await?
            .ok_or_else(|| not_found("restoration"))?;
        let rows=sqlx::query("SELECT b.source_execution_id,e.payload FROM restored_execution_bindings b JOIN executions e ON e.id=b.execution_id WHERE b.target_id=? ORDER BY b.source_execution_id").bind(target.to_string()).fetch_all(&self.pool).await.map_err(db)?;
        let executions = rows
            .iter()
            .map(|r| {
                Ok(RestoredExecution {
                    source_execution_id: uuid(r, "source_execution_id")?,
                    execution: decode(r.try_get("payload").map_err(db)?)?,
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        Ok(SnapshotRestored {
            snapshot_id: r.snapshot_id,
            sandbox: self.sandbox(target).await?.sandbox,
            operation: self.operation(r.operation_id).await?,
            executions,
        })
    }
    pub async fn create_restoration(
        &self,
        profile: &RuntimeProfile,
        snapshot: Uuid,
        request: &RestoreSnapshot,
        key: &str,
    ) -> Result<SnapshotRestored, ApiError> {
        let target = Uuid::new_v4();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(prior) = reserve(
            &mut tx,
            &format!("snapshots:{snapshot}:restore"),
            key,
            &fingerprint(request)?,
            target,
        )
        .await?
        {
            tx.commit().await.map_err(db)?;
            return self.restored(prior).await;
        }
        let original = super::snapshots::load(&mut tx, snapshot).await?;
        let source = super::isolated::source(&mut tx, original.snapshot.source_sandbox_id).await?;
        if original.snapshot.kind != SnapshotKind::MemoryAndDisk
            || original.snapshot.state != SnapshotState::Ready
            || !original.source_collected
            || original.source_fenced
            || original.runtime_reference.is_none()
            || original.snapshot.cleanup != CleanupState::Pending
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "memory restoration requires Ready content and positive original source collection",
            ));
        }
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM snapshot_restorations WHERE snapshot_id=?)",
        )
        .bind(snapshot.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if exists {
            return Err(conflict(
                "memory snapshot already has its single durable restoration target",
            ));
        }
        goldenhoop_core::require_capability(profile, Capability::MemorySnapshot)?;
        goldenhoop_core::validate_create(profile, &request.target)?;
        if profile.availability != Availability::Available {
            return Err(ApiError::new(
                ErrorCode::BackendUnavailable,
                "restoration profile is unavailable",
            ));
        }
        let requested = &request.target;
        if requested.profile != source.sandbox.profile
            || requested.image != source.sandbox.image
            || requested.resources != source.sandbox.resources
            || requested.child_budget.is_some()
            || requested.feature_limit != source.request.feature_limit
            || requested.network != NetworkPolicy::default()
        {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "memory continuation must preserve source image, profile, resources and feature ceiling",
            ));
        }
        if requested.ttl_seconds > 86400 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "restoration lifetime quota exceeded",
            ));
        }
        super::lifecycle::check_quota(&mut tx, &requested.resources).await?;
        let now = Utc::now();
        let created = super::lifecycle::insert_sandbox(
            &mut tx,
            target,
            requested,
            now,
            now + chrono::Duration::seconds(requested.ttl_seconds as i64),
            &requested.resources,
        )
        .await?;
        super::isolated::insert_scope(&mut tx, target, None, requested).await?;
        sqlx::query("UPDATE operations SET kind='snapshot_restore' WHERE id=?")
            .bind(created.operation.id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("INSERT INTO snapshot_restorations(snapshot_id,target_id,operation_id,target_payload) VALUES(?,?,?,?)").bind(snapshot.to_string()).bind(target.to_string()).bind(created.operation.id.to_string()).bind(encode(&created.sandbox)?).execute(&mut *tx).await.map_err(db)?;
        let candidates=sqlx::query("SELECT c.*,b.agent_id,b.agent_sandbox_id,b.event_offset FROM snapshot_execution_candidates c LEFT JOIN restored_execution_bindings b ON b.execution_id=c.source_execution_id WHERE c.snapshot_id=? ORDER BY c.source_execution_id").bind(snapshot.to_string()).fetch_all(&mut *tx).await.map_err(db)?;
        for value in candidates {
            let previous: Execution = decode(value.try_get("payload").map_err(db)?)?;
            let source_id = uuid(&value, "source_execution_id")?;
            if previous.id != source_id
                || previous.sandbox_id != source.sandbox.id
                || previous.state != ExecutionState::Running
                || previous.started_at.is_none()
            {
                return Err(internal());
            }
            let agent_id = value
                .try_get::<Option<&str>, _>("agent_id")
                .map_err(db)?
                .map(|id| Uuid::parse_str(id).map_err(|_| internal()))
                .transpose()?
                .unwrap_or(source_id);
            let agent_sandbox = value
                .try_get::<Option<&str>, _>("agent_sandbox_id")
                .map_err(db)?
                .map(|id| Uuid::parse_str(id).map_err(|_| internal()))
                .transpose()?
                .unwrap_or(source.sandbox.id);
            let offset = value
                .try_get::<i64, _>("cursor")
                .map_err(db)?
                .checked_add(
                    value
                        .try_get::<Option<i64>, _>("event_offset")
                        .map_err(db)?
                        .unwrap_or(0),
                )
                .filter(|n| *n >= 0)
                .ok_or_else(internal)?;
            let execution = Execution {
                id: Uuid::new_v4(),
                sandbox_id: target,
                state: ExecutionState::Unknown,
                created_at: now,
                cleanup: CleanupState::Pending,
                reason: Some("retained execution awaiting authenticated target observation".into()),
                ..previous
            };
            sqlx::query("INSERT INTO executions(id,sandbox_id,state,payload,spec) VALUES(?,?,'unknown',?,?)").bind(execution.id.to_string()).bind(target.to_string()).bind(encode(&execution)?).bind(value.try_get::<&str,_>("spec").map_err(db)?).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("INSERT INTO restored_execution_bindings(execution_id,target_id,source_execution_id,agent_id,agent_sandbox_id,event_offset) VALUES(?,?,?,?,?,?)").bind(execution.id.to_string()).bind(target.to_string()).bind(source_id.to_string()).bind(agent_id.to_string()).bind(agent_sandbox.to_string()).bind(offset).execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        self.restored(target).await
    }
    pub async fn begin_restoration(&self, target: Uuid) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let r = load(&mut tx, target).await?;
        let current = super::isolated::source(&mut tx, target).await?;
        let value: String = sqlx::query_scalar("SELECT payload FROM operations WHERE id=?")
            .bind(r.operation_id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let operation: Operation = decode(&value)?;
        if operation.state.is_terminal() {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "restoration operation already has a terminal decision",
            ));
        }
        if r.collected
            || r.active
            || current.sandbox.desired_state != DesiredState::Running
            || goldenhoop_core::expired(&current.sandbox, Utc::now())
            || matches!(
                current.sandbox.state,
                SandboxState::Failed | SandboxState::Terminated
            )
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "restoration target is no longer accepting dispatch",
            ));
        }
        sqlx::query("UPDATE snapshot_restorations SET dispatched=1 WHERE target_id=?")
            .bind(target.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        settle(&mut tx, &r, OperationState::Running, None).await?;
        tx.commit().await.map_err(db)
    }
    pub async fn bind_restoration_handle(
        &self,
        target: Uuid,
        handle: &RuntimeHandle,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let r = load(&mut tx, target).await?;
        if !r.dispatched
            || r.collected
            || handle.sandbox_id != target
            || handle.profile != r.target.profile
            || handle.backend_ref.is_empty()
            || r.handle.as_ref().is_some_and(|prior| !same(prior, handle))
        {
            return Err(conflict(
                "restoration runtime handle differs from its original target",
            ));
        }
        sqlx::query("UPDATE snapshot_restorations SET runtime_handle=? WHERE target_id=?")
            .bind(encode(handle)?)
            .bind(target.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("UPDATE sandboxes SET handle=? WHERE id=?")
            .bind(encode(handle)?)
            .bind(target.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)
    }
    pub async fn activate_restoration(
        &self,
        target: Uuid,
        handle: &RuntimeHandle,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let r = load(&mut tx, target).await?;
        let mut stored = super::isolated::source(&mut tx, target).await?;
        if !r.dispatched
            || r.collected
            || r.handle.as_ref().is_none_or(|prior| !same(prior, handle))
            || stored.sandbox.desired_state != DesiredState::Running
            || goldenhoop_core::expired(&stored.sandbox, Utc::now())
        {
            return Err(conflict(
                "restoration activation lost its original live target intent",
            ));
        }
        if r.active {
            tx.commit().await.map_err(db)?;
            return Ok(());
        }
        stored.sandbox.state = SandboxState::Running;
        stored.sandbox.cleanup = CleanupState::Pending;
        stored.sandbox.observed_at = Some(Utc::now());
        stored.sandbox.reason = None;
        sqlx::query("UPDATE snapshot_restorations SET active=1 WHERE target_id=?")
            .bind(target.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("UPDATE sandboxes SET state='running',cleanup='pending',ever_running=1,payload=? WHERE id=?").bind(encode(&stored.sandbox)?).bind(target.to_string()).execute(&mut *tx).await.map_err(db)?;
        let rows=sqlx::query("SELECT e.payload FROM executions e JOIN restored_execution_bindings b ON b.execution_id=e.id WHERE b.target_id=?").bind(target.to_string()).fetch_all(&mut *tx).await.map_err(db)?;
        for value in rows {
            let mut e: Execution = decode(value.try_get("payload").map_err(db)?)?;
            e.state = ExecutionState::Running;
            e.reason = None;
            sqlx::query("UPDATE executions SET state='running',payload=? WHERE id=?")
                .bind(encode(&e)?)
                .bind(e.id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        settle(&mut tx, &r, OperationState::Succeeded, None).await?;
        tx.commit().await.map_err(db)
    }
    /// Worker calls this only for undispatched intent or a positive backend close.
    pub async fn restoration_collected(&self, target: Uuid) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        load(&mut tx, target).await?;
        sqlx::query("UPDATE snapshot_restorations SET collected=1,active=0 WHERE target_id=?")
            .bind(target.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)
    }
    pub async fn restoration_failed(&self, target: Uuid, error: &ApiError) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let r = load(&mut tx, target).await?;
        if r.active {
            return Err(conflict(
                "active restoration keeps its original successful operation",
            ));
        }
        settle(&mut tx, &r, OperationState::Failed, Some(error.clone())).await?;
        let mut current = super::isolated::source(&mut tx, target).await?;
        if current.sandbox.cleanup != CleanupState::Complete {
            current.sandbox.state = SandboxState::Failed;
            current.sandbox.reason = Some(error.message.clone());
            sqlx::query("UPDATE sandboxes SET state='failed',payload=? WHERE id=?")
                .bind(encode(&current.sandbox)?)
                .bind(target.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        tx.commit().await.map_err(db)
    }
}
