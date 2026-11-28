//! Deletion is durable intent. It never authorizes destroying the source VM.
use super::*;

async fn collect_operation(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    stored: &StoredSnapshot,
) -> Result<Operation, ApiError> {
    let id = stored.collect_operation.ok_or_else(|| {
        ApiError::new(ErrorCode::InvalidState, "snapshot has no collection intent")
    })?;
    let payload: String = sqlx::query_scalar(
        "SELECT payload FROM operations WHERE id=? AND resource_id=? AND kind='snapshot_collect'",
    )
    .bind(id.to_string())
    .bind(stored.snapshot.id.to_string())
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    decode(&payload)
}
async fn save_operation(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    op: &Operation,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE operations SET state=?,payload=? WHERE id=? AND kind='snapshot_collect'")
        .bind(tag(&op.state)?)
        .bind(encode(op)?)
        .bind(op.id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
fn collecting(stored: &StoredSnapshot, source: &RuntimeHandle) -> Result<(), ApiError> {
    if stored.snapshot.state != SnapshotState::Collecting
        || !same_handle(source, &stored.source_handle)
        || stored.collect_operation.is_none()
        || !stored.dispatched
        || !stored.source_collected
        || stored.source_fenced
    {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "snapshot collection differs from its original collected source",
        ));
    }
    Ok(())
}

impl Store {
    pub async fn list_snapshots(
        &self,
        sandbox: Option<Uuid>,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<SnapshotPage, ApiError> {
        if !(1..=1000).contains(&limit) {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "snapshot page limit must be between 1 and 1000",
            ));
        }
        let rows = sqlx::query("SELECT * FROM snapshots WHERE (? IS NULL OR source_sandbox_id=?) AND id>? ORDER BY id LIMIT ?")
            .bind(sandbox.map(|id|id.to_string())).bind(sandbox.map(|id|id.to_string())).bind(after.map(|id|id.to_string()).unwrap_or_default())
            .bind(i64::from(limit)+1).fetch_all(&self.pool).await.map_err(db)?;
        let mut items = rows
            .iter()
            .map(|r| row(r).map(|s| s.snapshot))
            .collect::<Result<Vec<_>, _>>()?;
        let more = items.len() > limit as usize;
        items.truncate(limit as usize);
        let next_cursor = more.then(|| items.last().map(|s| s.id)).flatten();
        Ok(SnapshotPage { items, next_cursor })
    }
    /// Identify snapshot operations before generic resource UUID lookup. This
    /// keeps their original source authority even if another table shares an ID.
    pub async fn snapshot_operation_source(&self, id: Uuid) -> Result<Option<Uuid>, ApiError> {
        let source: Option<String> = sqlx::query_scalar("SELECT s.source_sandbox_id FROM operations o JOIN snapshots s ON s.id=o.resource_id WHERE o.id=? AND o.kind IN('snapshot_capture','snapshot_collect')")
            .bind(id.to_string()).fetch_optional(&self.pool).await.map_err(db)?;
        source
            .map(|s| Uuid::parse_str(&s).map_err(|_| internal()))
            .transpose()
    }
    pub async fn delete_snapshot(&self, id: Uuid, key: &str) -> Result<Operation, ApiError> {
        let op_id = Uuid::new_v4();
        let scope = format!("snapshots:{id}:delete");
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(previous) = reserve(&mut tx, &scope, key, "delete", op_id).await? {
            tx.commit().await.map_err(db)?;
            return self.operation(previous).await;
        }
        let mut stored = load(&mut tx, id).await?;
        if stored.collect_operation.is_some() {
            let previous = collect_operation(&mut tx, &stored).await?;
            sqlx::query("UPDATE idempotency SET resource_id=? WHERE scope=? AND client_key=?")
                .bind(previous.id.to_string())
                .bind(scope)
                .bind(key)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            tx.commit().await.map_err(db)?;
            return Ok(previous);
        }
        let complete = !stored.dispatched || stored.snapshot.cleanup == CleanupState::Complete;
        if !complete && (!stored.source_collected || stored.source_fenced) {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "memory snapshot deletion requires explicit collection of its original source sandbox",
            ));
        }
        if !stored.dispatched
            && (stored.runtime_reference.is_some() || stored.snapshot.manifest.is_some())
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "undispatched snapshot unexpectedly owns backend content",
            ));
        }
        operation(
            &mut tx,
            stored.create_operation,
            OperationState::Cancelled,
            Some(ApiError::new(
                ErrorCode::Conflict,
                "snapshot capture superseded by deletion",
            )),
        )
        .await?;
        stored.snapshot.state = if complete {
            SnapshotState::Collected
        } else {
            SnapshotState::Collecting
        };
        stored.snapshot.cleanup = if complete {
            CleanupState::Complete
        } else {
            CleanupState::Pending
        };
        stored.snapshot.observed_at = Some(Utc::now());
        stored.collect_operation = Some(op_id);
        if complete {
            stored.source_fenced = false;
            stored.runtime_reference = None;
        }
        let op = Operation {
            id: op_id,
            resource_id: id,
            state: if complete {
                OperationState::Succeeded
            } else {
                OperationState::Pending
            },
            created_at: Utc::now(),
            finished_at: complete.then(Utc::now),
            error: None,
        };
        save(&mut tx, &stored).await?;
        sqlx::query("INSERT INTO operations(id,resource_id,kind,state,payload) VALUES(?,?,'snapshot_collect',?,?)")
            .bind(op_id.to_string()).bind(id.to_string()).bind(tag(&op.state)?).bind(encode(&op)?).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(op)
    }
    pub async fn begin_snapshot_collection(
        &self,
        id: Uuid,
        source: &RuntimeHandle,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let stored = load(&mut tx, id).await?;
        collecting(&stored, source)?;
        let mut op = collect_operation(&mut tx, &stored).await?;
        if op.state.is_terminal() {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "snapshot collection operation is already terminal",
            ));
        }
        op.state = OperationState::Running;
        save_operation(&mut tx, &op).await?;
        tx.commit().await.map_err(db)
    }
    pub async fn snapshot_collection_unknown(
        &self,
        id: Uuid,
        error: &ApiError,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        let source = stored.source_handle.clone();
        collecting(&stored, &source)?;
        let mut op = collect_operation(&mut tx, &stored).await?;
        if op.state.is_terminal() {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "snapshot collection operation is already terminal",
            ));
        }
        stored.snapshot.cleanup = CleanupState::Unknown;
        stored.snapshot.observed_at = Some(Utc::now());
        op.state = OperationState::Running;
        op.error = Some(error.clone());
        save(&mut tx, &stored).await?;
        save_operation(&mut tx, &op).await?;
        tx.commit().await.map_err(db)
    }
    /// Caller supplies positive, source-bound backend collection, or its durable
    /// pre-reservation refusal. Timeout and NotFound never grant this transition.
    pub async fn complete_snapshot_collection(
        &self,
        id: Uuid,
        source: &RuntimeHandle,
        refusal: Option<(&ApiError, &serde_json::Value)>,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        if !same_handle(source, &stored.source_handle) {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "snapshot collection source generation differs",
            ));
        }
        if stored.snapshot.state == SnapshotState::Collected
            && stored.snapshot.cleanup == CleanupState::Complete
        {
            if let Some((_, receipt)) = refusal
                && stored.capture_refusal.as_ref() != Some(receipt)
            {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "snapshot collection refusal receipt differs",
                ));
            }
            tx.commit().await.map_err(db)?;
            return Ok(());
        }
        collecting(&stored, source)?;
        if let Some((_, receipt)) = refusal {
            if !receipt.as_object().is_some_and(|o| !o.is_empty())
                || encode(receipt)?.len() > 65536
                || stored.runtime_reference.is_some()
                || stored.snapshot.manifest.is_some()
                || stored
                    .capture_refusal
                    .as_ref()
                    .is_some_and(|previous| previous != receipt)
            {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "capture refusal contradicts snapshot collection content",
                ));
            }
            stored.capture_refusal = Some(receipt.clone());
        }
        let mut op = collect_operation(&mut tx, &stored).await?;
        if op.state.is_terminal() {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "snapshot collection operation is already terminal",
            ));
        }
        stored.snapshot.state = SnapshotState::Collected;
        stored.snapshot.cleanup = CleanupState::Complete;
        stored.snapshot.observed_at = Some(Utc::now());
        stored.runtime_reference = None;
        op.state = OperationState::Succeeded;
        op.finished_at = Some(Utc::now());
        op.error = None;
        save(&mut tx, &stored).await?;
        save_operation(&mut tx, &op).await?;
        tx.commit().await.map_err(db)
    }
}
