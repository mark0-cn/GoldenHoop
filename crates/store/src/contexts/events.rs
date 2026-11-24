use super::*;
use serde_json::json;

fn invalid(message: &str) -> ApiError {
    ApiError::new(ErrorCode::InvalidState, message)
}
async fn emit(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    cursor: &mut u64,
    context: Uuid,
    run: Option<Uuid>,
    kind: CodeContextEventKind,
    data: serde_json::Value,
    time: DateTime<Utc>,
) -> Result<(), ApiError> {
    *cursor = cursor
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(internal)?;
    let event = CodeContextEvent {
        sequence: *cursor,
        context_id: context,
        run_id: run,
        timestamp: time,
        kind,
        data,
    };
    sqlx::query("INSERT INTO code_context_events(context_id,sequence,run_id,kind,payload) VALUES(?,?,?,?,?)")
        .bind(context.to_string()).bind(*cursor as i64).bind(run.map(|id|id.to_string())).bind(tag(&kind)?).bind(encode(&event)?)
        .execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
async fn save_run(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    run: &CodeRun,
    settled: bool,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE code_runs SET state=?,payload=?,settled=? WHERE id=?")
        .bind(tag(&run.state)?)
        .bind(encode(run)?)
        .bind(settled)
        .bind(run.id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
async fn run_record(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    context: Uuid,
    id: Uuid,
) -> Result<sqlx::sqlite::SqliteRow, ApiError> {
    sqlx::query("SELECT * FROM code_runs WHERE context_id=? AND id=?")
        .bind(context.to_string())
        .bind(id.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?
        .ok_or_else(|| invalid("context event refers to an unknown run"))
}
fn proposal(raw: &serde_json::Value, stored: &StoredCodeRun) -> Result<CodeRun, ApiError> {
    let mut value: CodeRun = serde_json::from_value(raw.clone())
        .map_err(|_| invalid("invalid code-run event record"))?;
    if value.id != stored.run.id
        || value.context_id != stored.run.context_id
        || value.started_at != stored.run.started_at
    {
        return Err(invalid(
            "code-run event identity or start observation differs",
        ));
    }
    value.created_at = stored.run.created_at;
    value.output_truncated |= stored.run.output_truncated;
    if value
        .reason
        .as_ref()
        .is_some_and(|reason| reason.len() > 4096)
    {
        return Err(invalid("code-run reason exceeds limit"));
    }
    if value.finished_at.is_none()
        || value
            .started_at
            .zip(value.finished_at)
            .is_some_and(|(start, end)| start > end)
    {
        return Err(invalid("completed code run lacks valid timestamps"));
    }
    let valid = match value.state {
        CodeRunState::KernelSucceeded => {
            value.started_at.is_some() && value.kernel_status.as_deref() == Some("ok")
        }
        CodeRunState::KernelFailed => {
            value.started_at.is_some() && value.kernel_status.as_deref() == Some("error")
        }
        CodeRunState::Cancelled | CodeRunState::TimedOut | CodeRunState::Unknown => {
            value.kernel_status.is_none()
        }
        _ => false,
    };
    if !valid {
        return Err(invalid(
            "code completion is not a matching kernel/cancellation observation",
        ));
    }
    Ok(value)
}
async fn settle_runs(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    context: &CodeContext,
    cursor: &mut u64,
    time: DateTime<Utc>,
    reason: &str,
) -> Result<(), ApiError> {
    let rows = sqlx::query("SELECT * FROM code_runs WHERE context_id=? AND settled=0 ORDER BY id")
        .bind(context.id.to_string())
        .fetch_all(&mut **tx)
        .await
        .map_err(db)?;
    for row in rows {
        let stored = run_row(&row)?;
        let pending: Option<String> = row.try_get("pending_result").map_err(db)?;
        let mut run = if let Some(pending) = pending {
            decode::<CodeRun>(&pending)?
        } else {
            let mut run = stored.run.clone();
            run.state = if stored.cancel_requested || !stored.dispatched {
                CodeRunState::Cancelled
            } else {
                CodeRunState::Unknown
            };
            run.finished_at = Some(time);
            run.kernel_status = None;
            run.reason = Some(reason.into());
            run
        };
        if matches!(
            run.state,
            CodeRunState::KernelSucceeded | CodeRunState::KernelFailed
        ) && (stored.cancel_requested
            || context.desired_state == CodeContextDesiredState::Closed)
        {
            emit(
                tx,
                cursor,
                context.id,
                Some(run.id),
                CodeContextEventKind::Diagnostic,
                json!({"reason":"kernel_result_after_close_intent","reported":run}),
                time,
            )
            .await?;
            run.state = CodeRunState::Cancelled;
            run.kernel_status = None;
            run.reason =
                Some("late kernel result discarded after close intent; context collected".into());
        }
        run.output_truncated |= stored.run.output_truncated;
        if !matches!(
            run.state,
            CodeRunState::KernelSucceeded | CodeRunState::KernelFailed
        ) {
            run.finished_at = Some(time);
        }
        save_run(tx, &run, true).await?;
        emit(
            tx,
            cursor,
            context.id,
            Some(run.id),
            CodeContextEventKind::RunCompleted,
            json!(run),
            time,
        )
        .await?;
    }
    Ok(())
}

impl Store {
    pub async fn code_context_events(
        &self,
        id: Uuid,
        after: u64,
    ) -> Result<Vec<CodeContextEvent>, ApiError> {
        let after = i64::try_from(after).map_err(|_| invalid("context cursor exceeds limit"))?;
        let current: i64 = sqlx::query_scalar("SELECT event_cursor FROM code_contexts WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("code context"))?;
        if after > current {
            return Err(invalid("context cursor is ahead of durable events"));
        }
        sqlx::query("SELECT payload FROM code_context_events WHERE context_id=? AND sequence>? ORDER BY sequence LIMIT 256")
            .bind(id.to_string()).bind(after).fetch_all(&self.pool).await.map_err(db)?.iter().map(|row|decode(row.try_get("payload").map_err(db)?)).collect()
    }

    /// Apply agent events and advance their acknowledgement atomically. Public
    /// cursors are independent: cancellation results await confirmed collection.
    pub async fn append_code_context_events(
        &self,
        id: Uuid,
        events: &[CodeContextEvent],
    ) -> Result<(), ApiError> {
        if events.len() > 256 {
            return Err(invalid("context event batch exceeds limit"));
        }
        let mut bytes = 0usize;
        for event in events {
            let size = encode(event)?.len();
            if size > 2 * 1024 * 1024 + 16 * 1024 {
                return Err(invalid("context event exceeds size limit"));
            }
            bytes = bytes.checked_add(size).ok_or_else(internal)?;
        }
        if bytes > 24 * 1024 * 1024 {
            return Err(invalid("context event batch exceeds byte limit"));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        let mut cursor: u64 =
            sqlx::query_scalar::<_, i64>("SELECT event_cursor FROM code_contexts WHERE id=?")
                .bind(id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?
                .try_into()
                .map_err(|_| internal())?;
        for event in events {
            if event.context_id != id || event.sequence == 0 || event.sequence > i64::MAX as u64 {
                return Err(invalid("context event identity/sequence is invalid"));
            }
            let hash = fingerprint(event)?;
            if event.sequence <= stored.cursor {
                let existing:Option<String>=sqlx::query_scalar("SELECT fingerprint FROM code_context_sources WHERE context_id=? AND sequence=?")
                    .bind(id.to_string()).bind(event.sequence as i64).fetch_optional(&mut *tx).await.map_err(db)?;
                if existing.as_deref() != Some(&hash) {
                    return Err(ApiError::new(
                        ErrorCode::Conflict,
                        "context event sequence has different content",
                    ));
                }
                continue;
            }
            if event.sequence != stored.cursor + 1
                || stored.context.cleanup == CleanupState::Complete
                || !stored.dispatched
            {
                return Err(invalid(
                    "context event has a gap or belongs to a retired/undispatched context",
                ));
            }
            match event.kind {
                CodeContextEventKind::Ready => {
                    let observed: CodeContext = serde_json::from_value(event.data.clone())
                        .map_err(|_| invalid("invalid context readiness record"))?;
                    if stored.context.state != CodeContextState::Starting
                        || stored.context.cleanup != CleanupState::Pending
                        || event.run_id.is_some()
                        || observed.id != id
                        || fingerprint(&observed.spec)? != fingerprint(&stored.context.spec)?
                        || observed.state != CodeContextState::Ready
                        || observed.cleanup != CleanupState::Pending
                        || observed.ready_at.is_none()
                        || observed.finished_at.is_some()
                        || observed
                            .kernel_info
                            .as_ref()
                            .is_none_or(|info| !info.is_object())
                        || stored.ever_ready
                    {
                        return Err(invalid("context readiness observation is invalid"));
                    }
                    if encode(&observed.kernel_info)?.len() > 16 * 1024 {
                        return Err(invalid("kernel info exceeds limit"));
                    }
                    stored.context.state = CodeContextState::Ready;
                    stored.context.ready_at = observed.ready_at;
                    stored.context.kernel_info = observed.kernel_info;
                    stored.ever_ready = true;
                    emit(
                        &mut tx,
                        &mut cursor,
                        id,
                        None,
                        event.kind,
                        json!(stored.context),
                        event.timestamp,
                    )
                    .await?;
                }
                CodeContextEventKind::RunStarted => {
                    let run_id = event
                        .run_id
                        .ok_or_else(|| invalid("run start lacks run identity"))?;
                    let row = run_record(&mut tx, id, run_id).await?;
                    let previous = run_row(&row)?;
                    let mut run: CodeRun = serde_json::from_value(event.data.clone())
                        .map_err(|_| invalid("invalid code start record"))?;
                    if !stored.ever_ready
                        || !previous.dispatched
                        || previous.run.state != CodeRunState::Pending
                        || row.try_get::<bool, _>("settled").map_err(db)?
                        || run.id != run_id
                        || run.context_id != id
                        || run.state != CodeRunState::Running
                        || run.started_at.is_none()
                        || run.finished_at.is_some()
                        || run.kernel_status.is_some()
                    {
                        return Err(invalid("code start has invalid identity or state"));
                    }
                    run.created_at = previous.run.created_at;
                    save_run(&mut tx, &run, false).await?;
                    emit(
                        &mut tx,
                        &mut cursor,
                        id,
                        Some(run_id),
                        event.kind,
                        json!(run),
                        event.timestamp,
                    )
                    .await?;
                }
                CodeContextEventKind::RunCompleted => {
                    let run_id = event
                        .run_id
                        .ok_or_else(|| invalid("run completion lacks run identity"))?;
                    let row = run_record(&mut tx, id, run_id).await?;
                    let previous = run_row(&row)?;
                    if row.try_get::<bool, _>("settled").map_err(db)?
                        || row
                            .try_get::<Option<String>, _>("pending_result")
                            .map_err(db)?
                            .is_some()
                        || !previous.dispatched
                    {
                        return Err(invalid(
                            "completed/undispatched code run cannot accept a result",
                        ));
                    }
                    let run = proposal(&event.data, &previous)?;
                    if matches!(
                        run.state,
                        CodeRunState::KernelSucceeded | CodeRunState::KernelFailed
                    ) && !previous.cancel_requested
                        && stored.context.desired_state == CodeContextDesiredState::Open
                    {
                        save_run(&mut tx, &run, true).await?;
                        emit(
                            &mut tx,
                            &mut cursor,
                            id,
                            Some(run_id),
                            event.kind,
                            json!(run),
                            event.timestamp,
                        )
                        .await?;
                    } else {
                        sqlx::query("UPDATE code_runs SET pending_result=? WHERE id=?")
                            .bind(encode(&run)?)
                            .bind(run_id.to_string())
                            .execute(&mut *tx)
                            .await
                            .map_err(db)?;
                    }
                }
                CodeContextEventKind::Closed => {
                    let observed: CodeContext = serde_json::from_value(event.data.clone())
                        .map_err(|_| invalid("invalid context close record"))?;
                    if event.run_id.is_some()
                        || observed.id != id
                        || fingerprint(&observed.spec)? != fingerprint(&stored.context.spec)?
                        || observed.finished_at.is_none()
                        || observed.ready_at != stored.context.ready_at
                        || fingerprint(&observed.kernel_info)?
                            != fingerprint(&stored.context.kernel_info)?
                        || observed
                            .reason
                            .as_ref()
                            .is_some_and(|reason| reason.len() > 4096)
                    {
                        return Err(invalid("context close identity/history is invalid"));
                    }
                    if observed.cleanup == CleanupState::Complete
                        && matches!(
                            observed.state,
                            CodeContextState::Closed | CodeContextState::Failed
                        )
                    {
                        stored.context.state = observed.state;
                        stored.context.cleanup = CleanupState::Complete;
                        stored.context.finished_at = observed.finished_at;
                        stored.context.reason = observed.reason;
                        settle_runs(
                            &mut tx,
                            &stored.context,
                            &mut cursor,
                            event.timestamp,
                            "context collected before an execution result was confirmed",
                        )
                        .await?;
                        emit(
                            &mut tx,
                            &mut cursor,
                            id,
                            None,
                            event.kind,
                            json!(stored.context),
                            event.timestamp,
                        )
                        .await?;
                    } else if observed.cleanup == CleanupState::Unknown
                        && observed.state == CodeContextState::Unknown
                    {
                        stored.context.state = CodeContextState::Unknown;
                        stored.context.cleanup = CleanupState::Unknown;
                        stored.context.reason = observed.reason.clone();
                        let pending =
                            sqlx::query("SELECT * FROM code_runs WHERE context_id=? AND settled=0")
                                .bind(id.to_string())
                                .fetch_all(&mut *tx)
                                .await
                                .map_err(db)?;
                        for row in pending {
                            let mut run = run_row(&row)?.run;
                            run.state = CodeRunState::Unknown;
                            run.reason = Some("context cleanup is unconfirmed".into());
                            save_run(&mut tx, &run, false).await?;
                        }
                        emit(
                            &mut tx,
                            &mut cursor,
                            id,
                            None,
                            CodeContextEventKind::Diagnostic,
                            json!({"reason":"context_cleanup_unknown","observation":observed}),
                            event.timestamp,
                        )
                        .await?;
                    } else {
                        return Err(invalid("context close lacks valid cleanup observations"));
                    }
                }
                _ => {
                    if !stored.ever_ready {
                        return Err(invalid("context output precedes readiness"));
                    }
                    let row = if let Some(run) = event.run_id {
                        Some(run_record(&mut tx, id, run).await?)
                    } else {
                        None
                    };
                    if matches!(
                        event.kind,
                        CodeContextEventKind::Stdout
                            | CodeContextEventKind::Stderr
                            | CodeContextEventKind::Result
                            | CodeContextEventKind::Display
                            | CodeContextEventKind::KernelError
                    ) {
                        let late = event.data["late"]
                            .as_bool()
                            .ok_or_else(|| invalid("kernel output lacks late-output provenance"))?;
                        let size = encode(&event.data)?.len() as u64;
                        if let Some(row) = &row
                            && run_row(row)?.run.started_at.is_none()
                        {
                            return Err(invalid("output cannot be attributed to an unstarted run"));
                        }
                        if let Some(row) = &row
                            && !late
                        {
                            let run = run_row(row)?;
                            let used: i64 = row.try_get("output_bytes").map_err(db)?;
                            if run.run.started_at.is_none()
                                || row.try_get::<bool, _>("settled").map_err(db)?
                                || row
                                    .try_get::<Option<String>, _>("pending_result")
                                    .map_err(db)?
                                    .is_some()
                                || used as u64 + size > run.spec.max_output_bytes
                            {
                                return Err(invalid(
                                    "run output exceeds its accepted budget or lifetime",
                                ));
                            }
                            sqlx::query(
                                "UPDATE code_runs SET output_bytes=output_bytes+? WHERE id=?",
                            )
                            .bind(size as i64)
                            .bind(run.run.id.to_string())
                            .execute(&mut *tx)
                            .await
                            .map_err(db)?;
                        } else if !late {
                            return Err(invalid("unattributed output must be background output"));
                        } else {
                            let used: i64 = sqlx::query_scalar(
                                "SELECT background_bytes FROM code_contexts WHERE id=?",
                            )
                            .bind(id.to_string())
                            .fetch_one(&mut *tx)
                            .await
                            .map_err(db)?;
                            if used as u64 + size > 1024 * 1024 {
                                return Err(invalid("context background output exceeds budget"));
                            }
                            sqlx::query("UPDATE code_contexts SET background_bytes=background_bytes+? WHERE id=?").bind(size as i64).bind(id.to_string()).execute(&mut *tx).await.map_err(db)?;
                        }
                    }
                    if event.kind == CodeContextEventKind::OutputTruncated
                        && event.data["scope"] == "run"
                    {
                        let row = row
                            .as_ref()
                            .ok_or_else(|| invalid("run truncation lacks run identity"))?;
                        let mut run = run_row(row)?.run;
                        if row.try_get::<bool, _>("settled").map_err(db)? {
                            return Err(invalid("settled run output is immutable"));
                        }
                        run.output_truncated = true;
                        save_run(&mut tx, &run, false).await?;
                    }
                    emit(
                        &mut tx,
                        &mut cursor,
                        id,
                        event.run_id,
                        event.kind,
                        event.data.clone(),
                        event.timestamp,
                    )
                    .await?;
                }
            }
            sqlx::query(
                "INSERT INTO code_context_sources(context_id,sequence,fingerprint) VALUES(?,?,?)",
            )
            .bind(id.to_string())
            .bind(event.sequence as i64)
            .bind(hash)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
            stored.cursor = event.sequence;
        }
        save(&mut tx, &stored.context).await?;
        sqlx::query("UPDATE code_contexts SET cursor=?,event_cursor=?,ever_ready=? WHERE id=?")
            .bind(stored.cursor as i64)
            .bind(cursor as i64)
            .bind(stored.ever_ready)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }

    /// Worker-only reconciliation after actual runtime absence or a proven never-
    /// dispatched context. This cannot synthesize kernel success or an interpreter error.
    pub async fn finish_code_context_absent(&self, id: Uuid, reason: &str) -> Result<(), ApiError> {
        if reason.len() > 4096 {
            return Err(invalid("context absence reason exceeds limit"));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        if stored.context.cleanup == CleanupState::Complete {
            tx.commit().await.map_err(db)?;
            return Ok(());
        }
        let mut cursor: u64 =
            sqlx::query_scalar::<_, i64>("SELECT event_cursor FROM code_contexts WHERE id=?")
                .bind(id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?
                .try_into()
                .map_err(|_| internal())?;
        let now = Utc::now();
        stored.context.state = if stored.context.desired_state == CodeContextDesiredState::Closed {
            CodeContextState::Closed
        } else {
            CodeContextState::Failed
        };
        stored.context.cleanup = CleanupState::Complete;
        stored.context.finished_at = Some(now);
        stored.context.reason = Some(reason.into());
        settle_runs(&mut tx, &stored.context, &mut cursor, now, reason).await?;
        emit(
            &mut tx,
            &mut cursor,
            id,
            None,
            CodeContextEventKind::Closed,
            json!(stored.context),
            now,
        )
        .await?;
        save(&mut tx, &stored.context).await?;
        sqlx::query("UPDATE code_contexts SET event_cursor=? WHERE id=?")
            .bind(cursor as i64)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }
}
