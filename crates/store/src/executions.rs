use super::*;
use goldenhoop_core::validate_command;

fn execution_row(row: &sqlx::sqlite::SqliteRow) -> Result<StoredExecution, ApiError> {
    Ok(StoredExecution {
        execution: decode(row.try_get("payload").map_err(db)?)?,
        spec: decode(row.try_get("spec").map_err(db)?)?,
        cancel_requested: row.try_get("cancel_requested").map_err(db)?,
        cursor: row
            .try_get::<i64, _>("cursor")
            .map_err(db)?
            .try_into()
            .map_err(|_| internal())?,
    })
}

impl Store {
    pub async fn execution(&self, id: Uuid) -> Result<StoredExecution, ApiError> {
        execution_row(
            &sqlx::query("SELECT * FROM executions WHERE id=?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?
                .ok_or_else(|| not_found("execution"))?,
        )
    }

    pub async fn create_execution(
        &self,
        sandbox_id: Uuid,
        spec: &CommandSpec,
        key: &str,
    ) -> Result<Execution, ApiError> {
        self.create_process(sandbox_id, spec, key, None).await
    }

    pub(crate) async fn create_process(
        &self,
        sandbox_id: Uuid,
        spec: &CommandSpec,
        key: &str,
        session: Option<&SessionSpec>,
    ) -> Result<Execution, ApiError> {
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let (scope, request_fingerprint) = if let Some(session) = session {
            (format!("sessions:{sandbox_id}"), fingerprint(session)?)
        } else {
            (format!("commands:{sandbox_id}"), fingerprint(spec)?)
        };
        if let Some(existing) = reserve(&mut tx, &scope, key, &request_fingerprint, id).await? {
            tx.commit().await.map_err(db)?;
            return Ok(self.execution(existing).await?.execution);
        }
        validate_command(spec)?;
        if let Some(session) = session {
            goldenhoop_core::validate_session(session)?;
        }
        super::isolated::require_work(
            &mut tx,
            sandbox_id,
            if session.is_some() {
                Capability::ShellSessions
            } else {
                Capability::Commands
            },
        )
        .await?;
        if session.is_some_and(|spec| spec.terminal.is_some()) {
            super::isolated::require_feature_limit(&mut tx, sandbox_id, Capability::Pty).await?;
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM executions WHERE sandbox_id=?")
            .bind(sandbox_id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        if count >= 256 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "sandbox execution history limit reached",
            ));
        }
        let record = Execution {
            id,
            sandbox_id,
            state: ExecutionState::Pending,
            exit_code: None,
            created_at: Utc::now(),
            started_at: None,
            finished_at: None,
            output_truncated: false,
            cleanup: CleanupState::NotRequired,
            reason: None,
        };
        sqlx::query(
            "INSERT INTO executions(id,sandbox_id,state,payload,spec) VALUES(?,?,'pending',?,?)",
        )
        .bind(id.to_string())
        .bind(sandbox_id.to_string())
        .bind(encode(&record)?)
        .bind(encode(spec)?)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if let Some(session) = session {
            sqlx::query("INSERT INTO sessions(execution_id,spec) VALUES(?,?)")
                .bind(id.to_string())
                .bind(encode(session)?)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(record)
    }

    pub async fn execution_work(&self, sandbox_id: Uuid) -> Result<Vec<StoredExecution>, ApiError> {
        sqlx::query("SELECT * FROM executions WHERE sandbox_id=? AND state IN('pending','running','unknown') ORDER BY cancel_requested DESC,CASE state WHEN 'running' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END,json_extract(payload,'$.created_at'),id")
            .bind(sandbox_id.to_string()).fetch_all(&self.pool).await.map_err(db)?.iter().map(execution_row).collect()
    }

    pub async fn cancel_execution(&self, id: Uuid) -> Result<Execution, ApiError> {
        sqlx::query("UPDATE executions SET cancel_requested=1 WHERE id=?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(self.execution(id).await?.execution)
    }

    pub async fn events(&self, id: Uuid, after: u64) -> Result<Vec<ExecutionEvent>, ApiError> {
        let after = i64::try_from(after)
            .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "event cursor is too large"))?;
        sqlx::query("SELECT payload FROM events WHERE execution_id=? AND sequence>? ORDER BY sequence LIMIT 256")
            .bind(id.to_string()).bind(after).fetch_all(&self.pool).await.map_err(db)?
            .iter().map(|row| decode(row.try_get("payload").map_err(db)?)).collect()
    }

    /// Events and their acknowledgement cursor commit atomically with the public result.
    pub async fn persist_execution(
        &self,
        record: &Execution,
        events: &[ExecutionEvent],
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let previous = execution_row(
            &sqlx::query("SELECT * FROM executions WHERE id=?")
                .bind(record.id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?,
        )?;
        if previous.execution.sandbox_id != record.sandbox_id
            || previous.execution.created_at != record.created_at
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "execution identity is immutable",
            ));
        }
        if previous.execution.state.is_terminal() && encode(&previous.execution)? != encode(record)?
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "terminal execution result is immutable",
            ));
        }
        let mut cursor = previous.cursor;
        let mut completions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events WHERE execution_id=? AND kind='completed'",
        )
        .bind(record.id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        for event in events {
            if event.execution_id != record.id || event.sequence > i64::MAX as u64 {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "event identity or sequence is invalid",
                ));
            }
            let payload = encode(event)?;
            if event.sequence <= cursor {
                let existing: Option<String> = sqlx::query_scalar(
                    "SELECT payload FROM events WHERE execution_id=? AND sequence=?",
                )
                .bind(record.id.to_string())
                .bind(event.sequence as i64)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
                if existing.as_deref() != Some(&payload) {
                    return Err(ApiError::new(
                        ErrorCode::Conflict,
                        "event sequence has different content",
                    ));
                }
                continue;
            }
            if event.sequence != cursor + 1 {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "event sequence has a gap",
                ));
            }
            if previous.execution.state.is_terminal() || completions > 0 {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "completed event stream is immutable",
                ));
            }
            if event.kind == EventKind::Completed {
                let terminal: Execution =
                    serde_json::from_value(event.data.clone()).map_err(|_| internal())?;
                if !terminal.state.is_terminal() || encode(&terminal)? != encode(record)? {
                    return Err(ApiError::new(
                        ErrorCode::InvalidState,
                        "completion event requires the matching terminal result",
                    ));
                }
                completions += 1;
            }
            sqlx::query("INSERT INTO events(execution_id,sequence,kind,payload) VALUES(?,?,?,?)")
                .bind(record.id.to_string())
                .bind(event.sequence as i64)
                .bind(tag(&event.kind)?)
                .bind(payload)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            cursor = event.sequence;
        }
        if record.state.is_terminal()
            && (completions != 1
                || record.cleanup != CleanupState::Complete
                || record.finished_at.is_none()
                || (record.state == ExecutionState::Succeeded && record.exit_code != Some(0)))
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "terminal result requires completion, cleanup and exit observations",
            ));
        }
        sqlx::query("UPDATE executions SET state=?,payload=?,cursor=? WHERE id=?")
            .bind(tag(&record.state)?)
            .bind(encode(record)?)
            .bind(cursor as i64)
            .bind(record.id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if record.state.is_terminal() {
            super::sessions::finish_pending_controls(&mut tx, record.id).await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(())
    }

    pub async fn finish_execution(
        &self,
        id: Uuid,
        state: ExecutionState,
        reason: &str,
    ) -> Result<(), ApiError> {
        if !matches!(
            state,
            ExecutionState::Failed | ExecutionState::Cancelled | ExecutionState::TimedOut
        ) {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "worker cannot synthesize command success",
            ));
        }
        let stored = self.execution(id).await?;
        if stored.execution.state.is_terminal() {
            return Ok(());
        }
        let mut record = stored.execution;
        record.state = state;
        record.cleanup = CleanupState::Complete;
        record.finished_at = Some(Utc::now());
        record.reason = Some(reason.into());
        let event = ExecutionEvent {
            sequence: stored.cursor + 1,
            execution_id: id,
            timestamp: Utc::now(),
            kind: EventKind::Completed,
            data: serde_json::to_value(&record).map_err(|_| internal())?,
        };
        self.persist_execution(&record, &[event]).await
    }
}
