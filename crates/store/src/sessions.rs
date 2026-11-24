use super::*;
use goldenhoop_core::{MAX_SESSION_TOTAL_INPUT_BYTES, expired, validate_session_control};

fn control_row(row: &sqlx::sqlite::SqliteRow) -> Result<StoredSessionControl, ApiError> {
    Ok(StoredSessionControl {
        request: decode(row.try_get("request").map_err(db)?)?,
        receipt: decode(row.try_get("payload").map_err(db)?)?,
    })
}

impl Store {
    pub async fn session_spec(&self, id: Uuid) -> Result<Option<SessionSpec>, ApiError> {
        let spec: Option<String> =
            sqlx::query_scalar("SELECT spec FROM sessions WHERE execution_id=?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
        spec.as_deref().map(decode).transpose()
    }
    pub async fn session(&self, id: Uuid) -> Result<Session, ApiError> {
        let spec = self
            .session_spec(id)
            .await?
            .ok_or_else(|| not_found("session"))?;
        Ok(Session {
            execution: self.execution(id).await?.execution,
            spec,
        })
    }
    pub async fn create_session(
        &self,
        sandbox: Uuid,
        spec: &SessionSpec,
        key: &str,
    ) -> Result<Session, ApiError> {
        let execution = self
            .create_process(sandbox, &spec.command, key, Some(spec))
            .await?;
        let spec = self
            .session_spec(execution.id)
            .await?
            .ok_or_else(internal)?;
        Ok(Session { execution, spec })
    }
    pub async fn list_sessions(
        &self,
        sandbox: Option<Uuid>,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<SessionPage, ApiError> {
        if !(1..=1000).contains(&limit) {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "session page limit must be 1..1000",
            ));
        }
        let rows=sqlx::query("SELECT e.payload AS execution,s.spec AS session FROM executions e JOIN sessions s ON s.execution_id=e.id WHERE (? IS NULL OR e.sandbox_id=?) AND (? IS NULL OR e.id>?) ORDER BY e.id LIMIT ?")
            .bind(sandbox.map(|id|id.to_string())).bind(sandbox.map(|id|id.to_string())).bind(after.map(|id|id.to_string())).bind(after.map(|id|id.to_string())).bind(i64::from(limit)+1).fetch_all(&self.pool).await.map_err(db)?;
        let mut items = rows
            .iter()
            .map(|row| {
                Ok(Session {
                    execution: decode(row.try_get("execution").map_err(db)?)?,
                    spec: decode(row.try_get("session").map_err(db)?)?,
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        let next_after = if items.len() > limit as usize {
            items.truncate(limit as usize);
            items.last().map(|s| s.execution.id)
        } else {
            None
        };
        Ok(SessionPage { items, next_after })
    }
    pub async fn session_control(
        &self,
        id: Uuid,
        sequence: u64,
    ) -> Result<StoredSessionControl, ApiError> {
        let sequence = i64::try_from(sequence).map_err(|_| {
            ApiError::new(ErrorCode::InvalidRequest, "control sequence is too large")
        })?;
        control_row(
            &sqlx::query("SELECT * FROM session_controls WHERE execution_id=? AND sequence=?")
                .bind(id.to_string())
                .bind(sequence)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?
                .ok_or_else(|| not_found("session control"))?,
        )
    }
    pub async fn replay_session_control(
        &self,
        id: Uuid,
        control: &SessionControl,
    ) -> Result<Option<SessionControlReceipt>, ApiError> {
        validate_session_control(control)?;
        match self.session_control(id, control.sequence).await {
            Ok(stored) => {
                if fingerprint(&stored.request)? != fingerprint(control)? {
                    return Err(ApiError::new(
                        ErrorCode::Conflict,
                        "session control sequence has different content",
                    ));
                }
                Ok(Some(stored.receipt))
            }
            Err(error) if error.code == ErrorCode::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    pub async fn enqueue_session_control(
        &self,
        id: Uuid,
        control: &SessionControl,
    ) -> Result<SessionControlReceipt, ApiError> {
        let bytes = validate_session_control(control)?;
        let fingerprint = fingerprint(control)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(row) =
            sqlx::query("SELECT * FROM session_controls WHERE execution_id=? AND sequence=?")
                .bind(id.to_string())
                .bind(control.sequence as i64)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
        {
            if row.try_get::<&str, _>("fingerprint").map_err(db)? != fingerprint {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "session control sequence has different content",
                ));
            }
            let receipt = control_row(&row)?.receipt;
            tx.commit().await.map_err(db)?;
            return Ok(receipt);
        }
        let row=sqlx::query("SELECT e.payload AS execution,e.cancel_requested,b.payload AS sandbox,b.desired AS desired FROM sessions s JOIN executions e ON e.id=s.execution_id JOIN sandboxes b ON b.id=e.sandbox_id WHERE e.id=?")
            .bind(id.to_string()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or_else(||not_found("session"))?;
        let execution: Execution = decode(row.try_get("execution").map_err(db)?)?;
        let sandbox: Sandbox = decode(row.try_get("sandbox").map_err(db)?)?;
        if execution.state.is_terminal()
            || row.try_get::<bool, _>("cancel_requested").map_err(db)?
            || sandbox.state != SandboxState::Running
            || row.try_get::<&str, _>("desired").map_err(db)? != "running"
            || expired(&sandbox, Utc::now())
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "session is not accepting controls",
            ));
        }
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM session_controls WHERE execution_id=?")
                .bind(id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        if control.sequence != count as u64 + 1 {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "session control sequence has a gap",
            ));
        }
        let used: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(input_bytes),0) FROM session_controls WHERE execution_id=?",
        )
        .bind(id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if used as usize + bytes > MAX_SESSION_TOTAL_INPUT_BYTES {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "session input budget exceeds 1 MiB",
            ));
        }
        let receipt = SessionControlReceipt {
            execution_id: id,
            sequence: control.sequence,
            state: SessionControlState::Pending,
            observed_at: Utc::now(),
            error: None,
        };
        sqlx::query("INSERT INTO session_controls(execution_id,sequence,state,fingerprint,request,payload,input_bytes) VALUES(?,?,'pending',?,?,?,?)")
            .bind(id.to_string()).bind(control.sequence as i64).bind(fingerprint).bind(encode(control)?).bind(encode(&receipt)?).bind(bytes as i64).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(receipt)
    }
    pub async fn session_control_work(
        &self,
        id: Uuid,
    ) -> Result<Vec<StoredSessionControl>, ApiError> {
        sqlx::query("SELECT * FROM session_controls WHERE execution_id=? AND state='pending' ORDER BY sequence LIMIT 16").bind(id.to_string()).fetch_all(&self.pool).await.map_err(db)?.iter().map(control_row).collect()
    }
    pub async fn observe_session_control(
        &self,
        receipt: &SessionControlReceipt,
    ) -> Result<(), ApiError> {
        if receipt.state == SessionControlState::Pending
            || ((receipt.state == SessionControlState::Applied) != receipt.error.is_none())
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "invalid session control observation",
            ));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let previous: SessionControlReceipt = decode(
            &sqlx::query_scalar::<_, String>(
                "SELECT payload FROM session_controls WHERE execution_id=? AND sequence=?",
            )
            .bind(receipt.execution_id.to_string())
            .bind(i64::try_from(receipt.sequence).map_err(|_| internal())?)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("session control"))?,
        )?;
        if previous.state != SessionControlState::Pending && encode(&previous)? != encode(receipt)?
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "settled session control is immutable",
            ));
        }
        sqlx::query(
            "UPDATE session_controls SET state=?,payload=? WHERE execution_id=? AND sequence=?",
        )
        .bind(tag(&receipt.state)?)
        .bind(encode(receipt)?)
        .bind(receipt.execution_id.to_string())
        .bind(receipt.sequence as i64)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }
}

pub(super) async fn finish_pending_controls(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<(), ApiError> {
    let rows =
        sqlx::query("SELECT * FROM session_controls WHERE execution_id=? AND state='pending'")
            .bind(id.to_string())
            .fetch_all(&mut **tx)
            .await
            .map_err(db)?;
    for row in rows {
        let mut receipt = control_row(&row)?.receipt;
        receipt.state = SessionControlState::Unknown;
        receipt.observed_at = Utc::now();
        receipt.error = Some(ApiError::new(
            ErrorCode::BackendUnavailable,
            "execution ended before input delivery could be confirmed",
        ));
        sqlx::query("UPDATE session_controls SET state='unknown',payload=? WHERE execution_id=? AND sequence=?").bind(encode(&receipt)?).bind(id.to_string()).bind(receipt.sequence as i64).execute(&mut **tx).await.map_err(db)?;
    }
    Ok(())
}
