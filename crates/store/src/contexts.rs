use super::*;
use goldenhoop_core::{validate_code_context, validate_code_run};
mod events;

fn context_row(row: &sqlx::sqlite::SqliteRow) -> Result<StoredCodeContext, ApiError> {
    let mut context: CodeContext = decode(row.try_get("payload").map_err(db)?)?;
    context.desired_state = decode(&format!(
        "\"{}\"",
        row.try_get::<&str, _>("desired").map_err(db)?
    ))?;
    Ok(StoredCodeContext {
        context,
        dispatched: row.try_get("dispatched").map_err(db)?,
        ever_ready: row.try_get("ever_ready").map_err(db)?,
        cursor: row
            .try_get::<i64, _>("cursor")
            .map_err(db)?
            .try_into()
            .map_err(|_| internal())?,
        events_cursor: row
            .try_get::<i64, _>("event_cursor")
            .map_err(db)?
            .try_into()
            .map_err(|_| internal())?,
    })
}
fn run_row(row: &sqlx::sqlite::SqliteRow) -> Result<StoredCodeRun, ApiError> {
    Ok(StoredCodeRun {
        run: decode(row.try_get("payload").map_err(db)?)?,
        spec: decode(row.try_get("spec").map_err(db)?)?,
        dispatched: row.try_get("dispatched").map_err(db)?,
        cancel_requested: row.try_get("cancel_requested").map_err(db)?,
    })
}
async fn load(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<StoredCodeContext, ApiError> {
    context_row(
        &sqlx::query("SELECT * FROM code_contexts WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("code context"))?,
    )
}
async fn save(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    context: &CodeContext,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE code_contexts SET desired=?,state=?,cleanup=?,payload=? WHERE id=?")
        .bind(tag(&context.desired_state)?)
        .bind(tag(&context.state)?)
        .bind(tag(&context.cleanup)?)
        .bind(encode(context)?)
        .bind(context.id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
async fn running_source(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<(), ApiError> {
    super::isolated::require_work(tx, id, Capability::CodeContexts).await
}
async fn close_intent(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    context: &mut CodeContext,
) -> Result<(), ApiError> {
    context.desired_state = CodeContextDesiredState::Closed;
    save(tx, context).await?;
    sqlx::query("UPDATE code_runs SET cancel_requested=1 WHERE context_id=? AND settled=0")
        .bind(context.id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}

impl Store {
    pub async fn code_context(&self, id: Uuid) -> Result<StoredCodeContext, ApiError> {
        context_row(
            &sqlx::query("SELECT * FROM code_contexts WHERE id=?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?
                .ok_or_else(|| not_found("code context"))?,
        )
    }
    pub async fn code_run(&self, id: Uuid) -> Result<StoredCodeRun, ApiError> {
        run_row(
            &sqlx::query("SELECT * FROM code_runs WHERE id=?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?
                .ok_or_else(|| not_found("code run"))?,
        )
    }
    pub async fn create_code_context(
        &self,
        sandbox: Uuid,
        spec: &CodeContextSpec,
        key: &str,
    ) -> Result<CodeContext, ApiError> {
        validate_code_context(spec)?;
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(existing) = reserve(
            &mut tx,
            &format!("contexts:{sandbox}:create"),
            key,
            &fingerprint(spec)?,
            id,
        )
        .await?
        {
            tx.commit().await.map_err(db)?;
            return Ok(self.code_context(existing).await?.context);
        }
        running_source(&mut tx, sandbox).await?;
        let row=sqlx::query("SELECT COUNT(*) AS history,COALESCE(SUM(cleanup!='complete'),0) AS live FROM code_contexts WHERE sandbox_id=?")
            .bind(sandbox.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
        if row.try_get::<i64, _>("history").map_err(db)? >= 16
            || row.try_get::<i64, _>("live").map_err(db)? >= 4
        {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "sandbox context history/identity budget is exhausted",
            ));
        }
        let context = CodeContext {
            id,
            sandbox_id: sandbox,
            spec: spec.clone(),
            state: CodeContextState::Starting,
            desired_state: CodeContextDesiredState::Open,
            cleanup: CleanupState::Pending,
            created_at: Utc::now(),
            ready_at: None,
            finished_at: None,
            kernel_info: None,
            reason: None,
        };
        sqlx::query("INSERT INTO code_contexts(id,sandbox_id,desired,state,cleanup,payload) VALUES(?,?,'open','starting','pending',?)")
            .bind(id.to_string()).bind(sandbox.to_string()).bind(encode(&context)?).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(context)
    }
    pub async fn close_code_context(&self, id: Uuid, key: &str) -> Result<CodeContext, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        reserve(
            &mut tx,
            &format!("contexts:{id}:close"),
            key,
            &fingerprint(&CodeContextDesiredState::Closed)?,
            id,
        )
        .await?;
        let mut stored = load(&mut tx, id).await?;
        close_intent(&mut tx, &mut stored.context).await?;
        tx.commit().await.map_err(db)?;
        Ok(stored.context)
    }
    /// Returns true only for the first durably recorded dispatch attempt.
    pub async fn dispatch_code_context(&self, id: Uuid) -> Result<bool, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let stored = load(&mut tx, id).await?;
        if stored.dispatched {
            tx.commit().await.map_err(db)?;
            return Ok(false);
        }
        if stored.context.state != CodeContextState::Starting
            || stored.context.desired_state != CodeContextDesiredState::Open
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "context is not dispatchable",
            ));
        }
        running_source(&mut tx, stored.context.sandbox_id).await?;
        sqlx::query("UPDATE code_contexts SET dispatched=1 WHERE id=?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(true)
    }
    pub async fn create_code_run(
        &self,
        context: Uuid,
        spec: &CodeRunSpec,
        key: &str,
    ) -> Result<CodeRun, ApiError> {
        validate_code_run(spec)?;
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(existing) = reserve(
            &mut tx,
            &format!("contexts:{context}:run"),
            key,
            &fingerprint(spec)?,
            id,
        )
        .await?
        {
            tx.commit().await.map_err(db)?;
            return Ok(self.code_run(existing).await?.run);
        }
        let stored = load(&mut tx, context).await?;
        if stored.context.state != CodeContextState::Ready
            || stored.context.desired_state != CodeContextDesiredState::Open
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "code context is not accepting runs",
            ));
        }
        running_source(&mut tx, stored.context.sandbox_id).await?;
        let row=sqlx::query("SELECT COUNT(*) AS history,COALESCE(SUM(state='pending' AND settled=0),0) AS queued FROM code_runs WHERE context_id=?")
            .bind(context.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
        let total:i64=sqlx::query_scalar("SELECT COUNT(*) FROM code_runs r JOIN code_contexts c ON c.id=r.context_id WHERE c.sandbox_id=?")
            .bind(stored.context.sandbox_id.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
        if total >= 128
            || row.try_get::<i64, _>("history").map_err(db)? >= 64
            || row.try_get::<i64, _>("queued").map_err(db)? >= 8
        {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "sandbox code history/context queue budget is exhausted",
            ));
        }
        let events_after: i64 =
            sqlx::query_scalar("SELECT event_cursor FROM code_contexts WHERE id=?")
                .bind(context.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        let run = CodeRun {
            id,
            context_id: context,
            events_after: events_after.try_into().map_err(|_| internal())?,
            state: CodeRunState::Pending,
            created_at: Utc::now(),
            started_at: None,
            finished_at: None,
            output_truncated: false,
            kernel_status: None,
            reason: None,
        };
        sqlx::query(
            "INSERT INTO code_runs(id,context_id,state,payload,spec) VALUES(?,?,'pending',?,?)",
        )
        .bind(id.to_string())
        .bind(context.to_string())
        .bind(encode(&run)?)
        .bind(encode(spec)?)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(run)
    }
    pub async fn dispatch_code_run(&self, id: Uuid) -> Result<bool, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let row = sqlx::query("SELECT * FROM code_runs WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("code run"))?;
        let run = run_row(&row)?;
        if run.dispatched {
            tx.commit().await.map_err(db)?;
            return Ok(false);
        }
        let context = load(&mut tx, run.run.context_id).await?.context;
        if run.cancel_requested
            || run.run.finished_at.is_some()
            || context.state != CodeContextState::Ready
            || context.desired_state != CodeContextDesiredState::Open
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "code run is not dispatchable",
            ));
        }
        running_source(&mut tx, context.sandbox_id).await?;
        sqlx::query("UPDATE code_runs SET dispatched=1 WHERE id=?")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(true)
    }
    pub async fn cancel_code_run(&self, id: Uuid) -> Result<CodeRun, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let row = sqlx::query("SELECT * FROM code_runs WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("code run"))?;
        let run = run_row(&row)?;
        if !row.try_get::<bool, _>("settled").map_err(db)? {
            let mut context = load(&mut tx, run.run.context_id).await?.context;
            close_intent(&mut tx, &mut context).await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(run.run)
    }
    pub async fn code_context_work(
        &self,
        sandbox: Uuid,
    ) -> Result<Vec<StoredCodeContext>, ApiError> {
        sqlx::query("SELECT * FROM code_contexts WHERE sandbox_id=? AND cleanup!='complete' ORDER BY id LIMIT 16")
            .bind(sandbox.to_string()).fetch_all(&self.pool).await.map_err(db)?.iter().map(context_row).collect()
    }
    pub async fn code_run_work(&self, context: Uuid) -> Result<Vec<StoredCodeRun>, ApiError> {
        // Row insertion order is the durable FIFO, independent of random UUIDs.
        sqlx::query(
            "SELECT * FROM code_runs WHERE context_id=? AND settled=0 ORDER BY rowid LIMIT 64",
        )
        .bind(context.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db)?
        .iter()
        .map(run_row)
        .collect()
    }
    pub async fn list_code_contexts(
        &self,
        sandbox: Option<Uuid>,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<CodeContextPage, ApiError> {
        page_limit(limit)?;
        let rows=sqlx::query("SELECT * FROM code_contexts WHERE (? IS NULL OR sandbox_id=?) AND (? IS NULL OR id>?) ORDER BY id LIMIT ?")
            .bind(sandbox.map(|id|id.to_string())).bind(sandbox.map(|id|id.to_string())).bind(after.map(|id|id.to_string())).bind(after.map(|id|id.to_string()))
            .bind(i64::from(limit)+1).fetch_all(&self.pool).await.map_err(db)?;
        let mut items = rows
            .iter()
            .map(|row| Ok(context_row(row)?.context))
            .collect::<Result<Vec<_>, ApiError>>()?;
        let next_after = if items.len() > limit as usize {
            items.truncate(limit as usize);
            items.last().map(|item| item.id)
        } else {
            None
        };
        Ok(CodeContextPage { items, next_after })
    }
    pub async fn list_code_runs(
        &self,
        context: Uuid,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<CodeRunPage, ApiError> {
        page_limit(limit)?;
        self.code_context(context).await?;
        let rows=sqlx::query("SELECT * FROM code_runs WHERE context_id=? AND (? IS NULL OR id>?) ORDER BY id LIMIT ?")
            .bind(context.to_string()).bind(after.map(|id|id.to_string())).bind(after.map(|id|id.to_string())).bind(i64::from(limit)+1)
            .fetch_all(&self.pool).await.map_err(db)?;
        let mut items = rows
            .iter()
            .map(|row| Ok(run_row(row)?.run))
            .collect::<Result<Vec<_>, ApiError>>()?;
        let next_after = if items.len() > limit as usize {
            items.truncate(limit as usize);
            items.last().map(|item| item.id)
        } else {
            None
        };
        Ok(CodeRunPage { items, next_after })
    }
}
fn page_limit(limit: u32) -> Result<(), ApiError> {
    if !(1..=1000).contains(&limit) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "page limit must be 1..1000",
        ));
    }
    Ok(())
}
