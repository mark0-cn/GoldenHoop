use super::*;
use goldenhoop_core::{expired, request_fingerprint, transition, validate_create};

pub(super) async fn check_quota(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    extra: &ResourceLimits,
) -> Result<(), ApiError> {
    let used=sqlx::query("SELECT COUNT(*) AS count,COALESCE(SUM(cpu_millis),0) AS cpu,COALESCE(SUM(memory_bytes),0) AS memory,COALESCE(SUM(pids),0) AS pids FROM sandboxes WHERE cleanup<>'complete'").fetch_one(&mut **tx).await.map_err(db)?;
    if extra.memory_bytes > 32 * 1024 * 1024 * 1024
        || used.try_get::<i64, _>("count").map_err(db)? >= 16
        || used.try_get::<i64, _>("cpu").map_err(db)? + i64::from(extra.cpu_millis) > 16000
        || used.try_get::<i64, _>("memory").map_err(db)? + extra.memory_bytes as i64
            > 32 * 1024 * 1024 * 1024
        || used.try_get::<i64, _>("pids").map_err(db)? + i64::from(extra.pids) > 4096
    {
        return Err(ApiError::new(
            ErrorCode::QuotaExceeded,
            "installation resource or live-sandbox quota exceeded",
        ));
    }
    Ok(())
}

pub(super) async fn insert_sandbox(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    request: &CreateSandbox,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    charge: &ResourceLimits,
) -> Result<SandboxCreated, ApiError> {
    let sandbox = Sandbox {
        id,
        profile: request.profile.clone(),
        image: request.image.clone(),
        state: SandboxState::Pending,
        desired_state: DesiredState::Running,
        cleanup: CleanupState::Pending,
        created_at: now,
        expires_at,
        observed_at: None,
        resources: request.resources.clone(),
        metadata: request.metadata.clone(),
        reason: None,
    };
    let operation = Operation {
        id: Uuid::new_v4(),
        resource_id: id,
        state: OperationState::Pending,
        created_at: now,
        finished_at: None,
        error: None,
    };
    sqlx::query("INSERT INTO sandboxes(id,desired,state,cleanup,payload,request,cpu_millis,memory_bytes,pids,create_operation) VALUES(?,'running','pending','pending',?,?,?,?,?,?)")
        .bind(id.to_string()).bind(encode(&sandbox)?).bind(encode(request)?)
        .bind(i64::from(charge.cpu_millis)).bind(charge.memory_bytes as i64).bind(i64::from(charge.pids)).bind(operation.id.to_string())
        .execute(&mut **tx).await.map_err(db)?;
    sqlx::query("INSERT INTO operations(id,resource_id,kind,state,payload) VALUES(?,?,'create','pending',?)")
        .bind(operation.id.to_string()).bind(id.to_string()).bind(encode(&operation)?).execute(&mut **tx).await.map_err(db)?;
    Ok(SandboxCreated { sandbox, operation })
}

impl Store {
    pub async fn sandbox(&self, id: Uuid) -> Result<StoredSandbox, ApiError> {
        let row = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("sandbox"))?;
        sandbox_row(&row)
    }

    pub async fn created(&self, id: Uuid) -> Result<SandboxCreated, ApiError> {
        let stored = self.sandbox(id).await?;
        Ok(SandboxCreated {
            sandbox: stored.sandbox,
            operation: self.operation(stored.create_operation).await?,
        })
    }

    pub async fn operation(&self, id: Uuid) -> Result<Operation, ApiError> {
        let value: Option<String> = sqlx::query_scalar("SELECT payload FROM operations WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        decode(&value.ok_or_else(|| not_found("operation"))?)
    }

    pub async fn create_sandbox(
        &self,
        profile: &RuntimeProfile,
        request: &CreateSandbox,
        key: &str,
    ) -> Result<SandboxCreated, ApiError> {
        self.create_root(profile, request, key, false).await
    }

    /// Host-owned availability probe. Its marker commits before any external
    /// write, so a replacement worker can collect it instead of adopting it.
    pub async fn create_network_profile_probe(
        &self,
        profile: &RuntimeProfile,
        request: &CreateSandbox,
        key: &str,
    ) -> Result<SandboxCreated, ApiError> {
        goldenhoop_core::require_capability(profile, Capability::NetworkPolicy)?;
        self.create_root(profile, request, key, true).await
    }

    async fn create_root(
        &self,
        profile: &RuntimeProfile,
        request: &CreateSandbox,
        key: &str,
        probe: bool,
    ) -> Result<SandboxCreated, ApiError> {
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(existing) = reserve(
            &mut tx,
            if probe {
                "network-profile-probe"
            } else {
                "sandboxes:create"
            },
            key,
            &request_fingerprint(request)?,
            id,
        )
        .await?
        {
            tx.commit().await.map_err(db)?;
            return self.created(existing).await;
        }
        validate_create(profile, request)?;
        if request.ttl_seconds > 86400 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "installation lifetime quota exceeded",
            ));
        }
        let envelope = goldenhoop_core::allocation_envelope(
            &request.resources,
            request.child_budget.as_ref(),
        )?;
        check_quota(&mut tx, &envelope).await?;
        let now = Utc::now();
        let expiry = now + chrono::Duration::seconds(request.ttl_seconds as i64);
        let created = insert_sandbox(&mut tx, id, request, now, expiry, &envelope).await?;
        if probe {
            sqlx::query("UPDATE operations SET kind='network_profile_probe' WHERE id=?")
                .bind(created.operation.id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        super::isolated::insert_scope(&mut tx, id, None, request).await?;
        tx.commit().await.map_err(db)?;
        Ok(created)
    }

    pub async fn list_sandboxes(
        &self,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<SandboxPage, ApiError> {
        if !(1..=1000).contains(&limit) {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "page limit must be 1..1000",
            ));
        }
        let rows = sqlx::query("SELECT b.* FROM sandboxes b JOIN sandbox_scopes s ON s.sandbox_id=b.id WHERE b.id>? AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.resource_id=s.root_id AND o.kind='network_profile_probe') ORDER BY b.id LIMIT ?")
            .bind(after.map(|id| id.to_string()).unwrap_or_default())
            .bind(i64::from(limit) + 1)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        let more = rows.len() > limit as usize;
        let items = rows
            .iter()
            .take(limit as usize)
            .map(|row| sandbox_row(row).map(|stored| stored.sandbox))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if more {
            items.last().map(|sandbox| sandbox.id)
        } else {
            None
        };
        Ok(SandboxPage { items, next_cursor })
    }

    pub async fn work(&self) -> Result<Vec<StoredSandbox>, ApiError> {
        // Collection and lifecycle acknowledgement are separate durable writes.
        // A restart between them must still settle the existing operation.
        sqlx::query("SELECT b.* FROM sandboxes b WHERE b.cleanup<>'complete' OR EXISTS(SELECT 1 FROM executions e WHERE e.sandbox_id=b.id AND e.state NOT IN('succeeded','failed','cancelled','timed_out')) OR EXISTS(SELECT 1 FROM code_contexts c WHERE c.sandbox_id=b.id AND c.cleanup!='complete') OR EXISTS(SELECT 1 FROM network_controllers c WHERE c.sandbox_id=b.id AND c.phase<>'collected') OR b.id IN(SELECT resource_id FROM operations WHERE kind IN('create','pause','resume','terminate') AND state IN('pending','running')) ORDER BY b.id")
            .fetch_all(&self.pool)
            .await
            .map_err(db)?
            .iter()
            .map(sandbox_row)
            .collect()
    }

    pub async fn network_profile_probes(&self) -> Result<Vec<StoredSandbox>, ApiError> {
        sqlx::query("SELECT b.* FROM sandboxes b JOIN operations o ON o.id=b.create_operation WHERE o.kind='network_profile_probe' AND (b.cleanup<>'complete' OR o.state IN('pending','running')) ORDER BY b.id")
            .fetch_all(&self.pool).await.map_err(db)?.iter().map(sandbox_row).collect()
    }

    /// Update only observed state. A concurrent API desired-state update is preserved.
    pub async fn observe(&self, mut stored: StoredSandbox) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let row = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
            .bind(stored.sandbox.id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let previous = sandbox_row(&row)?;
        if previous.sandbox.state != stored.sandbox.state {
            transition(previous.sandbox.state, stored.sandbox.state)?;
        }
        if stored.sandbox.cleanup == CleanupState::Complete
            && !matches!(
                stored.sandbox.state,
                SandboxState::Terminated | SandboxState::Failed
            )
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "a live sandbox cannot have completed cleanup",
            ));
        }
        if stored.sandbox.state == SandboxState::Terminated
            && stored.sandbox.cleanup != CleanupState::Complete
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "termination requires confirmed cleanup",
            ));
        }
        if stored.sandbox.cleanup == CleanupState::Complete {
            super::networks::require_collected(&mut tx, stored.sandbox.id).await?;
            super::isolated::confirm_children_absent(&mut tx, stored.sandbox.id).await?;
        }
        // The worker only supplies observations; request identity and absolute TTL
        // remain the values committed by the API, even when its snapshot is stale.
        let reported = stored.sandbox;
        stored.sandbox = previous.sandbox;
        stored.sandbox.state = reported.state;
        stored.sandbox.cleanup = reported.cleanup;
        stored.sandbox.observed_at = reported.observed_at;
        stored.sandbox.reason = reported.reason;
        if stored.handle.as_ref().is_some_and(|handle| {
            handle.sandbox_id != stored.sandbox.id || handle.profile != stored.sandbox.profile
        }) {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "runtime handle has a different sandbox identity",
            ));
        }
        let ever_running = previous.ever_running || stored.sandbox.state == SandboxState::Running;
        sqlx::query(
            "UPDATE sandboxes SET state=?,cleanup=?,payload=?,handle=?,ever_running=? WHERE id=?",
        )
        .bind(tag(&stored.sandbox.state)?)
        .bind(tag(&stored.sandbox.cleanup)?)
        .bind(encode(&stored.sandbox)?)
        .bind(stored.handle.as_ref().map(encode).transpose()?)
        .bind(ever_running)
        .bind(stored.sandbox.id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if matches!(
            stored.sandbox.state,
            SandboxState::Stopping | SandboxState::Failed | SandboxState::Terminated
        ) {
            super::isolated::terminate_descendants(&mut tx, stored.sandbox.id).await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(())
    }

    pub async fn set_desired(
        &self,
        id: Uuid,
        desired: DesiredState,
        key: &str,
    ) -> Result<Operation, ApiError> {
        let kind = match desired {
            DesiredState::Running => "resume",
            DesiredState::Paused => "pause",
            DesiredState::Terminated => "terminate",
        };
        let scope = format!("sandboxes:{id}:{kind}");
        let operation_id = Uuid::new_v4();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(existing) =
            reserve(&mut tx, &scope, key, &fingerprint(&desired)?, operation_id).await?
        {
            tx.commit().await.map_err(db)?;
            return self.operation(existing).await;
        }
        let row = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("sandbox"))?;
        let mut stored = sandbox_row(&row)?;
        if desired != DesiredState::Terminated {
            super::isolated::require_feature_limit(&mut tx, id, Capability::Pause).await?;
        }
        if stored.sandbox.desired_state == desired {
            let pending: Option<String> = sqlx::query_scalar("SELECT payload FROM operations WHERE resource_id=? AND kind=? AND state IN('pending','running') LIMIT 1")
                .bind(id.to_string()).bind(kind).fetch_optional(&mut *tx).await.map_err(db)?;
            if let Some(payload) = pending {
                let operation: Operation = decode(&payload)?;
                sqlx::query("UPDATE idempotency SET resource_id=? WHERE scope=? AND client_key=?")
                    .bind(operation.id.to_string())
                    .bind(&scope)
                    .bind(key)
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
                tx.commit().await.map_err(db)?;
                return Ok(operation);
            }
        }
        if desired != DesiredState::Terminated
            && (stored.sandbox.desired_state == DesiredState::Terminated
                || matches!(
                    stored.sandbox.state,
                    SandboxState::Pending
                        | SandboxState::Starting
                        | SandboxState::Stopping
                        | SandboxState::Failed
                        | SandboxState::Terminated
                        | SandboxState::Unknown
                )
                || expired(&stored.sandbox, Utc::now()))
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "sandbox cannot change to requested live state",
            ));
        }
        let mut satisfied = match desired {
            DesiredState::Running => {
                stored.sandbox.desired_state == desired
                    && stored.sandbox.state == SandboxState::Running
            }
            DesiredState::Paused => {
                stored.sandbox.desired_state == desired
                    && stored.sandbox.state == SandboxState::Paused
            }
            DesiredState::Terminated => stored.sandbox.cleanup == CleanupState::Complete,
        };
        if satisfied && desired != DesiredState::Terminated {
            satisfied = super::isolated::subtree_settled(&mut tx, id).await?;
        }
        let now = Utc::now();
        let operation = Operation {
            id: operation_id,
            resource_id: id,
            state: if satisfied {
                OperationState::Succeeded
            } else {
                OperationState::Pending
            },
            created_at: now,
            finished_at: satisfied.then_some(now),
            error: None,
        };
        // Desired lifecycle supersession must not cancel independent policy
        // intent. Its own source-version/native-confirmation path settles it.
        let pending = sqlx::query("SELECT id,kind,payload FROM operations WHERE resource_id=? AND kind IN('create','pause','resume','terminate') AND state IN('pending','running')").bind(id.to_string()).fetch_all(&mut *tx).await.map_err(db)?;
        for row in pending {
            if row.try_get::<&str, _>("kind").map_err(db)? == "create"
                && desired != DesiredState::Terminated
            {
                continue;
            }
            let mut previous: Operation = decode(row.try_get("payload").map_err(db)?)?;
            previous.state = OperationState::Cancelled;
            previous.finished_at = Some(now);
            previous.error = Some(ApiError::new(
                ErrorCode::Conflict,
                "operation superseded by desired-state request",
            ));
            sqlx::query("UPDATE operations SET state='cancelled',payload=? WHERE id=?")
                .bind(encode(&previous)?)
                .bind(previous.id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        stored.sandbox.desired_state = desired;
        sqlx::query("UPDATE sandboxes SET desired=?,payload=? WHERE id=?")
            .bind(tag(&desired)?)
            .bind(encode(&stored.sandbox)?)
            .bind(id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if desired == DesiredState::Terminated {
            // Permanent ancestor closure is a durable subtree intent. Pauses
            // are inherited separately so a child's own pause is preserved.
            super::isolated::terminate_descendants(&mut tx, id).await?;
        }
        sqlx::query("INSERT INTO operations(id,resource_id,kind,state,payload) VALUES(?,?,?,?,?)")
            .bind(operation.id.to_string())
            .bind(id.to_string())
            .bind(kind)
            .bind(tag(&operation.state)?)
            .bind(encode(&operation)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(operation)
    }

    pub async fn finish_operations(
        &self,
        id: Uuid,
        kind: &str,
        state: OperationState,
        error: Option<ApiError>,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let stored = sandbox_row(
            &sqlx::query("SELECT * FROM sandboxes WHERE id=?")
                .bind(id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?,
        )?;
        let sandbox = &stored.sandbox;
        if state == OperationState::Succeeded
            && !match kind {
                "create" => {
                    stored.ever_running
                        && matches!(sandbox.state, SandboxState::Running | SandboxState::Paused)
                }
                "resume" => sandbox.state == SandboxState::Running,
                "pause" => sandbox.state == SandboxState::Paused,
                "terminate" => sandbox.cleanup == CleanupState::Complete,
                _ => false,
            }
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "operation success lacks the required observation",
            ));
        }
        let rows = sqlx::query("SELECT payload FROM operations WHERE resource_id=? AND kind=? AND state IN('pending','running')").bind(id.to_string()).bind(kind).fetch_all(&mut *tx).await.map_err(db)?;
        for row in rows {
            let mut operation: Operation = decode(row.try_get("payload").map_err(db)?)?;
            operation.state = state;
            operation.error = error.clone();
            operation.finished_at = state.is_terminal().then(Utc::now);
            sqlx::query("UPDATE operations SET state=?,payload=? WHERE id=?")
                .bind(tag(&state)?)
                .bind(encode(&operation)?)
                .bind(operation.id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(())
    }
}
