use super::lifecycle::{check_quota, insert_sandbox};
use super::*;
use goldenhoop_core::{allocation_envelope, expired, require_feature, validate_create};

fn zero() -> ResourceLimits {
    ResourceLimits {
        cpu_millis: 0,
        memory_bytes: 0,
        pids: 0,
    }
}
fn uuid(value: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value).map_err(|_| internal())
}
fn resources(row: &sqlx::sqlite::SqliteRow, prefix: &str) -> Result<ResourceLimits, ApiError> {
    Ok(ResourceLimits {
        cpu_millis: row
            .try_get::<i64, _>(format!("{prefix}_cpu").as_str())
            .map_err(db)?
            .try_into()
            .map_err(|_| internal())?,
        memory_bytes: row
            .try_get::<i64, _>(format!("{prefix}_memory").as_str())
            .map_err(db)?
            .try_into()
            .map_err(|_| internal())?,
        pids: row
            .try_get::<i64, _>(format!("{prefix}_pids").as_str())
            .map_err(db)?
            .try_into()
            .map_err(|_| internal())?,
    })
}
pub(super) async fn source(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<StoredSandbox, ApiError> {
    sandbox_row(
        &sqlx::query("SELECT * FROM sandboxes WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("sandbox"))?,
    )
}
pub(super) async fn scope(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<SandboxScope, ApiError> {
    let row=sqlx::query("SELECT s.*,(SELECT COALESCE(SUM(c.envelope_cpu),0) FROM sandbox_scopes c JOIN sandboxes b ON b.id=c.sandbox_id WHERE c.parent_id=s.sandbox_id AND b.cleanup!='complete') AS used_cpu,(SELECT COALESCE(SUM(c.envelope_memory),0) FROM sandbox_scopes c JOIN sandboxes b ON b.id=c.sandbox_id WHERE c.parent_id=s.sandbox_id AND b.cleanup!='complete') AS used_memory,(SELECT COALESCE(SUM(c.envelope_pids),0) FROM sandbox_scopes c JOIN sandboxes b ON b.id=c.sandbox_id WHERE c.parent_id=s.sandbox_id AND b.cleanup!='complete') AS used_pids FROM sandbox_scopes s WHERE s.sandbox_id=?")
        .bind(id.to_string()).fetch_optional(&mut **tx).await.map_err(db)?.ok_or_else(||not_found("sandbox scope"))?;
    let budget = resources(&row, "child")?;
    let child_budget = if budget == zero() {
        None
    } else {
        if budget.cpu_millis == 0 || budget.memory_bytes == 0 || budget.pids == 0 {
            return Err(internal());
        }
        Some(budget)
    };
    let feature_limit: Option<String> = row.try_get("feature_limit").map_err(db)?;
    Ok(SandboxScope {
        sandbox_id: id,
        parent_id: row
            .try_get::<Option<&str>, _>("parent_id")
            .map_err(db)?
            .map(uuid)
            .transpose()?,
        root_id: uuid(row.try_get("root_id").map_err(db)?)?,
        depth: row
            .try_get::<i64, _>("depth")
            .map_err(db)?
            .try_into()
            .map_err(|_| internal())?,
        child_budget,
        envelope: resources(&row, "envelope")?,
        allocated_to_children: resources(&row, "used")?,
        feature_limit: feature_limit.as_deref().map(decode).transpose()?,
        observed_at: Utc::now(),
    })
}
pub(super) async fn insert_scope(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    parent: Option<&SandboxScope>,
    request: &CreateSandbox,
) -> Result<(), ApiError> {
    let envelope = allocation_envelope(&request.resources, request.child_budget.as_ref())?;
    let children = request.child_budget.clone().unwrap_or_else(zero);
    sqlx::query("INSERT INTO sandbox_scopes(sandbox_id,parent_id,root_id,depth,envelope_cpu,envelope_memory,envelope_pids,child_cpu,child_memory,child_pids,feature_limit) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
        .bind(id.to_string()).bind(parent.map(|scope|scope.sandbox_id.to_string())).bind(parent.map_or(id,|scope|scope.root_id).to_string())
        .bind(parent.map_or(0,|scope|i64::from(scope.depth)+1))
        .bind(i64::from(envelope.cpu_millis)).bind(envelope.memory_bytes as i64).bind(i64::from(envelope.pids))
        .bind(i64::from(children.cpu_millis)).bind(children.memory_bytes as i64).bind(i64::from(children.pids))
        .bind(request.feature_limit.as_ref().map(encode).transpose()?).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
pub(super) async fn require_running_tree(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<(), ApiError> {
    let mut next = Some(id);
    for _ in 0..5 {
        let Some(id) = next else {
            return Ok(());
        };
        let record = source(tx, id).await?.sandbox;
        super::snapshots::require_dispatch(tx, id).await?;
        if record.desired_state != DesiredState::Running
            || record.state != SandboxState::Running
            || expired(&record, Utc::now())
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "sandbox or ancestor is not accepting work",
            ));
        }
        next = scope(tx, id).await?.parent_id;
    }
    if next.is_some() {
        return Err(internal());
    }
    Ok(())
}
pub(super) async fn require_feature_limit(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    capability: Capability,
) -> Result<(), ApiError> {
    let mut next = Some(id);
    for _ in 0..5 {
        let Some(id) = next else {
            return Ok(());
        };
        let record = scope(tx, id).await?;
        if record
            .feature_limit
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&capability))
        {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                format!("{capability:?} is outside the sandbox or ancestor feature ceiling"),
            ));
        }
        next = record.parent_id;
    }
    if next.is_some() {
        return Err(internal());
    }
    Ok(())
}
pub(super) async fn require_work(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    capability: Capability,
) -> Result<(), ApiError> {
    require_feature_limit(tx, id, capability).await?;
    require_running_tree(tx, id).await
}
pub(super) async fn terminate_descendants(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query("WITH RECURSIVE descendants(id) AS (SELECT sandbox_id FROM sandbox_scopes WHERE parent_id=? UNION ALL SELECT s.sandbox_id FROM sandbox_scopes s JOIN descendants d ON s.parent_id=d.id) UPDATE sandboxes SET desired='terminated' WHERE id IN (SELECT id FROM descendants) AND cleanup!='complete'")
        .bind(id.to_string()).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
pub(super) async fn effective_desired(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<DesiredState, ApiError> {
    let own = source(tx, id).await?.sandbox;
    let mut result = own.desired_state;
    let mut next = Some(id);
    for level in 0..5 {
        let Some(id) = next else {
            return Ok(result);
        };
        let record = source(tx, id).await?.sandbox;
        if record.desired_state == DesiredState::Terminated
            || expired(&record, Utc::now())
            || matches!(
                record.state,
                SandboxState::Failed | SandboxState::Terminated
            )
        {
            return Ok(DesiredState::Terminated);
        }
        if level > 0
            && (record.desired_state == DesiredState::Paused
                || record.state != SandboxState::Running)
        {
            result = DesiredState::Paused;
        }
        next = scope(tx, id).await?.parent_id;
    }
    if next.is_some() {
        return Err(internal());
    }
    Ok(result)
}
pub(super) async fn subtree_settled(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<bool, ApiError> {
    let rows=sqlx::query("WITH RECURSIVE subtree(id) AS (SELECT ? UNION ALL SELECT s.sandbox_id FROM sandbox_scopes s JOIN subtree p ON s.parent_id=p.id) SELECT b.* FROM sandboxes b JOIN subtree s ON s.id=b.id WHERE b.cleanup!='complete'")
        .bind(id.to_string()).fetch_all(&mut **tx).await.map_err(db)?;
    for row in rows {
        let record = sandbox_row(&row)?.sandbox;
        let desired = effective_desired(tx, record.id).await?;
        if !matches!(
            (desired, record.state),
            (DesiredState::Running, SandboxState::Running)
                | (DesiredState::Paused, SandboxState::Paused)
        ) {
            return Ok(false);
        }
    }
    Ok(true)
}
pub(super) async fn confirm_children_absent(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<(), ApiError> {
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM sandbox_scopes c JOIN sandboxes b ON b.id=c.sandbox_id WHERE c.parent_id=? AND b.cleanup!='complete'")
        .bind(id.to_string()).fetch_one(&mut **tx).await.map_err(db)?;
    if count != 0 {
        return Err(ApiError::new(
            ErrorCode::InvalidState,
            "parent cleanup requires confirmed child collection",
        ));
    }
    Ok(())
}

impl Store {
    /// Checks immutable feature ceilings; runtime availability is checked by the caller.
    pub async fn authorize_feature(
        &self,
        id: Uuid,
        capability: Capability,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        require_feature_limit(&mut tx, id, capability).await?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }
    /// A single snapshot checks feature ceilings, desired state and all ancestor deadlines.
    pub async fn authorize_work(&self, id: Uuid, capability: Capability) -> Result<(), ApiError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        require_work(&mut tx, id, capability).await?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }
    pub async fn children_collected(&self, id: Uuid) -> Result<bool, ApiError> {
        let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM sandbox_scopes c JOIN sandboxes b ON b.id=c.sandbox_id WHERE c.parent_id=? AND b.cleanup!='complete'")
            .bind(id.to_string()).fetch_one(&self.pool).await.map_err(db)?;
        Ok(count == 0)
    }
    pub async fn subtree_settled(&self, id: Uuid) -> Result<bool, ApiError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let settled = subtree_settled(&mut tx, id).await?;
        tx.commit().await.map_err(db)?;
        Ok(settled)
    }
    pub async fn sandbox_scope(&self, id: Uuid) -> Result<SandboxScope, ApiError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let result = scope(&mut tx, id).await?;
        tx.commit().await.map_err(db)?;
        Ok(result)
    }
    pub async fn create_isolated_session(
        &self,
        profile: &RuntimeProfile,
        parent: Uuid,
        spec: &CreateIsolatedSession,
        key: &str,
    ) -> Result<IsolatedSessionCreated, ApiError> {
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(existing) = reserve(
            &mut tx,
            &format!("sandboxes:{parent}:isolated:create"),
            key,
            &fingerprint(spec)?,
            id,
        )
        .await?
        {
            let scope = scope(&mut tx, existing).await?;
            tx.commit().await.map_err(db)?;
            let created = self.created(existing).await?;
            return Ok(IsolatedSessionCreated {
                sandbox: created.sandbox,
                scope,
                operation: created.operation,
            });
        }
        require_running_tree(&mut tx, parent).await?;
        let parent_record = source(&mut tx, parent).await?;
        let parent_scope = scope(&mut tx, parent).await?;
        if profile.id != parent_record.sandbox.profile {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "child profile must match its parent",
            ));
        }
        require_feature(
            profile,
            parent_scope.feature_limit.as_ref(),
            Capability::IsolatedSessions,
        )?;
        if parent_scope.depth >= 4 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "sandbox hierarchy depth exceeds four edges",
            ));
        }
        let history: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sandbox_scopes WHERE parent_id=?")
                .bind(parent.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        if history >= 64 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "parent child-history limit is exhausted",
            ));
        }
        let ceiling = parent_scope
            .feature_limit
            .clone()
            .unwrap_or_else(|| profile.capabilities.clone());
        if spec
            .feature_limit
            .as_ref()
            .is_some_and(|requested| !requested.is_subset(&ceiling))
        {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "child feature ceiling exceeds its parent",
            ));
        }
        let granted = spec
            .feature_limit
            .clone()
            .unwrap_or(ceiling)
            .intersection(&profile.capabilities)
            .copied()
            .collect();
        let mut request = CreateSandbox::new(
            &parent_record.sandbox.profile,
            spec.image
                .as_deref()
                .unwrap_or(&parent_record.sandbox.image),
        );
        request.resources = spec.resources.clone();
        request.child_budget = spec.child_budget.clone();
        request.feature_limit = Some(granted);
        request.required_capabilities = spec.required_capabilities.clone();
        request.metadata = spec.metadata.clone();
        request.ttl_seconds = spec.ttl_seconds.unwrap_or(
            parent_record
                .request
                .ttl_seconds
                .min(profile.max_ttl_seconds),
        );
        request.network = spec
            .network
            .clone()
            .unwrap_or_else(|| parent_record.request.network.clone());
        let layered_network =
            super::network_policy_public::public_parent(&mut tx, parent, self.installation_id)
                .await?;
        if layered_network {
            // The child must have an enforcing backend even when its own API
            // feature ceiling forbids later policy edits. Runtime permission
            // still waits for the full ancestor/user/operator configuration.
            goldenhoop_core::require_capability(profile, Capability::NetworkPolicy)?;
        }
        if request.network != NetworkPolicy::default()
            && request.network != parent_record.request.network
            && !layered_network
        {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "child network policy exceeds its parent",
            ));
        }
        validate_create(profile, &request)?;
        if request.ttl_seconds > 86400 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "installation lifetime quota exceeded",
            ));
        }
        let envelope = allocation_envelope(&request.resources, request.child_budget.as_ref())?;
        let budget = parent_scope.child_budget.as_ref().ok_or_else(|| {
            ApiError::new(
                ErrorCode::QuotaExceeded,
                "parent has no reserved child budget",
            )
        })?;
        let used = &parent_scope.allocated_to_children;
        if u64::from(used.cpu_millis) + u64::from(envelope.cpu_millis)
            > u64::from(budget.cpu_millis)
            || used
                .memory_bytes
                .checked_add(envelope.memory_bytes)
                .is_none_or(|total| total > budget.memory_bytes)
            || u64::from(used.pids) + u64::from(envelope.pids) > u64::from(budget.pids)
        {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "parent child-resource reservation is exhausted",
            ));
        }
        // Root rows already charge the complete reservation. Child rows charge a
        // live object, while their resource envelope debits only the parent.
        check_quota(&mut tx, &zero()).await?;
        let now = Utc::now();
        let expiry = (now + chrono::Duration::seconds(request.ttl_seconds as i64))
            .min(parent_record.sandbox.expires_at);
        if expiry <= now {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "parent deadline was reached before child acceptance",
            ));
        }
        let created = insert_sandbox(&mut tx, id, &request, now, expiry, &zero()).await?;
        insert_scope(&mut tx, id, Some(&parent_scope), &request).await?;
        let scope = scope(&mut tx, id).await?;
        tx.commit().await.map_err(db)?;
        Ok(IsolatedSessionCreated {
            sandbox: created.sandbox,
            scope,
            operation: created.operation,
        })
    }
    pub async fn isolated_sessions(
        &self,
        parent: Uuid,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<SandboxPage, ApiError> {
        if !(1..=1000).contains(&limit) {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "page limit must be 1..1000",
            ));
        }
        self.sandbox(parent).await?;
        let rows=sqlx::query("SELECT b.* FROM sandboxes b JOIN sandbox_scopes s ON s.sandbox_id=b.id WHERE s.parent_id=? AND b.id>? ORDER BY b.id LIMIT ?")
            .bind(parent.to_string()).bind(after.map(|id|id.to_string()).unwrap_or_default()).bind(i64::from(limit)+1).fetch_all(&self.pool).await.map_err(db)?;
        let mut items = rows
            .iter()
            .map(|row| Ok(sandbox_row(row)?.sandbox))
            .collect::<Result<Vec<_>, ApiError>>()?;
        let next_cursor = if items.len() > limit as usize {
            items.truncate(limit as usize);
            items.last().map(|record| record.id)
        } else {
            None
        };
        Ok(SandboxPage { items, next_cursor })
    }
    /// Ancestor pause is inherited without overwriting a child's own desire.
    pub async fn effective_desired(&self, id: Uuid) -> Result<DesiredState, ApiError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let result = effective_desired(&mut tx, id).await?;
        tx.commit().await.map_err(db)?;
        Ok(result)
    }
}
