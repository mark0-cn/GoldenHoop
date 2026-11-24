use super::*;

fn row(value: &sqlx::sqlite::SqliteRow) -> Result<StoredArtifact, ApiError> {
    let mut artifact: Artifact = decode(value.try_get("payload").map_err(db)?)?;
    artifact.desired_state = decode(&format!(
        "\"{}\"",
        value.try_get::<&str, _>("desired").map_err(db)?
    ))?;
    Ok(StoredArtifact {
        artifact,
        request: decode(value.try_get("request").map_err(db)?)?,
        create_operation: Uuid::parse_str(value.try_get("create_operation").map_err(db)?)
            .map_err(|_| internal())?,
    })
}
async fn load(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<StoredArtifact, ApiError> {
    let value = sqlx::query("SELECT * FROM artifacts WHERE id=?")
        .bind(id.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("artifact"))?;
    row(&value)
}
async fn save(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    artifact: &Artifact,
) -> Result<(), ApiError> {
    sqlx::query("UPDATE artifacts SET desired=?,state=?,cleanup=?,payload=? WHERE id=?")
        .bind(tag(&artifact.desired_state)?)
        .bind(tag(&artifact.state)?)
        .bind(tag(&artifact.cleanup)?)
        .bind(encode(artifact)?)
        .bind(artifact.id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
async fn finish(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    kind: &str,
    state: OperationState,
    error: Option<ApiError>,
) -> Result<(), ApiError> {
    let values=sqlx::query("SELECT payload FROM operations WHERE resource_id=? AND kind=? AND state IN('pending','running')")
        .bind(id.to_string()).bind(kind).fetch_all(&mut **tx).await.map_err(db)?;
    for value in values {
        let mut operation: Operation = decode(value.try_get("payload").map_err(db)?)?;
        operation.state = state;
        operation.error = error.clone();
        operation.finished_at = state.is_terminal().then(Utc::now);
        sqlx::query("UPDATE operations SET state=?,payload=? WHERE id=?")
            .bind(tag(&state)?)
            .bind(encode(&operation)?)
            .bind(operation.id.to_string())
            .execute(&mut **tx)
            .await
            .map_err(db)?;
    }
    Ok(())
}

impl Store {
    pub async fn artifact(&self, id: Uuid) -> Result<StoredArtifact, ApiError> {
        let value = sqlx::query("SELECT * FROM artifacts WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("artifact"))?;
        row(&value)
    }
    pub async fn artifact_created(&self, id: Uuid) -> Result<ArtifactCreated, ApiError> {
        let stored = self.artifact(id).await?;
        Ok(ArtifactCreated {
            artifact: stored.artifact,
            operation: self.operation(stored.create_operation).await?,
        })
    }
    pub async fn create_artifact(
        &self,
        sandbox_id: Uuid,
        request: &CreateArtifact,
        key: &str,
    ) -> Result<ArtifactCreated, ApiError> {
        goldenhoop_core::validate_artifact(request)?;
        let id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(existing) = reserve(
            &mut tx,
            &format!("sandboxes:{sandbox_id}:artifacts:create"),
            key,
            &fingerprint(request)?,
            id,
        )
        .await?
        {
            tx.commit().await.map_err(db)?;
            return self.artifact_created(existing).await;
        }
        let sandbox = sandbox_row(
            &sqlx::query("SELECT * FROM sandboxes WHERE id=?")
                .bind(sandbox_id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or_else(|| not_found("sandbox"))?,
        )?
        .sandbox;
        if sandbox.state != SandboxState::Running
            || sandbox.desired_state != DesiredState::Running
            || goldenhoop_core::expired(&sandbox, Utc::now())
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "artifact capture requires a live running source sandbox",
            ));
        }
        let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE NOT(state IN('deleted','failed') AND cleanup='complete')")
            .fetch_one(&mut *tx).await.map_err(db)?;
        if count >= 256 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "installation artifact limit is 256 retained or uncollected artifacts",
            ));
        }
        let now = Utc::now();
        let artifact = Artifact {
            id,
            sandbox_id,
            name: request.name.clone(),
            source_path: request.path.clone(),
            state: ArtifactState::Pending,
            desired_state: ArtifactDesiredState::Available,
            cleanup: CleanupState::Pending,
            sha256: None,
            size_bytes: None,
            created_at: now,
            observed_at: None,
            error: None,
        };
        let operation = Operation {
            id: operation_id,
            resource_id: id,
            state: OperationState::Pending,
            created_at: now,
            finished_at: None,
            error: None,
        };
        sqlx::query("INSERT INTO artifacts(id,sandbox_id,desired,state,cleanup,payload,request,create_operation) VALUES(?,?,?,?,?,?,?,?)")
            .bind(id.to_string()).bind(sandbox_id.to_string()).bind("available").bind("pending").bind("pending")
            .bind(encode(&artifact)?).bind(encode(request)?).bind(operation_id.to_string()).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("INSERT INTO operations(id,resource_id,kind,state,payload) VALUES(?,?,'artifact_create','pending',?)")
            .bind(operation_id.to_string()).bind(id.to_string()).bind(encode(&operation)?).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(ArtifactCreated {
            artifact,
            operation,
        })
    }

    pub async fn artifact_work(&self) -> Result<Vec<StoredArtifact>, ApiError> {
        sqlx::query("SELECT * FROM artifacts WHERE state IN('pending','uploading','deleting') OR(state='failed' AND cleanup!='complete') ORDER BY id LIMIT 256")
            .fetch_all(&self.pool).await.map_err(db)?.iter().map(row).collect()
    }
    pub async fn list_artifacts(
        &self,
        sandbox: Option<Uuid>,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<ArtifactPage, ApiError> {
        if !(1..=1000).contains(&limit) {
            return Err(invalid_page());
        }
        let values=sqlx::query("SELECT * FROM artifacts WHERE (? IS NULL OR sandbox_id=?) AND id>? ORDER BY id LIMIT ?")
            .bind(sandbox.map(|id|id.to_string())).bind(sandbox.map(|id|id.to_string()))
            .bind(after.map(|id|id.to_string()).unwrap_or_default()).bind(limit as i64+1).fetch_all(&self.pool).await.map_err(db)?;
        let mut items = values
            .iter()
            .map(|value| row(value).map(|value| value.artifact))
            .collect::<Result<Vec<_>, _>>()?;
        let more = items.len() > limit as usize;
        items.truncate(limit as usize);
        let next_cursor = if more {
            items.last().map(|value| value.id)
        } else {
            None
        };
        Ok(ArtifactPage { items, next_cursor })
    }

    pub async fn prepare_artifact(
        &self,
        id: Uuid,
        sha256: &str,
        size_bytes: u64,
    ) -> Result<StoredArtifact, ApiError> {
        if size_bytes > 16 * 1024 * 1024
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "artifact content metadata exceeds limits or has an invalid digest",
            ));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        if stored
            .artifact
            .sha256
            .as_deref()
            .is_some_and(|digest| digest != sha256)
            || stored
                .artifact
                .size_bytes
                .is_some_and(|size| size != size_bytes)
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "prepared artifact content is immutable",
            ));
        }
        if stored.artifact.desired_state == ArtifactDesiredState::Available
            && stored.artifact.state == ArtifactState::Pending
        {
            stored.artifact.sha256 = Some(sha256.into());
            stored.artifact.size_bytes = Some(size_bytes);
            stored.artifact.state = ArtifactState::Uploading;
            stored.artifact.cleanup = CleanupState::Pending;
            stored.artifact.error = None;
            stored.artifact.observed_at = Some(Utc::now());
            save(&mut tx, &stored.artifact).await?;
            finish(
                &mut tx,
                id,
                "artifact_create",
                OperationState::Running,
                None,
            )
            .await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(stored)
    }

    pub async fn delete_artifact(&self, id: Uuid, key: &str) -> Result<Operation, ApiError> {
        let operation_id = Uuid::new_v4();
        let scope = format!("artifacts:{id}:delete");
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(existing) = reserve(&mut tx, &scope, key, "delete", operation_id).await? {
            tx.commit().await.map_err(db)?;
            return self.operation(existing).await;
        }
        let mut stored = load(&mut tx, id).await?;
        if stored.artifact.desired_state == ArtifactDesiredState::Deleted {
            let pending:Option<String>=sqlx::query_scalar("SELECT payload FROM operations WHERE resource_id=? AND kind='artifact_delete' AND state IN('pending','running') LIMIT 1")
                .bind(id.to_string()).fetch_optional(&mut *tx).await.map_err(db)?;
            if let Some(payload) = pending {
                let operation: Operation = decode(&payload)?;
                sqlx::query("UPDATE idempotency SET resource_id=? WHERE scope=? AND client_key=?")
                    .bind(operation.id.to_string())
                    .bind(scope)
                    .bind(key)
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
                tx.commit().await.map_err(db)?;
                return Ok(operation);
            }
        }
        let complete = stored.artifact.cleanup == CleanupState::Complete;
        let operation = Operation {
            id: operation_id,
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
        stored.artifact.desired_state = ArtifactDesiredState::Deleted;
        stored.artifact.state = if complete {
            ArtifactState::Deleted
        } else {
            ArtifactState::Deleting
        };
        finish(
            &mut tx,
            id,
            "artifact_create",
            OperationState::Cancelled,
            Some(ApiError::new(
                ErrorCode::Conflict,
                "artifact creation superseded by deletion",
            )),
        )
        .await?;
        save(&mut tx, &stored.artifact).await?;
        sqlx::query("INSERT INTO operations(id,resource_id,kind,state,payload) VALUES(?,?,'artifact_delete',?,?)")
            .bind(operation_id.to_string()).bind(id.to_string()).bind(tag(&operation.state)?).bind(encode(&operation)?)
            .execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(operation)
    }

    /// Publish a worker observation and its operation outcome in one transaction.
    pub async fn observe_artifact(
        &self,
        id: Uuid,
        state: ArtifactState,
        cleanup: CleanupState,
        error: Option<ApiError>,
    ) -> Result<Artifact, ApiError> {
        if cleanup == CleanupState::Complete
            && !matches!(state, ArtifactState::Failed | ArtifactState::Deleted)
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "live artifact content cannot have completed cleanup",
            ));
        }
        if state == ArtifactState::Deleted && cleanup != CleanupState::Complete {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "artifact deletion lacks confirmed cleanup",
            ));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut stored = load(&mut tx, id).await?;
        let previous = &stored.artifact;
        if previous.cleanup == CleanupState::Complete && state != previous.state {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "collected artifacts cannot be resurrected",
            ));
        }
        if state == ArtifactState::Available
            && (previous.sha256.is_none()
                || previous.size_bytes.is_none()
                || cleanup != CleanupState::Pending)
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "available artifact lacks prepared content metadata",
            ));
        }
        if state == ArtifactState::Deleted
            && previous.desired_state != ArtifactDesiredState::Deleted
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "artifact deletion was not requested",
            ));
        }
        let actual = if previous.desired_state == ArtifactDesiredState::Deleted {
            if cleanup == CleanupState::Complete {
                ArtifactState::Deleted
            } else {
                ArtifactState::Deleting
            }
        } else {
            state
        };
        if previous.state != actual
            && !matches!(
                (previous.state, actual),
                (
                    ArtifactState::Pending,
                    ArtifactState::Failed | ArtifactState::Deleting
                ) | (
                    ArtifactState::Uploading,
                    ArtifactState::Available | ArtifactState::Failed | ArtifactState::Deleting
                ) | (ArtifactState::Available, ArtifactState::Deleting)
                    | (ArtifactState::Deleting, ArtifactState::Deleted)
                    | (ArtifactState::Failed, ArtifactState::Deleting)
            )
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "artifact observation violates its lifecycle",
            ));
        }
        stored.artifact.state = actual;
        stored.artifact.cleanup = cleanup;
        stored.artifact.observed_at = Some(Utc::now());
        stored.artifact.error = error.clone();
        save(&mut tx, &stored.artifact).await?;
        match actual {
            ArtifactState::Available => {
                finish(
                    &mut tx,
                    id,
                    "artifact_create",
                    OperationState::Succeeded,
                    None,
                )
                .await?
            }
            ArtifactState::Failed => {
                finish(
                    &mut tx,
                    id,
                    "artifact_create",
                    OperationState::Failed,
                    error,
                )
                .await?
            }
            ArtifactState::Deleted => {
                finish(
                    &mut tx,
                    id,
                    "artifact_delete",
                    OperationState::Succeeded,
                    None,
                )
                .await?
            }
            _ => {}
        }
        tx.commit().await.map_err(db)?;
        Ok(stored.artifact)
    }
}

fn invalid_page() -> ApiError {
    ApiError::new(
        ErrorCode::InvalidRequest,
        "artifact page limit must be 1..1000",
    )
}
