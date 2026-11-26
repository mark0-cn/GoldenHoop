use super::*;
use subtle::ConstantTimeEq;

async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    event: &AuditEvent,
) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO audit(event) VALUES(?)")
        .bind(encode(event)?)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}

fn key_event(id: Uuid, request: Uuid, phase: AuditPhase) -> AuditEvent {
    AuditEvent {
        actor: AuditActor::Bootstrap,
        key_id: None,
        request_id: Some(request),
        target_id: Some(id),
        sandbox_id: None,
        action: if phase == AuditPhase::Created {
            AuditAction::KeyCreate
        } else {
            AuditAction::KeyRevoke
        },
        phase,
        http_status: None,
    }
}

impl Store {
    /// Only the bootstrap administrator's route calls this method. Scoped keys
    /// cannot delegate or acquire key-management authority.
    pub async fn issue_api_key(
        &self,
        spec: &CreateApiKey,
        request_id: Uuid,
    ) -> Result<ApiKeyIssued, ApiError> {
        let now = Utc::now();
        if spec.permissions.is_empty()
            || spec.expires_at <= now
            || spec.expires_at > now + chrono::Duration::days(366)
            || matches!(&spec.resources, KeyResources::Sandboxes(ids) if ids.is_empty() || ids.len()>256)
        {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "invalid key grant or lifetime",
            ));
        }
        let key = ApiKey {
            id: Uuid::new_v4(),
            permissions: spec.permissions.clone(),
            resources: spec.resources.clone(),
            created_at: now,
            expires_at: spec.expires_at,
            revoked_at: None,
        };
        // Two independent v4 UUIDs provide 244 random bits; the public ID is not
        // counted as secret entropy. Only a verifier reaches persistent storage.
        let token = format!(
            "ghk_{}.{}{}",
            key.id.simple(),
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        let verifier = Sha256::digest(token.as_bytes());
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let KeyResources::Sandboxes(ids) = &key.resources {
            for id in ids {
                let exists: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sandboxes WHERE id=?)")
                        .bind(id.to_string())
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(db)?;
                if !exists {
                    return Err(not_found("sandbox"));
                }
            }
        }
        sqlx::query("INSERT INTO api_keys(id,verifier,payload) VALUES(?,?,?)")
            .bind(key.id.to_string())
            .bind(verifier.as_slice())
            .bind(encode(&key)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        audit(&mut tx, &key_event(key.id, request_id, AuditPhase::Created)).await?;
        tx.commit().await.map_err(db)?;
        Ok(ApiKeyIssued { key, token })
    }

    pub async fn api_key(&self, id: Uuid) -> Result<ApiKey, ApiError> {
        let payload: String = sqlx::query_scalar("SELECT payload FROM api_keys WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("API key"))?;
        decode(&payload)
    }

    pub async fn authenticate_api_key(&self, token: &str) -> Result<ApiKey, ApiError> {
        let invalid = || {
            ApiError::new(
                ErrorCode::Unauthorized,
                "valid bearer authentication is required",
            )
        };
        let id = token
            .strip_prefix("ghk_")
            .and_then(|v| v.split_once('.'))
            .filter(|(id, secret)| {
                id.len() == 32
                    && secret.len() == 64
                    && secret.bytes().all(|v| v.is_ascii_hexdigit())
            })
            .and_then(|(id, _)| Uuid::parse_str(id).ok())
            .ok_or_else(invalid)?;
        let row = sqlx::query("SELECT verifier,payload FROM api_keys WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(invalid)?;
        let verifier: Vec<u8> = row.try_get("verifier").map_err(db)?;
        let supplied = Sha256::digest(token.as_bytes());
        if !bool::from(verifier.as_slice().ct_eq(supplied.as_slice())) {
            return Err(invalid());
        }
        let key: ApiKey = decode(row.try_get("payload").map_err(db)?)?;
        if key.revoked_at.is_some() || key.expires_at <= Utc::now() {
            return Err(invalid());
        }
        Ok(key)
    }

    pub async fn revoke_api_key(&self, id: Uuid, request_id: Uuid) -> Result<ApiKey, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let payload: String = sqlx::query_scalar("SELECT payload FROM api_keys WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("API key"))?;
        let mut key: ApiKey = decode(&payload)?;
        if key.revoked_at.is_none() {
            key.revoked_at = Some(Utc::now());
            sqlx::query("UPDATE api_keys SET payload=? WHERE id=?")
                .bind(encode(&key)?)
                .bind(id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            audit(&mut tx, &key_event(id, request_id, AuditPhase::Revoked)).await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(key)
    }

    pub async fn append_audit(&self, event: &AuditEvent) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        audit(&mut tx, event).await?;
        tx.commit().await.map_err(db)
    }

    pub async fn audit_page(&self, after: u64, limit: u32) -> Result<AuditPage, ApiError> {
        self.audit_page_through(after, limit, None).await
    }

    pub async fn audit_page_through(
        &self,
        after: u64,
        limit: u32,
        through: Option<u64>,
    ) -> Result<AuditPage, ApiError> {
        if !(1..=1000).contains(&limit) || after > i64::MAX as u64 {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "invalid audit page",
            ));
        }
        let maximum: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(sequence),0) FROM audit")
            .fetch_one(&self.pool)
            .await
            .map_err(db)?;
        let through_sequence = through.unwrap_or(maximum as u64);
        if through_sequence > maximum as u64 || after > through_sequence {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "invalid audit snapshot",
            ));
        }
        let rows = sqlx::query(
            "SELECT * FROM audit WHERE sequence>? AND sequence<=? ORDER BY sequence LIMIT ?",
        )
        .bind(after as i64)
        .bind(through_sequence as i64)
        .bind(i64::from(limit) + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut items = Vec::new();
        let more = rows.len() > limit as usize;
        for row in rows.into_iter().take(limit as usize) {
            let observation: Option<String> = row.try_get("observation").map_err(db)?;
            items.push(AuditRecord {
                sequence: row
                    .try_get::<i64, _>("sequence")
                    .map_err(db)?
                    .try_into()
                    .map_err(|_| internal())?,
                timestamp: row
                    .try_get::<&str, _>("timestamp")
                    .map_err(db)?
                    .parse()
                    .map_err(|_| internal())?,
                event: decode(row.try_get("event").map_err(db)?)?,
                observation: observation.as_deref().map(decode).transpose()?,
            });
        }
        let next_after = more.then(|| items.last().expect("nonempty page").sequence);
        Ok(AuditPage {
            items,
            next_after,
            through_sequence,
        })
    }
}
