use super::*;
use goldenhoop_credentials::{
    BindingSpec, CredentialBinding, CredentialState, Sealed, SecretSource, VaultKey,
    WriteCredential,
};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
struct PrivateCredential {
    binding: BindingSpec,
    secret: SecretSource,
}

fn event(request: Uuid, sandbox: Uuid, id: Uuid, phase: AuditPhase) -> AuditEvent {
    AuditEvent {
        actor: AuditActor::Bootstrap,
        key_id: None,
        request_id: Some(request),
        target_id: Some(id),
        sandbox_id: Some(sandbox),
        action: AuditAction::Credential,
        phase,
        http_status: None,
    }
}

impl Store {
    pub async fn credential(&self, sandbox: Uuid, id: Uuid) -> Result<CredentialBinding, ApiError> {
        let payload: String = sqlx::query_scalar(
            "SELECT payload FROM credential_bindings WHERE sandbox_id=? AND id=?",
        )
        .bind(sandbox.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("credential binding"))?;
        decode(&payload)
    }

    pub async fn credentials(&self, sandbox: Uuid) -> Result<Vec<CredentialBinding>, ApiError> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT payload FROM credential_bindings WHERE sandbox_id=? ORDER BY id LIMIT 257",
        )
        .bind(sandbox.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        if rows.len() > 256 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "credential binding limit exceeded",
            ));
        }
        rows.iter().map(|p| decode(p)).collect()
    }

    pub async fn put_credential(
        &self,
        key: &VaultKey,
        request_id: Uuid,
        sandbox: Uuid,
        id: Uuid,
        input: WriteCredential,
    ) -> Result<CredentialBinding, ApiError> {
        if input.expected_revision >= i64::MAX as u64 || id.is_nil() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "invalid credential identity or revision",
            ));
        }
        let binding = input.binding.canonicalize()?;
        if let SecretSource::Exchange { resolver } = &input.secret
            && (resolver.is_empty()
                || resolver.len() > 64
                || !resolver
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')))
        {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "invalid trusted exchange resolver identity",
            ));
        }
        let private = PrivateCredential {
            binding: binding.clone(),
            secret: input.secret,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&private).map_err(|_| internal())?);
        let fingerprint = key.fingerprint(
            format!("{}:{sandbox}:{id}", self.installation_id()).as_bytes(),
            &plaintext,
        )?;
        let revision = input.expected_revision + 1;
        let sealed = key.seal(self.installation_id(), sandbox, id, revision, &plaintext)?;
        let record = CredentialBinding {
            id,
            sandbox_id: sandbox,
            revision,
            applied_revision: None,
            state: CredentialState::Pending,
            binding,
        };
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        super::isolated::require_feature_limit(&mut tx, sandbox, Capability::SecretInjection)
            .await?;
        if super::isolated::effective_desired(&mut tx, sandbox).await? == DesiredState::Terminated {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "sandbox or ancestor is not accepting credential changes",
            ));
        }
        // A missing parent or terminated lifecycle cannot acquire a secret.
        let parent = sandbox_row(
            &sqlx::query("SELECT * FROM sandboxes WHERE id=?")
                .bind(sandbox.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or_else(|| not_found("sandbox"))?,
        )?;
        if parent.sandbox.desired_state == DesiredState::Terminated
            || parent.sandbox.expires_at <= Utc::now()
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "sandbox is not accepting credential changes",
            ));
        }
        let existing = sqlx::query(
            "SELECT sandbox_id,revision,fingerprint,payload FROM credential_bindings WHERE id=?",
        )
        .bind(id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if let Some(existing) = existing {
            if existing.try_get::<String, _>("sandbox_id").map_err(db)? != sandbox.to_string() {
                return Err(not_found("credential binding"));
            }
            let observed: i64 = existing.try_get("revision").map_err(db)?;
            if observed == revision as i64
                && existing.try_get::<String, _>("fingerprint").map_err(db)? == fingerprint
            {
                let value = decode(existing.try_get("payload").map_err(db)?)?;
                tx.commit().await.map_err(db)?;
                return Ok(value);
            }
            if observed != input.expected_revision as i64 {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "credential revision changed",
                ));
            }
        } else if input.expected_revision != 0 {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "credential revision changed",
            ));
        }
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM credential_bindings WHERE sandbox_id=?")
                .bind(sandbox.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        if count >= 256 && input.expected_revision == 0 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "credential binding limit exceeded",
            ));
        }
        sqlx::query("INSERT INTO credential_bindings(id,sandbox_id,revision,fingerprint,payload,sealed) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,fingerprint=excluded.fingerprint,payload=excluded.payload,sealed=excluded.sealed")
            .bind(id.to_string()).bind(sandbox.to_string()).bind(revision as i64).bind(fingerprint).bind(encode(&record)?).bind(encode(&sealed)?)
            .execute(&mut *tx).await.map_err(db)?;
        sqlx::query("INSERT INTO audit(event,observation) VALUES(?,?)")
            .bind(encode(&event(
                request_id,
                sandbox,
                id,
                AuditPhase::Created,
            ))?)
            .bind(serde_json::json!({"desired_revision":revision,"state":"pending"}).to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(record)
    }

    /// Trusted broker input only. Public routes never call this method.
    pub async fn credential_secret(
        &self,
        key: &VaultKey,
        sandbox: Uuid,
        id: Uuid,
        revision: u64,
    ) -> Result<SecretSource, ApiError> {
        let row=sqlx::query("SELECT payload,sealed FROM credential_bindings WHERE sandbox_id=? AND id=? AND revision=?")
            .bind(sandbox.to_string()).bind(id.to_string()).bind(revision as i64).fetch_optional(&self.pool).await.map_err(db)?.ok_or_else(||not_found("current credential"))?;
        let metadata: CredentialBinding = decode(row.try_get("payload").map_err(db)?)?;
        if matches!(
            metadata.state,
            CredentialState::Revoking | CredentialState::Revoked | CredentialState::Failed
        ) {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "credential is not available",
            ));
        }
        let sealed: Option<String> = row.try_get("sealed").map_err(db)?;
        let sealed: Sealed = decode(
            sealed
                .as_deref()
                .ok_or_else(|| not_found("current credential"))?,
        )?;
        let plaintext = key.unseal(self.installation_id(), sandbox, id, revision, &sealed)?;
        let private: PrivateCredential =
            serde_json::from_slice(&plaintext).map_err(|_| internal())?;
        if private.binding != metadata.binding {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "credential metadata authentication failed",
            ));
        }
        Ok(private.secret)
    }

    /// Revoking is intent, not a claim that old in-flight transports are gone.
    pub async fn revoke_credential(
        &self,
        request_id: Uuid,
        sandbox: Uuid,
        id: Uuid,
    ) -> Result<CredentialBinding, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let payload: String = sqlx::query_scalar(
            "SELECT payload FROM credential_bindings WHERE sandbox_id=? AND id=?",
        )
        .bind(sandbox.to_string())
        .bind(id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("credential binding"))?;
        let mut record: CredentialBinding = decode(&payload)?;
        if !matches!(
            record.state,
            CredentialState::Revoking | CredentialState::Revoked
        ) {
            record.revision = record
                .revision
                .checked_add(1)
                .filter(|v| *v < i64::MAX as u64)
                .ok_or_else(internal)?;
            record.state = CredentialState::Revoking;
            sqlx::query("UPDATE credential_bindings SET revision=?,payload=?,sealed=NULL,fingerprint='' WHERE id=?")
                .bind(record.revision as i64).bind(encode(&record)?).bind(id.to_string()).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("INSERT INTO audit(event,observation) VALUES(?,?)")
                .bind(encode(&event(
                    request_id,
                    sandbox,
                    id,
                    AuditPhase::RequestStarted,
                ))?)
                .bind(
                    serde_json::json!({"desired_revision":record.revision,"state":"revoking"})
                        .to_string(),
                )
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(record)
    }
}
