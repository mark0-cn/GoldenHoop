//! Bridge/workload create dispatch and settlement, never lease authority.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkCreateKind {
    Bridge,
    Workload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCreateDispatch {
    pub sandbox_id: Uuid,
    pub allocation_generation: Uuid,
    pub kind: NetworkCreateKind,
    pub attempt: Uuid,
    pub request_sha256: String,
    pub dispatched_at: DateTime<Utc>,
    pub settled_at: Option<DateTime<Utc>>,
    pub physical_id: Option<String>,
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn conflict() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "protected network create dispatch differs",
    )
}
fn validate(record: &NetworkCreateDispatch) -> Result<(), ApiError> {
    if record.sandbox_id.is_nil()
        || record.allocation_generation.is_nil()
        || record.attempt.is_nil()
        || !digest(&record.request_sha256)
        || record
            .settled_at
            .is_some_and(|time| time < record.dispatched_at)
        || record
            .physical_id
            .as_ref()
            .is_some_and(|id| !digest(id) || record.settled_at.is_none())
    {
        return Err(internal());
    }
    Ok(())
}
async fn source(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    kind: NetworkCreateKind,
) -> Result<Option<NetworkCreateDispatch>, ApiError> {
    let row = sqlx::query("SELECT * FROM network_create_dispatches WHERE sandbox_id=? AND kind=?")
        .bind(id.to_string())
        .bind(tag(&kind)?)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?;
    row.map(|row| {
        let record: NetworkCreateDispatch = decode(row.try_get("payload").map_err(db)?)?;
        validate(&record)?;
        if record.sandbox_id != id
            || record.kind != kind
            || row
                .try_get::<&str, _>("allocation_generation")
                .map_err(db)?
                != record.allocation_generation.to_string()
            || row.try_get::<&str, _>("attempt").map_err(db)? != record.attempt.to_string()
        {
            return Err(internal());
        }
        Ok(record)
    })
    .transpose()
}
pub(super) async fn require_settled(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<(), ApiError> {
    for kind in [NetworkCreateKind::Bridge, NetworkCreateKind::Workload] {
        if source(tx, id, kind)
            .await?
            .is_some_and(|r| r.settled_at.is_none())
        {
            return Err(ApiError::new(
                ErrorCode::BackendUnavailable,
                "protected network creation remains unsettled",
            ));
        }
    }
    Ok(())
}
impl Store {
    pub async fn network_create_dispatch(
        &self,
        id: Uuid,
        kind: NetworkCreateKind,
    ) -> Result<Option<NetworkCreateDispatch>, ApiError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let record = source(&mut tx, id, kind).await?;
        tx.commit().await.map_err(db)?;
        Ok(record)
    }
    pub async fn begin_network_create(
        &self,
        id: Uuid,
        generation: Uuid,
        kind: NetworkCreateKind,
        request_sha256: &str,
    ) -> Result<NetworkCreateDispatch, ApiError> {
        if !digest(request_sha256) {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "invalid network create fingerprint",
            ));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if source(&mut tx, id, kind).await?.is_some() {
            return Err(conflict());
        }
        if kind == NetworkCreateKind::Workload
            && source(&mut tx, id, NetworkCreateKind::Bridge)
                .await?
                .is_some_and(|r| r.settled_at.is_none())
        {
            return Err(conflict());
        }
        let network = super::networks::source(&mut tx, id, self.installation_id).await?;
        let stored = super::isolated::source(&mut tx, id).await?;
        let stage = match kind {
            NetworkCreateKind::Bridge => {
                network.native_binding().is_none()
                    && matches!(
                        stored.sandbox.state,
                        SandboxState::Pending | SandboxState::Starting
                    )
            }
            NetworkCreateKind::Workload => {
                network.native_binding().is_some() && stored.sandbox.state == SandboxState::Starting
            }
        };
        if network.generation != generation
            || network.phase != NetworkPhase::Provisioning
            || !stage
            || stored.sandbox.desired_state != DesiredState::Running
            || stored.ever_running
            || stored.handle.is_some()
            || goldenhoop_core::expired(&stored.sandbox, Utc::now())
        {
            return Err(conflict());
        }
        let record = NetworkCreateDispatch {
            sandbox_id: id,
            allocation_generation: generation,
            kind,
            attempt: Uuid::new_v4(),
            request_sha256: request_sha256.into(),
            dispatched_at: Utc::now(),
            settled_at: None,
            physical_id: None,
        };
        validate(&record)?;
        sqlx::query("INSERT INTO network_create_dispatches(sandbox_id,kind,allocation_generation,attempt,payload) VALUES(?,?,?,?,?)")
            .bind(id.to_string()).bind(tag(&kind)?).bind(generation.to_string()).bind(record.attempt.to_string()).bind(encode(&record)?)
            .execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(record)
    }
    /// Only a correlated daemon response or freshly validated owned physical
    /// identity may call this host method. Empty inventory cannot settle I/O.
    pub async fn settle_network_create(
        &self,
        id: Uuid,
        kind: NetworkCreateKind,
        attempt: Uuid,
        physical_id: Option<&str>,
    ) -> Result<NetworkCreateDispatch, ApiError> {
        if physical_id.is_some_and(|id| !digest(id)) {
            return Err(conflict());
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut record = source(&mut tx, id, kind).await?.ok_or_else(conflict)?;
        if record.attempt != attempt
            || record
                .physical_id
                .as_deref()
                .zip(physical_id)
                .is_some_and(|(old, new)| old != new)
        {
            return Err(conflict());
        }
        let network = super::networks::source(&mut tx, id, self.installation_id).await?;
        if network.generation != record.allocation_generation {
            return Err(conflict());
        }
        if record.settled_at.is_none() {
            record.settled_at = Some(Utc::now());
        }
        if let Some(id) = physical_id {
            record.physical_id = Some(id.into());
        }
        validate(&record)?;
        sqlx::query("UPDATE network_create_dispatches SET payload=? WHERE sandbox_id=? AND kind=? AND attempt=?")
            .bind(encode(&record)?).bind(id.to_string()).bind(tag(&kind)?).bind(attempt.to_string()).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(record)
    }
    pub async fn require_network_creates_settled(&self, id: Uuid) -> Result<(), ApiError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        require_settled(&mut tx, id).await?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }
}
