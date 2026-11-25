//! Durable trusted-controller identity and dispatch fences; never packet grants.
use super::*;
use goldenhoop_egress::{ControllerPlan, native::NativeBridgePlan};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerPhase {
    Reserved,
    Creating,
    Created,
    Starting,
    Running,
    Collecting,
    Collected,
}

/// Supplied by the trusted collector after all dispatched writes are settled and
/// the exact provider identity is absent. This type performs no native lookup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerAbsence {
    pub container_id: Option<String>,
    pub creation_settled: bool,
    pub start_settled: bool,
    pub provider_absent: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkController {
    pub installation_id: Uuid,
    pub sandbox_id: Uuid,
    pub allocation_generation: Uuid,
    pub controller_generation: Uuid,
    pub network_id: String,
    pub plan: ControllerPlan,
    pub revision: u64,
    pub phase: ControllerPhase,
    pub container_id: Option<String>,
    pub create_token: Option<Uuid>,
    pub start_token: Option<Uuid>,
    pub collection_token: Option<Uuid>,
    pub absence: Option<ControllerAbsence>,
}
fn conflict() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "controller journal identity or dispatch phase differs",
    )
}
fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl NetworkController {
    fn validate(&self, installation: Uuid) -> Result<(), ApiError> {
        self.plan.validate().map_err(|_| internal())?;
        let identity = &self.plan.native.identity;
        if self.installation_id != installation
            || self.installation_id != identity.installation_id
            || self.sandbox_id != identity.sandbox_id
            || self.allocation_generation != identity.generation
            || self.controller_generation.is_nil()
            || self.plan.controller_generation != Some(self.controller_generation)
            || !valid_id(&self.network_id)
            || self.revision > i64::MAX as u64
            || self.container_id.as_deref().is_some_and(|s| !valid_id(s))
            || [self.create_token, self.start_token, self.collection_token]
                .iter()
                .flatten()
                .any(Uuid::is_nil)
            || (self.container_id.is_some() && self.create_token.is_none())
            || (self.start_token.is_some()
                && (self.create_token.is_none() || self.container_id.is_none()))
            || (self.phase == ControllerPhase::Collected) != self.absence.is_some()
            || (matches!(
                self.phase,
                ControllerPhase::Collecting | ControllerPhase::Collected
            )) != self.collection_token.is_some()
        {
            return Err(internal());
        }
        let invalid = match self.phase {
            ControllerPhase::Reserved => {
                self.create_token.is_some()
                    || self.container_id.is_some()
                    || self.start_token.is_some()
            }
            ControllerPhase::Creating => {
                self.create_token.is_none()
                    || self.container_id.is_some()
                    || self.start_token.is_some()
            }
            ControllerPhase::Created => {
                self.create_token.is_none()
                    || self.container_id.is_none()
                    || self.start_token.is_some()
            }
            ControllerPhase::Starting | ControllerPhase::Running => {
                self.create_token.is_none()
                    || self.container_id.is_none()
                    || self.start_token.is_none()
            }
            ControllerPhase::Collecting => false,
            ControllerPhase::Collected => {
                self.create_token.is_some() && self.container_id.is_none()
            }
        };
        if invalid
            || self.absence.as_ref().is_some_and(|a| {
                !a.creation_settled
                    || !a.start_settled
                    || !a.provider_absent
                    || a.container_id != self.container_id
            })
        {
            return Err(internal());
        }
        Ok(())
    }
}
fn row(value: &sqlx::sqlite::SqliteRow, installation: Uuid) -> Result<NetworkController, ApiError> {
    let record: NetworkController = decode(value.try_get("payload").map_err(db)?)?;
    record.validate(installation)?;
    if value
        .try_get::<&str, _>("controller_generation")
        .map_err(db)?
        != record.controller_generation.to_string()
        || value.try_get::<&str, _>("sandbox_id").map_err(db)? != record.sandbox_id.to_string()
        || value
            .try_get::<&str, _>("allocation_generation")
            .map_err(db)?
            != record.allocation_generation.to_string()
        || value.try_get::<&str, _>("phase").map_err(db)? != tag(&record.phase)?
        || value.try_get::<i64, _>("revision").map_err(db)? != record.revision as i64
        || value
            .try_get::<Option<String>, _>("container_id")
            .map_err(db)?
            != record.container_id
    {
        return Err(internal());
    }
    Ok(record)
}
async fn source(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    generation: Uuid,
    installation: Uuid,
) -> Result<NetworkController, ApiError> {
    let value = sqlx::query(
        "SELECT * FROM network_controllers WHERE sandbox_id=? AND controller_generation=?",
    )
    .bind(id.to_string())
    .bind(generation.to_string())
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?
    .ok_or_else(|| not_found("controller"))?;
    row(&value, installation)
}
async fn save(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    value: &mut NetworkController,
) -> Result<(), ApiError> {
    let previous = value.revision;
    value.revision = previous
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or_else(conflict)?;
    value.validate(value.installation_id)?;
    let changed=sqlx::query("UPDATE network_controllers SET phase=?,revision=?,container_id=?,payload=? WHERE controller_generation=? AND revision=?")
        .bind(tag(&value.phase)?).bind(value.revision as i64).bind(&value.container_id).bind(encode(value)?).bind(value.controller_generation.to_string()).bind(previous as i64).execute(&mut **tx).await.map_err(db)?;
    if changed.rows_affected() != 1 {
        return Err(conflict());
    }
    sqlx::query("INSERT INTO network_controller_events(controller_generation,revision,payload) VALUES(?,?,?)").bind(value.controller_generation.to_string()).bind(value.revision as i64).bind(encode(value)?).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
async fn live(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    value: &NetworkController,
) -> Result<(), ApiError> {
    value.plan.validate_dispatch_at(Utc::now())?;
    let network = super::networks::source(tx, value.sandbox_id, value.installation_id).await?;
    let native = network.native_binding().ok_or_else(conflict)?;
    let sandbox = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
        .bind(value.sandbox_id.to_string())
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
    let sandbox = sandbox_row(&sandbox)?;
    if network.generation != value.allocation_generation
        || !matches!(
            network.phase,
            NetworkPhase::Provisioning | NetworkPhase::Bound
        )
        || network.token != Some(value.plan.native.provisioning_token)
        || native.network_id != value.network_id
        || fingerprint(&native.allocation)? != fingerprint(&value.plan.native.allocation)?
        || sandbox.sandbox.profile != value.plan.native.identity.profile
        || sandbox.sandbox.expires_at != value.plan.native.expires_at
        || sandbox.sandbox.desired_state != DesiredState::Running
        || sandbox.sandbox.cleanup == CleanupState::Complete
        || !matches!(
            sandbox.sandbox.state,
            SandboxState::Pending | SandboxState::Starting | SandboxState::Running
        )
    {
        return Err(conflict());
    }
    Ok(())
}
pub(super) async fn require_collected(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<(), ApiError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM network_controllers WHERE sandbox_id=? AND phase<>'collected'",
    )
    .bind(id.to_string())
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if count != 0 {
        return Err(ApiError::new(
            ErrorCode::InvalidState,
            "controller cleanup is not confirmed",
        ));
    }
    Ok(())
}
pub(super) async fn collect_all(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    installation: Uuid,
) -> Result<(), ApiError> {
    let rows=sqlx::query("SELECT * FROM network_controllers WHERE sandbox_id=? AND phase NOT IN('collecting','collected')").bind(id.to_string()).fetch_all(&mut **tx).await.map_err(db)?;
    for item in rows {
        let mut value = row(&item, installation)?;
        value.phase = ControllerPhase::Collecting;
        value.collection_token = Some(Uuid::new_v4());
        save(tx, &mut value).await?;
    }
    Ok(())
}
impl Store {
    pub async fn network_controller(
        &self,
        id: Uuid,
        generation: Uuid,
    ) -> Result<NetworkController, ApiError> {
        let row_value = sqlx::query(
            "SELECT * FROM network_controllers WHERE sandbox_id=? AND controller_generation=?",
        )
        .bind(id.to_string())
        .bind(generation.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("controller"))?;
        row(&row_value, self.installation_id)
    }
    pub async fn active_network_controller(
        &self,
        id: Uuid,
    ) -> Result<Option<NetworkController>, ApiError> {
        let value = sqlx::query(
            "SELECT * FROM network_controllers WHERE sandbox_id=? AND phase<>'collected'",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        value
            .as_ref()
            .map(|v| row(v, self.installation_id))
            .transpose()
    }
    pub async fn network_controller_history(
        &self,
        id: Uuid,
        generation: Uuid,
        after: Option<u64>,
        limit: u16,
    ) -> Result<Vec<NetworkController>, ApiError> {
        if !(1..=128).contains(&limit) || after.is_some_and(|n| n > i64::MAX as u64) {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "invalid controller history cursor",
            ));
        }
        self.network_controller(id, generation).await?;
        let rows=sqlx::query("SELECT revision,payload FROM network_controller_events WHERE controller_generation=? AND revision>? ORDER BY revision LIMIT ?").bind(generation.to_string()).bind(after.map_or(-1,|n|n as i64)).bind(i64::from(limit)).fetch_all(&self.pool).await.map_err(db)?;
        rows.iter()
            .map(|item| {
                let value: NetworkController = decode(item.try_get("payload").map_err(db)?)?;
                value.validate(self.installation_id)?;
                if value.sandbox_id != id
                    || value.controller_generation != generation
                    || item.try_get::<i64, _>("revision").map_err(db)? != value.revision as i64
                {
                    return Err(internal());
                }
                Ok(value)
            })
            .collect()
    }
    /// Persist the complete immutable plan before any controller creation. The
    /// caller supplies a new epoch deliberately; replay never creates an epoch.
    pub async fn reserve_network_controller(
        &self,
        id: Uuid,
        allocation_generation: Uuid,
        generation: Uuid,
        image_id: &str,
    ) -> Result<NetworkController, ApiError> {
        if generation.is_nil() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "controller generation is required",
            ));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(existing) =
            sqlx::query("SELECT * FROM network_controllers WHERE controller_generation=?")
                .bind(generation.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
        {
            let value = row(&existing, self.installation_id)?;
            if value.sandbox_id != id
                || value.allocation_generation != allocation_generation
                || value.plan.image_id != image_id
            {
                return Err(conflict());
            }
            tx.commit().await.map_err(db)?;
            return Ok(value);
        }
        require_collected(&mut tx, id).await?;
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM network_controllers WHERE sandbox_id=?")
                .bind(id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        if count >= 128 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "controller history budget exhausted",
            ));
        }
        let network = super::networks::source(&mut tx, id, self.installation_id).await?;
        if network.generation != allocation_generation {
            return Err(conflict());
        }
        let native = network.native_binding().ok_or_else(conflict)?;
        let sandbox = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
            .bind(id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let sandbox = sandbox_row(&sandbox)?;
        let value = NetworkController {
            installation_id: self.installation_id,
            sandbox_id: id,
            allocation_generation,
            controller_generation: generation,
            network_id: native.network_id,
            plan: ControllerPlan {
                native: NativeBridgePlan {
                    identity: network.identity(),
                    allocation: native.allocation,
                    provisioning_token: network.token.ok_or_else(conflict)?,
                    expires_at: sandbox.sandbox.expires_at,
                },
                image_id: image_id.to_owned(),
                controller_generation: Some(generation),
            },
            revision: 0,
            phase: ControllerPhase::Reserved,
            container_id: None,
            create_token: None,
            start_token: None,
            collection_token: None,
            absence: None,
        };
        value.plan.validate()?;
        value.validate(self.installation_id)?;
        live(&mut tx, &value).await?;
        sqlx::query("INSERT INTO network_controllers(controller_generation,sandbox_id,allocation_generation,phase,revision,payload) VALUES(?,?,?,'reserved',0,?)").bind(generation.to_string()).bind(id.to_string()).bind(allocation_generation.to_string()).bind(encode(&value)?).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("INSERT INTO network_controller_events(controller_generation,revision,payload) VALUES(?,0,?)").bind(generation.to_string()).bind(encode(&value)?).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    pub async fn begin_controller_create(
        &self,
        id: Uuid,
        generation: Uuid,
        expected: u64,
    ) -> Result<NetworkController, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, generation, self.installation_id).await?;
        if value.revision != expected || value.phase != ControllerPhase::Reserved {
            return Err(conflict());
        }
        live(&mut tx, &value).await?;
        value.phase = ControllerPhase::Creating;
        value.create_token = Some(Uuid::new_v4());
        save(&mut tx, &mut value).await?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    pub async fn record_controller_created(
        &self,
        id: Uuid,
        generation: Uuid,
        token: Uuid,
        container_id: &str,
    ) -> Result<NetworkController, ApiError> {
        if !valid_id(container_id) {
            return Err(conflict());
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, generation, self.installation_id).await?;
        if value.create_token != Some(token)
            || value
                .container_id
                .as_deref()
                .is_some_and(|old| old != container_id)
        {
            return Err(conflict());
        }
        if value.container_id.is_some() {
            tx.commit().await.map_err(db)?;
            return Ok(value);
        }
        if !matches!(
            value.phase,
            ControllerPhase::Creating | ControllerPhase::Collecting
        ) {
            return Err(conflict());
        }
        let reused: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM network_controllers WHERE container_id=?")
                .bind(container_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        if reused != 0 {
            return Err(conflict());
        }
        if value.phase == ControllerPhase::Creating {
            live(&mut tx, &value).await?;
            value.phase = ControllerPhase::Created;
        }
        value.container_id = Some(container_id.into());
        save(&mut tx, &mut value).await?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    pub async fn begin_controller_start(
        &self,
        id: Uuid,
        generation: Uuid,
        expected: u64,
    ) -> Result<NetworkController, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, generation, self.installation_id).await?;
        if value.revision != expected || value.phase != ControllerPhase::Created {
            return Err(conflict());
        }
        live(&mut tx, &value).await?;
        value.phase = ControllerPhase::Starting;
        value.start_token = Some(Uuid::new_v4());
        save(&mut tx, &mut value).await?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    /// Running records a process observation, never a packet guard or lease.
    pub async fn record_controller_running(
        &self,
        id: Uuid,
        generation: Uuid,
        token: Uuid,
        container_id: &str,
    ) -> Result<NetworkController, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, generation, self.installation_id).await?;
        if value.start_token != Some(token) || value.container_id.as_deref() != Some(container_id) {
            return Err(conflict());
        }
        if value.phase == ControllerPhase::Running {
            tx.commit().await.map_err(db)?;
            return Ok(value);
        }
        if value.phase != ControllerPhase::Starting {
            return Err(conflict());
        }
        live(&mut tx, &value).await?;
        value.phase = ControllerPhase::Running;
        save(&mut tx, &mut value).await?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    pub async fn begin_controller_collection(
        &self,
        id: Uuid,
        generation: Uuid,
        expected: u64,
    ) -> Result<NetworkController, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, generation, self.installation_id).await?;
        if value.revision != expected {
            return Err(conflict());
        }
        if !matches!(
            value.phase,
            ControllerPhase::Collecting | ControllerPhase::Collected
        ) {
            value.phase = ControllerPhase::Collecting;
            value.collection_token = Some(Uuid::new_v4());
            save(&mut tx, &mut value).await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    pub async fn confirm_controller_absence(
        &self,
        id: Uuid,
        generation: Uuid,
        token: Uuid,
        absence: ControllerAbsence,
    ) -> Result<NetworkController, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, generation, self.installation_id).await?;
        if value.collection_token != Some(token) {
            return Err(conflict());
        }
        if value.phase == ControllerPhase::Collected && value.absence.as_ref() == Some(&absence) {
            tx.commit().await.map_err(db)?;
            return Ok(value);
        }
        let age = Utc::now().signed_duration_since(absence.observed_at);
        if value.phase != ControllerPhase::Collecting
            || !absence.creation_settled
            || !absence.start_settled
            || !absence.provider_absent
            || absence.container_id != value.container_id
            || (value.create_token.is_some() && value.container_id.is_none())
            || age > chrono::Duration::seconds(5)
            || age < chrono::Duration::seconds(-5)
        {
            return Err(conflict());
        }
        value.phase = ControllerPhase::Collected;
        value.absence = Some(absence);
        save(&mut tx, &mut value).await?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    /// Fresh positive residue revokes old cleanup atomically, never reactivates a
    /// controller and never accepts a cached observation older than its absence.
    pub async fn reopen_controller_collection(
        &self,
        id: Uuid,
        generation: Uuid,
        container_id: &str,
        observed_at: DateTime<Utc>,
    ) -> Result<NetworkController, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, generation, self.installation_id).await?;
        let age = Utc::now().signed_duration_since(observed_at);
        if value.container_id.as_deref() != Some(container_id)
            || value.phase != ControllerPhase::Collected
            || value
                .absence
                .as_ref()
                .is_none_or(|a| observed_at <= a.observed_at)
            || age > chrono::Duration::seconds(5)
            || age < chrono::Duration::seconds(-5)
        {
            return Err(conflict());
        }
        let mut network = super::networks::source(&mut tx, id, self.installation_id).await?;
        value.phase = ControllerPhase::Collecting;
        value.collection_token = Some(Uuid::new_v4());
        value.absence = None;
        save(&mut tx, &mut value).await?;
        if network.phase == NetworkPhase::Collected {
            network.phase = NetworkPhase::Unknown;
            network.token = None;
            network.absence = None;
            super::networks::save(&mut tx, &mut network).await?;
            let sandbox = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
                .bind(id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
            let mut sandbox = sandbox_row(&sandbox)?.sandbox;
            sandbox.state = SandboxState::Unknown;
            sandbox.desired_state = DesiredState::Terminated;
            sandbox.cleanup = CleanupState::Unknown;
            sandbox.observed_at = Some(Utc::now());
            sandbox.reason = Some("owned controller residue requires collection".into());
            sqlx::query("UPDATE sandboxes SET desired='terminated',state='unknown',cleanup='unknown',payload=? WHERE id=?").bind(encode(&sandbox)?).bind(id.to_string()).execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
}
