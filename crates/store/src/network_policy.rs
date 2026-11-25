//! Desired policy, exact recovery context and dispatch ownership. No stored
//! receipt is authority to publish Ready or to resume a monotonic lease.
use super::*;
use goldenhoop_egress::{Config, EffectivePolicyReceipt, ProtectedBindingReceipt};
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicyPhase {
    Pending,
    Recovering,
    Applying,
    Active,
    Fenced,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyOwner {
    pub worker_id: Uuid,
    pub controller_generation: Uuid,
    pub container_id: String,
    pub token: Uuid,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyControl {
    pub sandbox_id: Uuid,
    pub allocation_generation: Uuid,
    pub revision: u64,
    pub desired_revision: u64,
    pub config: Config,
    pub config_sha256: String,
    pub upstream: SocketAddr,
    /// The original observed immutable context, not a current kernel claim.
    pub checkpoint: ProtectedBindingReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_inputs: Option<NetworkPolicyInputs>,
    pub phase: NetworkPolicyPhase,
    pub owner: Option<NetworkPolicyOwner>,
    pub attempt: Option<Uuid>,
    /// Historical acknowledgement only. Never reconstruct a local live lease.
    pub observation: Option<EffectivePolicyReceipt>,
}
fn conflict() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "network policy ownership or desired revision differs",
    )
}
impl NetworkPolicyControl {
    pub(super) fn validate(&self, installation: Uuid) -> Result<(), ApiError> {
        self.checkpoint.validate().map_err(|_| internal())?;
        goldenhoop_egress::dns::Upstream::new(self.upstream).map_err(|_| internal())?;
        if let Some(inputs) = &self.public_inputs {
            inputs.validate(self.sandbox_id)?;
        }
        if self.sandbox_id.is_nil()
            || self.allocation_generation.is_nil()
            || self.checkpoint.allocation.installation_id != installation
            || self.checkpoint.allocation.sandbox_id != self.sandbox_id
            || self.checkpoint.allocation.generation != self.allocation_generation
            || self.revision > i64::MAX as u64
            || self.desired_revision > self.revision
            || self.config.digest().map_err(|_| internal())? != self.config_sha256
            || self.attempt.is_some_and(|t| t.is_nil())
            || self.owner.as_ref().is_some_and(|o| {
                o.worker_id.is_nil()
                    || o.controller_generation.is_nil()
                    || o.token.is_nil()
                    || o.container_id.len() != 64
                    || !o
                        .container_id
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
            || (matches!(
                self.phase,
                NetworkPolicyPhase::Recovering
                    | NetworkPolicyPhase::Applying
                    | NetworkPolicyPhase::Active
            ) && self.owner.is_none())
            || (self.phase == NetworkPolicyPhase::Applying) != self.attempt.is_some()
            || (self.phase == NetworkPolicyPhase::Active) != self.observation.is_some()
        {
            return Err(internal());
        }
        if let Some(receipt) = &self.observation {
            receipt
                .validate_config(&self.config)
                .map_err(|_| internal())?;
            same_context(&self.checkpoint, &receipt.binding).map_err(|_| internal())?;
        }
        Ok(())
    }
}
fn same_context(
    expected: &ProtectedBindingReceipt,
    actual: &ProtectedBindingReceipt,
) -> Result<(), ApiError> {
    if fingerprint(&expected.allocation)? != fingerprint(&actual.allocation)?
        || expected.source != actual.source
        || expected.destinations != actual.destinations
        || expected.expires_at != actual.expires_at
    {
        return Err(conflict());
    }
    Ok(())
}
fn row(
    value: &sqlx::sqlite::SqliteRow,
    installation: Uuid,
) -> Result<NetworkPolicyControl, ApiError> {
    let record: NetworkPolicyControl = decode(value.try_get("payload").map_err(db)?)?;
    record.validate(installation)?;
    if value.try_get::<&str, _>("sandbox_id").map_err(db)? != record.sandbox_id.to_string()
        || value
            .try_get::<&str, _>("allocation_generation")
            .map_err(db)?
            != record.allocation_generation.to_string()
        || value.try_get::<i64, _>("revision").map_err(db)? != record.revision as i64
        || value.try_get::<i64, _>("desired_revision").map_err(db)?
            != record.desired_revision as i64
    {
        return Err(internal());
    }
    Ok(record)
}
pub(super) async fn source(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    installation: Uuid,
) -> Result<NetworkPolicyControl, ApiError> {
    let value = sqlx::query("SELECT * FROM network_policies WHERE sandbox_id=?")
        .bind(id.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("network policy"))?;
    row(&value, installation)
}
pub(super) async fn save(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    record: &mut NetworkPolicyControl,
) -> Result<(), ApiError> {
    let previous = record.revision;
    record.revision = previous
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or_else(conflict)?;
    record.validate(record.checkpoint.allocation.installation_id)?;
    let changed = sqlx::query("UPDATE network_policies SET revision=?,desired_revision=?,payload=? WHERE sandbox_id=? AND revision=?")
        .bind(record.revision as i64).bind(record.desired_revision as i64).bind(encode(record)?).bind(record.sandbox_id.to_string()).bind(previous as i64).execute(&mut **tx).await.map_err(db)?;
    if changed.rows_affected() != 1 {
        return Err(conflict());
    }
    sqlx::query("INSERT INTO network_policy_events(sandbox_id,revision,payload) VALUES(?,?,?)")
        .bind(record.sandbox_id.to_string())
        .bind(record.revision as i64)
        .bind(encode(record)?)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
pub(super) async fn live(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    record: &NetworkPolicyControl,
    installation: Uuid,
) -> Result<StoredSandbox, ApiError> {
    let network = super::networks::source(tx, record.sandbox_id, installation).await?;
    let value = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
        .bind(record.sandbox_id.to_string())
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
    let sandbox = sandbox_row(&value)?;
    if let Some(expected) = &record.public_inputs {
        let (config, actual) = super::network_policy_public::inputs(tx, record.sandbox_id).await?;
        if expected != &actual || config.digest()? != record.config_sha256 {
            return Err(conflict());
        }
    }
    let binding = network.binding.as_ref().ok_or_else(conflict)?;
    if network.phase != NetworkPhase::Bound
        || network.generation != record.allocation_generation
        || fingerprint(&binding.allocation)? != fingerprint(&record.checkpoint.allocation)?
        || binding.source != record.checkpoint.source
        || binding.destinations != record.checkpoint.destinations
        || sandbox.sandbox.expires_at != record.checkpoint.expires_at
        || goldenhoop_core::expired(&sandbox.sandbox, Utc::now())
        || sandbox.sandbox.desired_state == DesiredState::Terminated
        || matches!(
            sandbox.sandbox.state,
            SandboxState::Stopping | SandboxState::Failed | SandboxState::Terminated
        )
        || sandbox.sandbox.cleanup == CleanupState::Complete
        || sandbox.handle.is_none()
    {
        return Err(conflict());
    }
    Ok(sandbox)
}
async fn current_worker(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    worker_id: Uuid,
) -> Result<(), ApiError> {
    let value: String = sqlx::query_scalar("SELECT value FROM meta WHERE key='worker'")
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
    let worker: WorkerRegistration = decode(&value)?;
    let age = Utc::now().signed_duration_since(worker.heartbeat);
    if worker.id != worker_id
        || age > chrono::Duration::seconds(10)
        || age < chrono::Duration::seconds(-5)
    {
        return Err(conflict());
    }
    Ok(())
}
/// Invalidate the public observation before an asynchronous policy/recovery
/// transition. Existing runtime identity and ever-running evidence are kept.
pub(super) async fn fence_sandbox(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<(), ApiError> {
    let value = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
        .bind(id.to_string())
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
    let mut stored = sandbox_row(&value)?;
    if matches!(
        stored.sandbox.state,
        SandboxState::Running | SandboxState::Resuming
    ) {
        goldenhoop_core::transition(stored.sandbox.state, SandboxState::Unknown)?;
        stored.sandbox.state = SandboxState::Unknown;
        stored.sandbox.cleanup = CleanupState::Unknown;
        stored.sandbox.reason = Some("network policy requires fresh worker confirmation".into());
        stored.sandbox.observed_at = Some(Utc::now());
        sqlx::query("UPDATE sandboxes SET state='unknown',cleanup='unknown',payload=? WHERE id=?")
            .bind(encode(&stored.sandbox)?)
            .bind(id.to_string())
            .execute(&mut **tx)
            .await
            .map_err(db)?;
    }
    Ok(())
}

pub(super) async fn stage(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    record: &NetworkPolicyControl,
    installation: Uuid,
) -> Result<(), ApiError> {
    record.validate(installation)?;
    let sandbox = live(tx, record, installation).await?;
    if sandbox.ever_running || sandbox.sandbox.state != SandboxState::Starting {
        return Err(conflict());
    }
    if sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM network_policies WHERE sandbox_id=?")
        .bind(record.sandbox_id.to_string())
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?
        != 0
    {
        return Err(conflict());
    }
    sqlx::query("INSERT INTO network_policies(sandbox_id,allocation_generation,revision,desired_revision,payload) VALUES(?,?,0,0,?)")
        .bind(record.sandbox_id.to_string()).bind(record.allocation_generation.to_string()).bind(encode(record)?).execute(&mut **tx).await.map_err(db)?;
    sqlx::query("INSERT INTO network_policy_events(sandbox_id,revision,payload) VALUES(?,0,?)")
        .bind(record.sandbox_id.to_string())
        .bind(encode(record)?)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}

/// Publish a replacement registration only after historical owners lose their
/// acknowledgements and Running observation in the same SQLite transaction.
/// Heartbeats of the same registered worker never enter this path.
pub(super) async fn fence_other_workers(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    worker_id: Uuid,
    installation: Uuid,
) -> Result<(), ApiError> {
    let rows = sqlx::query("SELECT * FROM network_policies")
        .fetch_all(&mut **tx)
        .await
        .map_err(db)?;
    for value in rows {
        let mut record = row(&value, installation)?;
        if record.phase != NetworkPolicyPhase::Fenced
            && record
                .owner
                .as_ref()
                .is_some_and(|owner| owner.worker_id != worker_id)
        {
            record.phase = NetworkPolicyPhase::Fenced;
            record.attempt = None;
            record.observation = None;
            fence_sandbox(tx, record.sandbox_id).await?;
            save(tx, &mut record).await?;
        }
    }
    Ok(())
}
impl Store {
    pub async fn network_policy(&self, id: Uuid) -> Result<NetworkPolicyControl, ApiError> {
        let value = sqlx::query("SELECT * FROM network_policies WHERE sandbox_id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("network policy"))?;
        row(&value, self.installation_id)
    }
    /// Trusted staging only: this is not a public capability or an enforcement
    /// acknowledgement. The worker must settle the producer and recover afresh.
    pub async fn stage_network_policy(
        &self,
        id: Uuid,
        generation: Uuid,
        checkpoint: ProtectedBindingReceipt,
        upstream: SocketAddr,
        config: Config,
    ) -> Result<NetworkPolicyControl, ApiError> {
        checkpoint.validate()?;
        let record = NetworkPolicyControl {
            sandbox_id: id,
            allocation_generation: generation,
            revision: 0,
            desired_revision: 0,
            config_sha256: config.digest()?,
            config,
            upstream,
            checkpoint,
            public_inputs: None,
            phase: NetworkPolicyPhase::Pending,
            owner: None,
            attempt: None,
            observation: None,
        };
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        stage(&mut tx, &record, self.installation_id).await?;
        tx.commit().await.map_err(db)?;
        Ok(record)
    }
    pub async fn update_network_policy(
        &self,
        id: Uuid,
        generation: Uuid,
        expected_desired: u64,
        config: Config,
    ) -> Result<NetworkPolicyControl, ApiError> {
        let digest = config.digest()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut record = source(&mut tx, id, self.installation_id).await?;
        if record.public_inputs.is_some() {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "public policy requires versioned user-policy changes",
            ));
        }
        live(&mut tx, &record, self.installation_id).await?;
        if record.allocation_generation != generation || record.desired_revision != expected_desired
        {
            return Err(conflict());
        }
        record.desired_revision = record
            .desired_revision
            .checked_add(1)
            .ok_or_else(conflict)?;
        record.config = config;
        record.config_sha256 = digest;
        record.phase = NetworkPolicyPhase::Pending;
        record.observation = None;
        record.attempt = None;
        fence_sandbox(&mut tx, id).await?;
        save(&mut tx, &mut record).await?;
        tx.commit().await.map_err(db)?;
        Ok(record)
    }
    pub async fn claim_network_policy(
        &self,
        id: Uuid,
        expected: u64,
        worker_id: Uuid,
        generation: Uuid,
    ) -> Result<NetworkPolicyControl, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut record = source(&mut tx, id, self.installation_id).await?;
        live(&mut tx, &record, self.installation_id).await?;
        current_worker(&mut tx, worker_id).await?;
        let controller =
            super::controllers::source(&mut tx, id, generation, self.installation_id).await?;
        if record.revision != expected
            || controller.allocation_generation != record.allocation_generation
            || controller.phase != ControllerPhase::Running
            || controller.plan.controller()?.purpose
                != goldenhoop_egress::ControllerPurpose::Enforce
            || record
                .owner
                .as_ref()
                .is_some_and(|o| o.controller_generation == generation)
        {
            return Err(conflict());
        }
        if let Some(old) = &record.owner {
            let old = super::controllers::source(
                &mut tx,
                id,
                old.controller_generation,
                self.installation_id,
            )
            .await?;
            if old.phase != ControllerPhase::Collected {
                return Err(conflict());
            }
        }
        record.owner = Some(NetworkPolicyOwner {
            worker_id,
            controller_generation: generation,
            container_id: controller.container_id.ok_or_else(conflict)?,
            token: Uuid::new_v4(),
        });
        record.phase = NetworkPolicyPhase::Recovering;
        record.attempt = None;
        record.observation = None;
        fence_sandbox(&mut tx, id).await?;
        save(&mut tx, &mut record).await?;
        tx.commit().await.map_err(db)?;
        Ok(record)
    }
    /// Check desired/owner state immediately before each bounded native change.
    pub async fn begin_network_policy_apply(
        &self,
        id: Uuid,
        expected: u64,
        owner: &NetworkPolicyOwner,
    ) -> Result<NetworkPolicyControl, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut record = source(&mut tx, id, self.installation_id).await?;
        live(&mut tx, &record, self.installation_id).await?;
        current_worker(&mut tx, owner.worker_id).await?;
        if record.revision != expected
            || record.owner.as_ref() != Some(owner)
            || !matches!(
                record.phase,
                NetworkPolicyPhase::Recovering
                    | NetworkPolicyPhase::Pending
                    | NetworkPolicyPhase::Active
            )
        {
            return Err(conflict());
        }
        let controller = super::controllers::source(
            &mut tx,
            id,
            owner.controller_generation,
            self.installation_id,
        )
        .await?;
        if controller.phase != ControllerPhase::Running
            || controller.container_id.as_ref() != Some(&owner.container_id)
        {
            return Err(conflict());
        }
        record.phase = NetworkPolicyPhase::Applying;
        record.attempt = Some(Uuid::new_v4());
        record.observation = None;
        fence_sandbox(&mut tx, id).await?;
        save(&mut tx, &mut record).await?;
        tx.commit().await.map_err(db)?;
        Ok(record)
    }
    pub async fn confirm_network_policy(
        &self,
        id: Uuid,
        expected: u64,
        owner: &NetworkPolicyOwner,
        attempt: Uuid,
        receipt: EffectivePolicyReceipt,
    ) -> Result<NetworkPolicyControl, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut record = source(&mut tx, id, self.installation_id).await?;
        live(&mut tx, &record, self.installation_id).await?;
        current_worker(&mut tx, owner.worker_id).await?;
        if record.revision != expected
            || record.owner.as_ref() != Some(owner)
            || record.attempt != Some(attempt)
            || record.phase != NetworkPolicyPhase::Applying
        {
            return Err(conflict());
        }
        receipt.validate_config(&record.config)?;
        same_context(&record.checkpoint, &receipt.binding)?;
        if receipt.binding.observed_at > Utc::now()
            || Utc::now().signed_duration_since(receipt.binding.observed_at)
                > chrono::Duration::seconds(10)
        {
            return Err(conflict());
        }
        record.phase = NetworkPolicyPhase::Active;
        record.attempt = None;
        record.observation = Some(receipt);
        save(&mut tx, &mut record).await?;
        super::network_policy_public::acknowledge(&mut tx, &record).await?;
        tx.commit().await.map_err(db)?;
        Ok(record)
    }
    pub async fn fence_network_policy(
        &self,
        id: Uuid,
        owner: &NetworkPolicyOwner,
    ) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut record = source(&mut tx, id, self.installation_id).await?;
        if record.owner.as_ref() != Some(owner) {
            return Err(conflict());
        }
        if record.phase != NetworkPolicyPhase::Fenced {
            record.phase = NetworkPolicyPhase::Fenced;
            record.attempt = None;
            record.observation = None;
            fence_sandbox(&mut tx, id).await?;
            save(&mut tx, &mut record).await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(())
    }
}
