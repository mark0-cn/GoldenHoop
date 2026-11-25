//! Private allocator metadata, never an enforcement acknowledgement or API DTO.
use super::*;
use goldenhoop_egress::{Allocation, DestinationDefinition, NetworkIdentity, SourceScope};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPhase {
    Reserved,
    Provisioning,
    Bound,
    Collecting,
    Collected,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkBinding {
    pub network_id: String,
    pub allocation: Allocation,
    pub source: SourceScope,
    pub destinations: DestinationDefinition,
}

/// Persist the observed physical identity before any alias or packet write.
/// Trusted observations are inputs; this record does not attest enforcement.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkNativeBinding {
    pub network_id: String,
    pub allocation: Allocation,
}
impl From<&NetworkBinding> for NetworkNativeBinding {
    fn from(binding: &NetworkBinding) -> Self {
        Self {
            network_id: binding.network_id.clone(),
            allocation: binding.allocation.clone(),
        }
    }
}

/// Supplied only by the trusted collector after fresh provider/kernel lookups.
/// This structure does not perform or attest those lookups by itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAbsence {
    /// All provisioning writes have settled or been fenced, including provider
    /// creation and any privileged controller/alias/packet installation.
    pub provisioning_settled: bool,
    pub endpoints_absent: bool,
    pub network_absent: bool,
    pub bridge_absent: bool,
    pub owned_tables_absent: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAllocation {
    pub installation_id: Uuid,
    pub sandbox_id: Uuid,
    pub generation: Uuid,
    pub profile: String,
    pub network_name: String,
    pub bridge: String,
    pub revision: u64,
    pub phase: NetworkPhase,
    pub network_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<NetworkNativeBinding>,
    pub binding: Option<NetworkBinding>,
    pub token: Option<Uuid>,
    pub absence: Option<NetworkAbsence>,
}
fn conflict() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "network allocation identity or phase differs",
    )
}
fn network_id_valid(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl NetworkAllocation {
    pub fn identity(&self) -> NetworkIdentity {
        NetworkIdentity {
            installation_id: self.installation_id,
            sandbox_id: self.sandbox_id,
            generation: self.generation,
            profile: self.profile.clone(),
        }
    }
    pub fn binding_fingerprint(&self) -> Result<Option<String>, ApiError> {
        self.binding.as_ref().map(fingerprint).transpose()
    }
    /// Schema-6 complete bindings already carry the physical identity. Preserve
    /// their original history bytes instead of backfilling old snapshots.
    pub fn native_binding(&self) -> Option<NetworkNativeBinding> {
        self.native
            .clone()
            .or_else(|| self.binding.as_ref().map(NetworkNativeBinding::from))
    }
    fn validate(&self, installation: Uuid) -> Result<(), ApiError> {
        let identity = self.identity();
        identity.validate().map_err(|_| internal())?;
        if self.installation_id != installation
            || self.sandbox_id.is_nil()
            || self.generation.is_nil()
            || self.network_name != identity.network_name()
            || self.bridge != identity.bridge_name()
            || self.profile.is_empty()
            || self.profile.len() > 128
            || self.revision > i64::MAX as u64
            || self
                .network_id
                .as_deref()
                .is_some_and(|id| !network_id_valid(id))
            || self.token.is_some_and(|t| t.is_nil())
            || (matches!(
                self.phase,
                NetworkPhase::Provisioning
                    | NetworkPhase::Bound
                    | NetworkPhase::Collecting
                    | NetworkPhase::Collected
            ) && self.token.is_none())
            || (self.phase == NetworkPhase::Bound && self.binding.is_none())
            || (self.phase == NetworkPhase::Collected) != self.absence.is_some()
        {
            return Err(internal());
        }
        if let Some(native) = &self.native {
            if self.network_id.as_ref() != Some(&native.network_id) {
                return Err(internal());
            }
            self.validate_native(native).map_err(|_| internal())?;
        }
        if let Some(binding) = &self.binding {
            if self.network_id.as_ref() != Some(&binding.network_id) {
                return Err(internal());
            }
            self.validate_binding(binding).map_err(|_| internal())?;
        }
        if (self.phase == NetworkPhase::Reserved
            && (self.token.is_some()
                || self.network_id.is_some()
                || self.native.is_some()
                || self.binding.is_some()))
            || (self.phase == NetworkPhase::Provisioning
                && (self.binding.is_some() || self.network_id.is_some() != self.native.is_some()))
            || self.absence.as_ref().is_some_and(|a| {
                !a.provisioning_settled
                    || !a.endpoints_absent
                    || !a.network_absent
                    || !a.bridge_absent
                    || !a.owned_tables_absent
            })
        {
            return Err(internal());
        }
        Ok(())
    }
    fn validate_native(&self, binding: &NetworkNativeBinding) -> Result<(), ApiError> {
        let allocation = &binding.allocation;
        allocation.validate()?;
        if let Some(old) = &self.native
            && fingerprint(old)? != fingerprint(binding)?
        {
            return Err(conflict());
        }
        if !network_id_valid(&binding.network_id)
            || allocation.installation_id != self.installation_id
            || allocation.sandbox_id != self.sandbox_id
            || allocation.generation != self.generation
            || allocation.bridge != self.bridge
            || self
                .network_id
                .as_ref()
                .is_some_and(|id| *id != binding.network_id)
        {
            return Err(conflict());
        }
        Ok(())
    }
    fn validate_binding(&self, binding: &NetworkBinding) -> Result<(), ApiError> {
        let allocation = &binding.allocation;
        self.validate_native(&NetworkNativeBinding::from(binding))?;
        binding.source.validate(allocation)?;
        if !network_id_valid(&binding.network_id)
            || allocation.installation_id != self.installation_id
            || allocation.sandbox_id != self.sandbox_id
            || allocation.generation != self.generation
            || allocation.bridge != self.bridge
            || self
                .network_id
                .as_ref()
                .is_some_and(|id| *id != binding.network_id)
            || binding.destinations.canonical()? != binding.destinations
            || !binding
                .destinations
                .scope
                .host_addresses
                .contains(&binding.source.gateway4.into())
            || binding.source.gateway6.is_some_and(|ip| {
                !binding
                    .destinations
                    .scope
                    .host_addresses
                    .contains(&ip.into())
            })
            || binding.destinations.dns.iter().any(|listener| {
                listener.address != binding.source.gateway4
                    && Some(listener.address) != binding.source.gateway6.map(Into::into)
            })
        {
            return Err(conflict());
        }
        Ok(())
    }
}
fn network_row(
    row: &sqlx::sqlite::SqliteRow,
    installation: Uuid,
) -> Result<NetworkAllocation, ApiError> {
    let value: NetworkAllocation = decode(row.try_get("payload").map_err(db)?)?;
    value.validate(installation)?;
    if row.try_get::<&str, _>("sandbox_id").map_err(db)? != value.sandbox_id.to_string()
        || row.try_get::<&str, _>("generation").map_err(db)? != value.generation.to_string()
        || row.try_get::<&str, _>("phase").map_err(db)? != tag(&value.phase)?
        || row.try_get::<i64, _>("revision").map_err(db)? != value.revision as i64
        || row.try_get::<Option<String>, _>("network_id").map_err(db)? != value.network_id
        || row.try_get::<&str, _>("bridge").map_err(db)? != value.bridge
        || row.try_get::<Option<i64>, _>("ifindex").map_err(db)?
            != value
                .native_binding()
                .map(|b| i64::from(b.allocation.ifindex))
    {
        return Err(internal());
    }
    Ok(value)
}
async fn source(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    installation: Uuid,
) -> Result<NetworkAllocation, ApiError> {
    let row = sqlx::query("SELECT * FROM network_allocations WHERE sandbox_id=?")
        .bind(id.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("network allocation"))?;
    network_row(&row, installation)
}
async fn save(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    value: &mut NetworkAllocation,
) -> Result<(), ApiError> {
    let previous = value.revision;
    value.revision = previous
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or_else(conflict)?;
    let changed=sqlx::query("UPDATE network_allocations SET phase=?,revision=?,network_id=?,ifindex=?,payload=? WHERE sandbox_id=? AND revision=?")
        .bind(tag(&value.phase)?).bind(value.revision as i64).bind(&value.network_id)
        .bind(value.native_binding().map(|b|i64::from(b.allocation.ifindex))).bind(encode(value)?)
        .bind(value.sandbox_id.to_string()).bind(previous as i64).execute(&mut **tx).await.map_err(db)?;
    if changed.rows_affected() != 1 {
        return Err(conflict());
    }
    sqlx::query("INSERT INTO network_allocation_events(sandbox_id,revision,payload) VALUES(?,?,?)")
        .bind(value.sandbox_id.to_string())
        .bind(value.revision as i64)
        .bind(encode(value)?)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
async fn provisionable(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    before_runtime: bool,
) -> Result<(), ApiError> {
    let row = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
        .bind(id.to_string())
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
    let sandbox = sandbox_row(&row)?;
    if sandbox.sandbox.desired_state != DesiredState::Running
        || !matches!(
            sandbox.sandbox.state,
            SandboxState::Pending | SandboxState::Starting
        )
        || sandbox.ever_running
        || (before_runtime && sandbox.handle.is_some())
        || goldenhoop_core::expired(&sandbox.sandbox, Utc::now())
    {
        return Err(conflict());
    }
    Ok(())
}
async fn native_available(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    value: &NetworkAllocation,
    binding: &NetworkNativeBinding,
) -> Result<(), ApiError> {
    let foreign:i64=sqlx::query_scalar("SELECT COUNT(*) FROM network_allocations WHERE sandbox_id<>? AND (network_id=? OR (phase<>'collected' AND (bridge=? OR ifindex=?)))").bind(value.sandbox_id.to_string()).bind(&binding.network_id).bind(&value.bridge).bind(i64::from(binding.allocation.ifindex)).fetch_one(&mut **tx).await.map_err(db)?;
    if foreign != 0 {
        return Err(conflict());
    }
    Ok(())
}
pub(super) async fn require_collected(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<(), ApiError> {
    let live: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM network_allocations WHERE sandbox_id=? AND phase<>'collected'",
    )
    .bind(id.to_string())
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if live != 0 {
        return Err(ApiError::new(
            ErrorCode::InvalidState,
            "network cleanup is not confirmed",
        ));
    }
    Ok(())
}
impl Store {
    pub async fn network_allocation_history(
        &self,
        id: Uuid,
        after: Option<u64>,
        limit: u16,
    ) -> Result<Vec<NetworkAllocation>, ApiError> {
        if !(1..=128).contains(&limit) || after.is_some_and(|r| r > i64::MAX as u64) {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "invalid network history cursor",
            ));
        }
        let rows=sqlx::query("SELECT revision,payload FROM network_allocation_events WHERE sandbox_id=? AND revision>? ORDER BY revision LIMIT ?")
            .bind(id.to_string()).bind(after.map_or(-1,|n|n as i64)).bind(i64::from(limit)).fetch_all(&self.pool).await.map_err(db)?;
        rows.iter()
            .map(|row| {
                let value: NetworkAllocation = decode(row.try_get("payload").map_err(db)?)?;
                value.validate(self.installation_id)?;
                if value.sandbox_id != id
                    || row.try_get::<i64, _>("revision").map_err(db)? != value.revision as i64
                {
                    return Err(internal());
                }
                Ok(value)
            })
            .collect()
    }
    pub async fn network_allocation(&self, id: Uuid) -> Result<NetworkAllocation, ApiError> {
        let row = sqlx::query("SELECT * FROM network_allocations WHERE sandbox_id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("network allocation"))?;
        network_row(&row, self.installation_id)
    }
    /// Commit this intent before creating any external network resource.
    /// Initial allocator metadata covers root Docker/gVisor sandboxes only.
    pub async fn reserve_network(
        &self,
        id: Uuid,
        generation: Uuid,
    ) -> Result<NetworkAllocation, ApiError> {
        if generation.is_nil() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "network generation is required",
            ));
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(row) = sqlx::query("SELECT * FROM network_allocations WHERE sandbox_id=?")
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
        {
            let value = network_row(&row, self.installation_id)?;
            if value.generation != generation {
                return Err(conflict());
            }
            tx.commit().await.map_err(db)?;
            return Ok(value);
        }
        let row = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("sandbox"))?;
        let sandbox = sandbox_row(&row)?;
        if sandbox.sandbox.state != SandboxState::Pending
            || sandbox.sandbox.desired_state != DesiredState::Running
            || sandbox.ever_running
            || sandbox.handle.is_some()
            || goldenhoop_core::expired(&sandbox.sandbox, Utc::now())
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "reserve a network before runtime dispatch",
            ));
        }
        if super::isolated::scope(&mut tx, id)
            .await?
            .parent_id
            .is_some()
        {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "isolated network allocation integration is unavailable",
            ));
        }
        let simple = generation.simple().to_string();
        let value = NetworkAllocation {
            installation_id: self.installation_id,
            sandbox_id: id,
            generation,
            profile: sandbox.sandbox.profile,
            network_name: format!("goldenhoop-net-{simple}"),
            bridge: format!("ghn{}", &simple[..12]),
            revision: 0,
            phase: NetworkPhase::Reserved,
            network_id: None,
            native: None,
            binding: None,
            token: None,
            absence: None,
        };
        value.validate(self.installation_id)?;
        sqlx::query("INSERT INTO network_allocations(sandbox_id,generation,phase,revision,bridge,payload) VALUES(?,?,'reserved',0,?,?)").bind(id.to_string()).bind(generation.to_string()).bind(&value.bridge).bind(encode(&value)?).execute(&mut *tx).await.map_err(db)?;
        sqlx::query(
            "INSERT INTO network_allocation_events(sandbox_id,revision,payload) VALUES(?,0,?)",
        )
        .bind(id.to_string())
        .bind(encode(&value)?)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    pub async fn begin_network_provisioning(
        &self,
        id: Uuid,
        generation: Uuid,
        expected: u64,
    ) -> Result<NetworkAllocation, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, self.installation_id).await?;
        if value.generation != generation
            || value.revision != expected
            || value.phase != NetworkPhase::Reserved
        {
            return Err(conflict());
        }
        let row = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
            .bind(id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let sandbox = sandbox_row(&row)?;
        if sandbox.sandbox.desired_state != DesiredState::Running
            || sandbox.sandbox.state != SandboxState::Pending
            || goldenhoop_core::expired(&sandbox.sandbox, Utc::now())
        {
            return Err(conflict());
        }
        value.phase = NetworkPhase::Provisioning;
        value.token = Some(Uuid::new_v4());
        save(&mut tx, &mut value).await?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    /// Commit this observed identity before installing an alias or any packet
    /// table. Replays only return the same identity and never grant a lease.
    pub async fn bind_native_network(
        &self,
        id: Uuid,
        generation: Uuid,
        token: Uuid,
        binding: NetworkNativeBinding,
    ) -> Result<NetworkAllocation, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, self.installation_id).await?;
        if value.generation != generation
            || value.token != Some(token)
            || !matches!(
                value.phase,
                NetworkPhase::Provisioning | NetworkPhase::Bound
            )
        {
            return Err(conflict());
        }
        value.validate_native(&binding)?;
        if let Some(old) = value.native_binding() {
            if fingerprint(&old)? != fingerprint(&binding)? {
                return Err(conflict());
            }
            tx.commit().await.map_err(db)?;
            return Ok(value);
        }
        provisionable(&mut tx, id, true).await?;
        native_available(&mut tx, &value, &binding).await?;
        value.network_id = Some(binding.network_id.clone());
        value.native = Some(binding);
        save(&mut tx, &mut value).await?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    /// Complete source/DNS identity after the immutable native checkpoint.
    pub async fn bind_network(
        &self,
        id: Uuid,
        generation: Uuid,
        token: Uuid,
        binding: NetworkBinding,
    ) -> Result<NetworkAllocation, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, self.installation_id).await?;
        if value.generation != generation
            || value.token != Some(token)
            || !matches!(
                value.phase,
                NetworkPhase::Provisioning | NetworkPhase::Bound
            )
        {
            return Err(conflict());
        }
        value.validate_binding(&binding)?;
        if let Some(old) = &value.binding {
            if fingerprint(old)? != fingerprint(&binding)? {
                return Err(conflict());
            }
            tx.commit().await.map_err(db)?;
            return Ok(value);
        }
        if value.native.is_none() {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "persist native network identity before complete binding",
            ));
        }
        provisionable(&mut tx, id, false).await?;
        native_available(&mut tx, &value, &NetworkNativeBinding::from(&binding)).await?;
        value.network_id = Some(binding.network_id.clone());
        value.binding = Some(binding);
        value.phase = NetworkPhase::Bound;
        save(&mut tx, &mut value).await?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    pub async fn begin_network_collection(
        &self,
        id: Uuid,
        generation: Uuid,
        expected: u64,
    ) -> Result<NetworkAllocation, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, self.installation_id).await?;
        if value.generation != generation
            || value.revision != expected
            || value.phase == NetworkPhase::Collected
        {
            return Err(conflict());
        }
        let row = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
            .bind(id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let sandbox = sandbox_row(&row)?;
        if sandbox.sandbox.desired_state != DesiredState::Terminated
            && !goldenhoop_core::expired(&sandbox.sandbox, Utc::now())
            && (sandbox.ever_running
                || !matches!(
                    sandbox.sandbox.state,
                    SandboxState::Pending | SandboxState::Starting | SandboxState::Failed
                ))
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "a live network cannot be collected",
            ));
        }
        value.phase = NetworkPhase::Collecting;
        value.token = Some(Uuid::new_v4());
        value.absence = None;
        save(&mut tx, &mut value).await?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    pub async fn confirm_network_absence(
        &self,
        id: Uuid,
        generation: Uuid,
        token: Uuid,
        absence: NetworkAbsence,
    ) -> Result<NetworkAllocation, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, self.installation_id).await?;
        if value.generation != generation || value.token != Some(token) {
            return Err(conflict());
        }
        if value.phase == NetworkPhase::Collected && value.absence.as_ref() == Some(&absence) {
            tx.commit().await.map_err(db)?;
            return Ok(value);
        }
        let age = Utc::now().signed_duration_since(absence.observed_at);
        if value.phase != NetworkPhase::Collecting
            || !absence.provisioning_settled
            || !absence.endpoints_absent
            || !absence.network_absent
            || !absence.bridge_absent
            || !absence.owned_tables_absent
            || age > chrono::Duration::seconds(5)
            || age < chrono::Duration::seconds(-5)
        {
            return Err(conflict());
        }
        value.phase = NetworkPhase::Collected;
        value.absence = Some(absence);
        save(&mut tx, &mut value).await?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    /// A late owned provider observation revokes old cleanup, never its audit history.
    pub async fn reopen_network_collection(
        &self,
        id: Uuid,
        generation: Uuid,
        network_id: &str,
    ) -> Result<NetworkAllocation, ApiError> {
        if !network_id_valid(network_id) {
            return Err(conflict());
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let mut value = source(&mut tx, id, self.installation_id).await?;
        if value.generation != generation
            || value
                .network_id
                .as_deref()
                .is_some_and(|old| old != network_id)
        {
            return Err(conflict());
        }
        if value.phase == NetworkPhase::Unknown {
            tx.commit().await.map_err(db)?;
            return Ok(value);
        }
        if value.phase != NetworkPhase::Collected {
            return Err(conflict());
        }
        value.phase = NetworkPhase::Unknown;
        value.token = None;
        value.absence = None;
        value.network_id = Some(network_id.to_owned());
        save(&mut tx, &mut value).await?;
        let row = sqlx::query("SELECT * FROM sandboxes WHERE id=?")
            .bind(id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let mut sandbox = sandbox_row(&row)?.sandbox;
        sandbox.state = SandboxState::Unknown;
        sandbox.desired_state = DesiredState::Terminated;
        sandbox.cleanup = CleanupState::Unknown;
        sandbox.observed_at = Some(Utc::now());
        sandbox.reason = Some("owned network residue requires collection".into());
        sqlx::query("UPDATE sandboxes SET desired='terminated',state='unknown',cleanup='unknown',payload=? WHERE id=?").bind(encode(&sandbox)?).bind(id.to_string()).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
}
