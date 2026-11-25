//! User policy versions and lineage. These rows describe intent and past
//! acknowledgements; only the worker's actual private lease admits execution.
use super::*;
use goldenhoop_egress::{Config, ProtectedBindingReceipt};
use std::{collections::BTreeSet, net::SocketAddr};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkOperatorPolicy {
    #[serde(default)]
    pub deny_always: Vec<NetworkRule>,
    #[serde(default)]
    pub allow_always: Vec<NetworkRule>,
    #[serde(default)]
    pub tcp_cap: Option<Vec<u16>>,
}
impl NetworkOperatorPolicy {
    fn config(&self, policies: Vec<NetworkPolicy>) -> Config {
        Config {
            policies,
            deny_always: self.deny_always.clone(),
            allow_always: self.allow_always.clone(),
            tcp_cap: self.tcp_cap.clone(),
        }
    }
    fn digest(&self) -> Result<String, ApiError> {
        self.config(vec![NetworkPolicy::default()]).digest()?;
        fingerprint(self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicySource {
    pub sandbox_id: Uuid,
    pub revision: u64,
    pub policy_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyInputs {
    pub operator_sha256: String,
    /// Root first, current node last. Versions never grant kernel authority.
    pub lineage: Vec<NetworkPolicySource>,
}
impl NetworkPolicyInputs {
    pub(super) fn validate(&self, id: Uuid) -> Result<(), ApiError> {
        let sha = |v: &str| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        };
        let unique = self
            .lineage
            .iter()
            .map(|s| s.sandbox_id)
            .collect::<BTreeSet<_>>();
        if !sha(&self.operator_sha256)
            || self.lineage.is_empty()
            || self.lineage.len() > 5
            || self.lineage.last().map(|s| s.sandbox_id) != Some(id)
            || unique.len() != self.lineage.len()
            || self.lineage.iter().any(|s| {
                s.sandbox_id.is_nil() || s.revision > i64::MAX as u64 || !sha(&s.policy_sha256)
            })
        {
            return Err(internal());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    policy: NetworkPolicyState,
    source_sha256: String,
    targets: Vec<Uuid>,
}
fn conflict() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "network user policy revision or lineage differs",
    )
}

/// A public lineage can authorize use of the layered compiler, never runtime
/// dispatch. Partial/private legacy records do not enable isolated networking.
pub(super) async fn public_parent(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
    installation: Uuid,
) -> Result<bool, ApiError> {
    match super::network_policy::source(tx, id, installation).await {
        Ok(record) if record.public_inputs.is_some() => {
            super::network_policy::live(tx, &record, installation).await?;
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(error) if error.code == ErrorCode::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
async fn own(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<NetworkPolicyState, ApiError> {
    let sandbox = super::isolated::source(tx, id).await?;
    if let Some(row) =
        sqlx::query("SELECT revision,policy FROM network_policy_users WHERE sandbox_id=?")
            .bind(id.to_string())
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?
    {
        let revision: i64 = row.try_get("revision").map_err(db)?;
        if revision <= 0 {
            return Err(internal());
        }
        Ok(NetworkPolicyState {
            sandbox_id: id,
            revision: revision as u64,
            policy: decode(row.try_get("policy").map_err(db)?)?,
        })
    } else {
        Ok(NetworkPolicyState {
            sandbox_id: id,
            revision: 0,
            policy: sandbox.request.network,
        })
    }
}
pub(super) async fn inputs(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Uuid,
) -> Result<(Config, NetworkPolicyInputs), ApiError> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT value FROM meta WHERE key='network_operator_policy'")
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?;
    let operator: NetworkOperatorPolicy = decode(&raw.ok_or_else(|| {
        ApiError::new(
            ErrorCode::UnsupportedCapability,
            "public network policy operator binding is unavailable",
        )
    })?)?;
    let mut lineage = Vec::new();
    let mut policies = Vec::new();
    let mut next = Some(id);
    for _ in 0..5 {
        let Some(node) = next else {
            break;
        };
        let sandbox = super::isolated::source(tx, node).await?;
        if sandbox.sandbox.desired_state == DesiredState::Terminated
            || goldenhoop_core::expired(&sandbox.sandbox, Utc::now())
            || matches!(
                sandbox.sandbox.state,
                SandboxState::Failed | SandboxState::Terminated
            )
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "network policy source is terminating or expired",
            ));
        }
        let policy = own(tx, node).await?;
        lineage.push(NetworkPolicySource {
            sandbox_id: node,
            revision: policy.revision,
            policy_sha256: fingerprint(&policy.policy)?,
        });
        policies.push(policy.policy);
        next = super::isolated::scope(tx, node).await?.parent_id;
    }
    if next.is_some() {
        return Err(internal());
    }
    lineage.reverse();
    policies.reverse();
    let sources = NetworkPolicyInputs {
        operator_sha256: operator.digest()?,
        lineage,
    };
    sources.validate(id)?;
    let config = operator.config(policies);
    config.digest()?;
    Ok((config, sources))
}
pub(super) async fn acknowledge(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    record: &NetworkPolicyControl,
) -> Result<(), ApiError> {
    if let Some(inputs) = &record.public_inputs {
        for source in &inputs.lineage {
            sqlx::query("INSERT OR IGNORE INTO network_policy_applied_sources(sandbox_id,source_id,source_revision,source_sha256,control_revision) VALUES(?,?,?,?,?)")
                .bind(record.sandbox_id.to_string()).bind(source.sandbox_id.to_string()).bind(source.revision as i64)
                .bind(&source.policy_sha256).bind(record.revision as i64).execute(&mut **tx).await.map_err(db)?;
            let digest:String=sqlx::query_scalar("SELECT source_sha256 FROM network_policy_applied_sources WHERE sandbox_id=? AND source_id=? AND source_revision=?")
                .bind(record.sandbox_id.to_string()).bind(source.sandbox_id.to_string()).bind(source.revision as i64).fetch_one(&mut **tx).await.map_err(db)?;
            if digest != source.policy_sha256 {
                return Err(conflict());
            }
        }
    }
    settle(tx).await
}
pub(super) async fn settle(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<(), ApiError> {
    let rows=sqlx::query("SELECT o.payload AS operation,c.payload AS change FROM network_policy_changes c JOIN operations o ON o.id=c.operation_id WHERE o.state IN('pending','running')")
        .fetch_all(&mut **tx).await.map_err(db)?;
    for row in rows {
        let mut operation: Operation = decode(row.try_get("operation").map_err(db)?)?;
        let change: Change = decode(row.try_get("change").map_err(db)?)?;
        let latest = own(tx, change.policy.sandbox_id).await?;
        let mut complete = true;
        let mut closed = false;
        for id in &change.targets {
            let ack:Option<String>=sqlx::query_scalar("SELECT source_sha256 FROM network_policy_applied_sources WHERE sandbox_id=? AND source_id=? AND source_revision=?")
                .bind(id.to_string()).bind(change.policy.sandbox_id.to_string()).bind(change.policy.revision as i64).fetch_optional(&mut **tx).await.map_err(db)?;
            if ack.as_deref() == Some(&change.source_sha256) {
                continue;
            }
            let target = super::isolated::source(tx, *id).await?;
            if *id != change.policy.sandbox_id && target.sandbox.cleanup == CleanupState::Complete {
                continue;
            }
            complete = false;
            if *id == change.policy.sandbox_id
                && (target.sandbox.desired_state == DesiredState::Terminated
                    || goldenhoop_core::expired(&target.sandbox, Utc::now())
                    || matches!(
                        target.sandbox.state,
                        SandboxState::Failed | SandboxState::Terminated
                    ))
            {
                closed = true;
            }
        }
        if complete {
            operation.state = OperationState::Succeeded;
        } else if latest.revision != change.policy.revision || closed {
            operation.state = OperationState::Cancelled;
            operation.error = Some(ApiError::new(
                ErrorCode::Conflict,
                "network policy was superseded or closed before all targets confirmed",
            ));
        } else {
            continue;
        }
        operation.finished_at = Some(Utc::now());
        sqlx::query("UPDATE operations SET state=?,payload=? WHERE id=?")
            .bind(tag(&operation.state)?)
            .bind(encode(&operation)?)
            .bind(operation.id.to_string())
            .execute(&mut **tx)
            .await
            .map_err(db)?;
    }
    Ok(())
}
impl Store {
    /// Administrator-owned static floor, never accepted from a workload or a
    /// per-sandbox public policy. A different floor needs an explicit rollout.
    pub async fn bind_network_operator(
        &self,
        operator: &NetworkOperatorPolicy,
    ) -> Result<(), ApiError> {
        let digest = operator.digest()?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let previous: Option<String> =
            sqlx::query_scalar("SELECT value FROM meta WHERE key='network_operator_policy'")
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        if let Some(previous) = previous {
            if decode::<NetworkOperatorPolicy>(&previous)?.digest()? != digest {
                return Err(conflict());
            }
        } else {
            sqlx::query("INSERT INTO meta(key,value) VALUES('network_operator_policy',?)")
                .bind(encode(operator)?)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(())
    }
    pub async fn public_network_policy(&self, id: Uuid) -> Result<NetworkPolicyState, ApiError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let policy = own(&mut tx, id).await?;
        tx.commit().await.map_err(db)?;
        Ok(policy)
    }
    pub async fn resolved_network_policy(
        &self,
        id: Uuid,
    ) -> Result<(Config, NetworkPolicyInputs), ApiError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let resolved = inputs(&mut tx, id).await?;
        tx.commit().await.map_err(db)?;
        Ok(resolved)
    }
    pub async fn stage_public_network_policy(
        &self,
        id: Uuid,
        generation: Uuid,
        checkpoint: ProtectedBindingReceipt,
        upstream: SocketAddr,
    ) -> Result<NetworkPolicyControl, ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let (config, public_inputs) = inputs(&mut tx, id).await?;
        let record = NetworkPolicyControl {
            sandbox_id: id,
            allocation_generation: generation,
            revision: 0,
            desired_revision: 0,
            config_sha256: config.digest()?,
            config,
            upstream,
            checkpoint,
            public_inputs: Some(public_inputs),
            phase: NetworkPolicyPhase::Pending,
            owner: None,
            attempt: None,
            observation: None,
        };
        super::network_policy::stage(&mut tx, &record, self.installation_id).await?;
        tx.commit().await.map_err(db)?;
        Ok(record)
    }
    pub async fn set_public_network_policy(
        &self,
        id: Uuid,
        request: &SetNetworkPolicy,
        key: &str,
    ) -> Result<NetworkPolicyChanged, ApiError> {
        let operation_id = Uuid::new_v4();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(previous) = reserve(
            &mut tx,
            &format!("network-policy:{id}"),
            key,
            &fingerprint(request)?,
            operation_id,
        )
        .await?
        {
            let raw=sqlx::query("SELECT o.payload AS operation,c.payload AS change FROM operations o JOIN network_policy_changes c ON c.operation_id=o.id WHERE o.id=?")
                .bind(previous.to_string()).fetch_one(&mut *tx).await.map_err(db)?;
            let change: Change = decode(raw.try_get("change").map_err(db)?)?;
            let operation = decode(raw.try_get("operation").map_err(db)?)?;
            tx.commit().await.map_err(db)?;
            return Ok(NetworkPolicyChanged {
                policy: change.policy,
                operation,
            });
        }
        let stored = super::isolated::source(&mut tx, id).await?;
        let root = match super::network_policy::source(&mut tx, id, self.installation_id).await {
            Ok(record) => record,
            Err(error) if error.code == ErrorCode::NotFound => {
                return Err(ApiError::new(
                    if matches!(
                        stored.sandbox.state,
                        SandboxState::Pending | SandboxState::Starting
                    ) {
                        ErrorCode::InvalidState
                    } else {
                        ErrorCode::UnsupportedCapability
                    },
                    "sandbox has no public protected-network binding",
                ));
            }
            Err(error) => return Err(error),
        };
        if root.public_inputs.is_none() {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "sandbox has no public protected-network binding",
            ));
        }
        super::network_policy::live(&mut tx, &root, self.installation_id).await?;
        super::isolated::require_feature_limit(&mut tx, id, Capability::NetworkPolicy).await?;
        let old = own(&mut tx, id).await?;
        if old.revision != request.expected_revision {
            return Err(conflict());
        }
        let revision = old
            .revision
            .checked_add(1)
            .filter(|r| *r <= i64::MAX as u64)
            .ok_or_else(conflict)?;
        let policy = NetworkPolicyState {
            sandbox_id: id,
            revision,
            policy: request.policy.clone(),
        };
        sqlx::query("INSERT INTO network_policy_users(sandbox_id,revision,policy) VALUES(?,?,?) ON CONFLICT(sandbox_id) DO UPDATE SET revision=excluded.revision,policy=excluded.policy")
            .bind(id.to_string()).bind(revision as i64).bind(encode(&request.policy)?).execute(&mut *tx).await.map_err(db)?;
        let targets:Vec<String>=sqlx::query_scalar("WITH RECURSIVE affected(id) AS (SELECT ? UNION ALL SELECT s.sandbox_id FROM sandbox_scopes s JOIN affected a ON s.parent_id=a.id) SELECT b.id FROM sandboxes b JOIN affected a ON a.id=b.id WHERE b.cleanup<>'complete' ORDER BY b.id")
            .bind(id.to_string()).fetch_all(&mut *tx).await.map_err(db)?;
        if targets.is_empty() || targets.len() > 16 {
            return Err(conflict());
        }
        let mut ids = Vec::new();
        for target in targets {
            let node = Uuid::parse_str(&target).map_err(|_| internal())?;
            ids.push(node);
            let state = super::isolated::source(&mut tx, node).await?;
            if node != id
                && (state.sandbox.desired_state == DesiredState::Terminated
                    || goldenhoop_core::expired(&state.sandbox, Utc::now())
                    || matches!(
                        state.sandbox.state,
                        SandboxState::Failed | SandboxState::Terminated
                    ))
            {
                continue;
            }
            // Compile every live descendant before committing any user intent.
            let (config, sources) = inputs(&mut tx, node).await?;
            match super::network_policy::source(&mut tx, node, self.installation_id).await {
                Ok(mut control) => {
                    if control.public_inputs.is_none() {
                        return Err(ApiError::new(
                            ErrorCode::UnsupportedCapability,
                            "descendant has no public protected-network binding",
                        ));
                    }
                    control.config_sha256 = config.digest()?;
                    control.config = config;
                    control.public_inputs = Some(sources);
                    control.desired_revision = control
                        .desired_revision
                        .checked_add(1)
                        .ok_or_else(conflict)?;
                    control.phase = NetworkPolicyPhase::Pending;
                    control.observation = None;
                    control.attempt = None;
                    super::network_policy::live(&mut tx, &control, self.installation_id).await?;
                    super::network_policy::fence_sandbox(&mut tx, node).await?;
                    super::network_policy::save(&mut tx, &mut control).await?;
                }
                Err(error) if error.code == ErrorCode::NotFound => {
                    let sandbox = super::isolated::source(&mut tx, node).await?;
                    if sandbox.ever_running
                        || !matches!(
                            sandbox.sandbox.state,
                            SandboxState::Pending | SandboxState::Starting
                        )
                    {
                        return Err(ApiError::new(
                            ErrorCode::UnsupportedCapability,
                            "descendant cannot adopt an owned network",
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        let operation = Operation {
            id: operation_id,
            resource_id: id,
            state: OperationState::Pending,
            created_at: Utc::now(),
            finished_at: None,
            error: None,
        };
        let change = Change {
            policy: policy.clone(),
            source_sha256: fingerprint(&policy.policy)?,
            targets: ids,
        };
        sqlx::query("INSERT INTO operations(id,resource_id,kind,state,payload) VALUES(?,?,'network_policy','pending',?)")
            .bind(operation_id.to_string()).bind(id.to_string()).bind(encode(&operation)?).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("INSERT INTO network_policy_changes(operation_id,payload) VALUES(?,?)")
            .bind(operation_id.to_string())
            .bind(encode(&change)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        settle(&mut tx).await?;
        tx.commit().await.map_err(db)?;
        Ok(NetworkPolicyChanged { policy, operation })
    }
    pub async fn settle_network_policy_changes(&self) -> Result<(), ApiError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        settle(&mut tx).await?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }
}
