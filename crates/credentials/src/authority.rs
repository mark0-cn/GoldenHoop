//! Concrete generation-fenced binding selection. The native allocation adapter
//! supplies PacketAuthority; constructing this type alone grants no network I/O.
use crate::{
    CredentialAuthority, CredentialBinding, CredentialGrant, CredentialOutcome, CredentialState,
    RequestIdentity, Secret, SecretSource, canonical_host, error,
};
use async_trait::async_trait;
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tokio::sync::{RwLock, watch};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct PacketWitness {
    pub epoch: Uuid,
    pub revision: u64,
    pub destination: SocketAddr,
    pub source_name: Option<String>,
    pub expires_at: Instant,
}

#[async_trait]
pub trait PacketAuthority: Send + Sync {
    /// Native policy/source identity and a current DNS-source/address grant,
    /// or explicit raw-address permission, are mandatory before obtaining a key.
    async fn admit(&self, request: &RequestIdentity) -> Result<PacketWitness, ApiError>;
    async fn current(&self, witness: &PacketWitness) -> Result<(), ApiError>;
}

#[async_trait]
pub trait SecretResolver: Send + Sync {
    async fn exchange(
        &self,
        resolver: &str,
        binding: &CredentialBinding,
    ) -> Result<Secret, ApiError>;
}

pub struct NoExchanges;
#[async_trait]
impl SecretResolver for NoExchanges {
    async fn exchange(&self, _: &str, _: &CredentialBinding) -> Result<Secret, ApiError> {
        Err(error(
            ErrorCode::UnsupportedCapability,
            "trusted credential exchange resolver is not configured",
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerAudit {
    pub request_id: Uuid,
    pub sandbox_id: Uuid,
    pub binding_id: Uuid,
    pub binding_revision: u64,
    pub policy_revision: u64,
    pub broker_epoch: Uuid,
    pub outcome: CredentialOutcome,
}

/// Private durable-delivery identity. Contains only redacted typed observations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerAuditDelivery {
    pub id: Uuid,
    pub record: BrokerAudit,
}

#[async_trait]
pub trait CredentialAudit: Send + Sync {
    async fn append(&self, record: BrokerAudit) -> Result<(), ApiError>;
}

pub struct LoadedBinding {
    pub metadata: CredentialBinding,
    pub source: Arc<SecretSource>,
}
struct Snapshot {
    epoch: Uuid,
    bindings: Vec<LoadedBinding>,
}

pub struct SnapshotAuthority {
    sandbox_id: Uuid,
    packet: Arc<dyn PacketAuthority>,
    resolver: Arc<dyn SecretResolver>,
    audit: Arc<dyn CredentialAudit>,
    snapshot: RwLock<Snapshot>,
    generations: watch::Sender<Uuid>,
}

fn revoked() -> ApiError {
    error(
        ErrorCode::Forbidden,
        "credential or packet generation is no longer current",
    )
}

impl SnapshotAuthority {
    pub fn new(
        sandbox_id: Uuid,
        packet: Arc<dyn PacketAuthority>,
        resolver: Arc<dyn SecretResolver>,
        audit: Arc<dyn CredentialAudit>,
    ) -> Result<Self, ApiError> {
        if sandbox_id.is_nil() {
            return Err(error(
                ErrorCode::InvalidRequest,
                "invalid credential allocation",
            ));
        }
        let epoch = Uuid::new_v4();
        let (generations, _) = watch::channel(epoch);
        Ok(Self {
            sandbox_id,
            packet,
            resolver,
            audit,
            snapshot: RwLock::new(Snapshot {
                epoch,
                bindings: Vec::new(),
            }),
            generations,
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<Uuid> {
        self.generations.subscribe()
    }

    /// Called only after trusted listener/redirect installation. Revocation
    /// swaps authority immediately; the caller separately observes old socket
    /// tasks/handlers collected before acknowledging installation or drain.
    pub async fn replace(&self, bindings: Vec<LoadedBinding>) -> Result<Uuid, ApiError> {
        if bindings.len() > 256 {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "credential snapshot limit exceeded",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for value in &bindings {
            let metadata = &value.metadata;
            if metadata.sandbox_id != self.sandbox_id
                || metadata.id.is_nil()
                || !ids.insert(metadata.id)
                || metadata.state != CredentialState::Active
                || metadata.applied_revision != Some(metadata.revision)
                || metadata.revision == 0
                || metadata.binding.canonicalize()? != metadata.binding
            {
                return Err(error(
                    ErrorCode::Forbidden,
                    "unconfirmed credential snapshot",
                ));
            }
        }
        let epoch = Uuid::new_v4();
        *self.snapshot.write().await = Snapshot { epoch, bindings };
        self.generations.send_replace(epoch);
        Ok(epoch)
    }

    pub async fn fence(&self) -> Uuid {
        let epoch = Uuid::new_v4();
        *self.snapshot.write().await = Snapshot {
            epoch,
            bindings: Vec::new(),
        };
        self.generations.send_replace(epoch);
        epoch
    }
}

#[async_trait]
impl CredentialAuthority for SnapshotAuthority {
    async fn admit(&self, request: &RequestIdentity) -> Result<CredentialGrant, ApiError> {
        if request.sandbox_id != self.sandbox_id {
            return Err(revoked());
        }
        let witness = self.packet.admit(request).await?;
        if witness.epoch.is_nil()
            || witness.revision == 0
            || witness.expires_at <= Instant::now()
            || witness.destination != SocketAddr::new(request.destination, request.port)
            || witness.source_name.as_ref().is_some_and(|name| {
                canonical_host(name).ok().as_deref() != Some(request.host.as_str())
            })
        {
            return Err(revoked());
        }
        let snapshot = self.snapshot.read().await;
        let mut selected = None;
        for value in &snapshot.bindings {
            if value.metadata.binding.matches(
                request.scheme,
                &request.host,
                request.port,
                request.method.as_str(),
                &request.path_and_query,
            )? {
                if selected.is_some() {
                    return Err(error(
                        ErrorCode::Forbidden,
                        "credential binding match is ambiguous",
                    ));
                }
                selected = Some(value);
            }
        }
        let binding = selected
            .ok_or_else(|| {
                error(
                    ErrorCode::Forbidden,
                    "no credential binding matches this request",
                )
            })?
            .metadata
            .clone();
        Ok(CredentialGrant {
            binding,
            policy_revision: witness.revision,
            epoch: snapshot.epoch,
            request_id: Uuid::new_v4(),
            packet: Some(witness),
        })
    }

    async fn current(&self, grant: &CredentialGrant) -> Result<(), ApiError> {
        let witness = grant.packet.as_ref().ok_or_else(revoked)?;
        if witness.expires_at <= Instant::now()
            || witness.revision != grant.policy_revision
            || grant.binding.sandbox_id != self.sandbox_id
        {
            return Err(revoked());
        }
        {
            let snapshot = self.snapshot.read().await;
            if snapshot.epoch != grant.epoch
                || !snapshot.bindings.iter().any(|v| {
                    v.metadata.id == grant.binding.id
                        && v.metadata.revision == grant.binding.revision
                })
            {
                return Err(revoked());
            }
        }
        self.packet.current(witness).await?;
        // Do not let an asynchronous native checker resurrect a fenced epoch.
        if self.snapshot.read().await.epoch != grant.epoch {
            return Err(revoked());
        }
        Ok(())
    }

    async fn resolve(&self, grant: &CredentialGrant) -> Result<Secret, ApiError> {
        self.current(grant).await?;
        let source = {
            let snapshot = self.snapshot.read().await;
            if snapshot.epoch != grant.epoch {
                return Err(revoked());
            }
            snapshot
                .bindings
                .iter()
                .find(|v| {
                    v.metadata.id == grant.binding.id
                        && v.metadata.revision == grant.binding.revision
                })
                .map(|v| v.source.clone())
                .ok_or_else(revoked)?
        };
        let value = match source.as_ref() {
            SecretSource::Literal { value } => Secret(Zeroizing::new(value.0.to_string())),
            SecretSource::Exchange { resolver } => {
                self.resolver.exchange(resolver, &grant.binding).await?
            }
        };
        self.current(grant).await?;
        Ok(value)
    }

    async fn record(
        &self,
        grant: &CredentialGrant,
        outcome: CredentialOutcome,
    ) -> Result<(), ApiError> {
        self.audit
            .append(BrokerAudit {
                request_id: grant.request_id,
                sandbox_id: self.sandbox_id,
                binding_id: grant.binding.id,
                binding_revision: grant.binding.revision,
                policy_revision: grant.policy_revision,
                broker_epoch: grant.epoch,
                outcome,
            })
            .await
    }
}
