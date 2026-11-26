//! Private staged broker material and actual allocation TCP ingress.
use crate::controller::CredentialIngressObservation;
use crate::{
    AcknowledgedAudit, CredentialRedirect, EndpointAddresses, InstalledCredentials, Manager,
    NativePacketAuthority, error,
};
use goldenhoop_credentials::{
    Broker, CaMaterial, CertificateAuthority, CredentialBinding, ExchangeProvider,
    ExchangeRegistry, LoadedBinding, Scheme, SecretSource, SnapshotAuthority,
};
use goldenhoop_protocol::{ApiError, ErrorCode};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU16, AtomicU64, Ordering},
    },
};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct ActiveIngress {
    sandbox: Uuid,
    source: EndpointAddresses,
    definition: CredentialRedirect,
    broker: Broker,
    ca: Arc<CertificateAuthority>,
}
#[derive(Default)]
pub struct CredentialIngress {
    active: RwLock<Option<Arc<ActiveIngress>>>,
    counters: [AtomicU64; 7],
    last_original_port: AtomicU16,
}

impl CredentialIngress {
    fn observe(&self, index: usize) {
        let counter = &self.counters[index];
        let mut current = counter.load(Ordering::Relaxed);
        while let Err(actual) = counter.compare_exchange_weak(
            current,
            current.saturating_add(1),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            current = actual;
        }
    }
    pub fn observation(&self) -> CredentialIngressObservation {
        let values = self.counters.each_ref().map(|n| n.load(Ordering::Relaxed));
        CredentialIngressObservation {
            inactive: values[0],
            original_unavailable: values[1],
            dns: values[2],
            unexpected_port: values[3],
            foreign_peer: values[4],
            http_socket: values[5],
            transport_failed: values[6],
            last_original_port: self.last_original_port.load(Ordering::Relaxed),
            dns_resolution: None,
        }
    }
}

#[async_trait::async_trait]
impl crate::frontend::TcpHandler for CredentialIngress {
    async fn handle(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        stop: CancellationToken,
    ) -> Result<Option<TcpStream>, ApiError> {
        let active = self
            .active
            .read()
            .map_err(|_| error(ErrorCode::Forbidden, "credential ingress is fenced"))?
            .clone();
        let Some(active) = active else {
            self.observe(0);
            return Ok(Some(stream));
        };
        // Direct trusted DNS queries have no NAT original target; their bytes
        // continue through the existing bounded DNS parser. No HTTP fallback.
        let original = match goldenhoop_credentials::frontend::original_destination(&stream) {
            Ok(original) => original,
            Err(_) => {
                self.observe(1);
                return Ok(Some(stream));
            }
        };
        self.last_original_port
            .store(original.port(), Ordering::Relaxed);
        if original.port() == 53 {
            self.observe(2);
            return Ok(Some(stream));
        }
        let scheme = active
            .definition
            .ports
            .get(&original.port())
            .ok_or_else(|| {
                self.observe(3);
                error(
                    ErrorCode::Forbidden,
                    "original credential port is not installed",
                )
            })?;
        let native_peer = peer.ip().to_canonical();
        if native_peer != peer.ip()
            || !(native_peer == std::net::IpAddr::V4(active.source.ipv4)
                || active
                    .source
                    .ipv6
                    .is_some_and(|ip| native_peer == std::net::IpAddr::V6(ip)))
            || matches!(peer,SocketAddr::V6(v) if v.scope_id()!=0)
        {
            self.observe(4);
            return Err(error(
                ErrorCode::Forbidden,
                "credential socket source is outside the owned endpoint",
            ));
        }
        self.observe(5);
        let result = goldenhoop_credentials::frontend::serve_connection(
            stream,
            active.broker.clone(),
            active.ca.clone(),
            goldenhoop_credentials::frontend::ConnectionIdentity {
                sandbox_id: active.sandbox,
                original,
                tls: *scheme == Scheme::Https,
            },
            stop,
        )
        .await;
        if result.is_err() {
            self.observe(6);
        }
        result?;
        Ok(None)
    }
}

struct Staged {
    epoch: Uuid,
    ca: CaMaterial,
    binding_count: usize,
    provider_count: usize,
    bindings: Vec<LoadedBinding>,
    providers: BTreeMap<String, ExchangeProvider>,
    upstream_ca: Vec<goldenhoop_credentials::UpstreamCertificate>,
}
#[derive(Default)]
pub struct CredentialService {
    pub packets: Arc<NativePacketAuthority>,
    pub audit: Arc<AcknowledgedAudit>,
    pub ingress: Arc<CredentialIngress>,
    staged: Option<Staged>,
    activated: bool,
}
fn stage_error() -> ApiError {
    error(
        ErrorCode::Conflict,
        "credential staging epoch or count differs",
    )
}

impl CredentialService {
    pub fn begin(
        &mut self,
        epoch: Uuid,
        ca: CaMaterial,
        bindings: u16,
        providers: u16,
        upstream_ca_pem: Vec<String>,
    ) -> Result<(), ApiError> {
        if self.activated
            || self.staged.is_some()
            || epoch.is_nil()
            || bindings == 0
            || bindings > 256
            || providers > 64
        {
            return Err(stage_error());
        }
        self.staged = Some(Staged {
            epoch,
            ca,
            binding_count: usize::from(bindings),
            provider_count: usize::from(providers),
            bindings: Vec::new(),
            providers: BTreeMap::new(),
            upstream_ca: goldenhoop_credentials::upstream_certificates(upstream_ca_pem)?,
        });
        Ok(())
    }
    pub fn binding(
        &mut self,
        epoch: Uuid,
        binding: CredentialBinding,
        source: SecretSource,
    ) -> Result<(), ApiError> {
        let staged = self.staged.as_mut().ok_or_else(stage_error)?;
        if staged.epoch != epoch
            || staged.bindings.len() >= staged.binding_count
            || staged.bindings.iter().any(|v| v.metadata.id == binding.id)
        {
            return Err(stage_error());
        }
        staged.bindings.push(LoadedBinding {
            metadata: binding,
            source: Arc::new(source),
        });
        Ok(())
    }
    pub fn provider(
        &mut self,
        epoch: Uuid,
        name: String,
        provider: ExchangeProvider,
    ) -> Result<(), ApiError> {
        let staged = self.staged.as_mut().ok_or_else(stage_error)?;
        if staged.epoch != epoch
            || staged.providers.len() >= staged.provider_count
            || staged.providers.contains_key(&name)
        {
            return Err(stage_error());
        }
        // One bounded frame per provider. This serialization is private and
        // zeroized, and no serialized provider ever enters a reply or log.
        let private =
            zeroize::Zeroizing::new(serde_json::to_vec(&provider).map_err(|_| stage_error())?);
        if private.len() > 64 * 1024 {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "exchange provider exceeds private frame budget",
            ));
        }
        staged.providers.insert(name, provider);
        Ok(())
    }
    pub async fn activate(
        &mut self,
        manager: &mut Manager,
        epoch: Uuid,
        revision: u64,
    ) -> Result<InstalledCredentials, ApiError> {
        let staged = self.staged.take().ok_or_else(stage_error)?;
        if self.activated
            || staged.epoch != epoch
            || staged.bindings.len() != staged.binding_count
            || staged.providers.len() != staged.provider_count
        {
            return Err(stage_error());
        }
        let providers = Arc::new(ExchangeRegistry::with_trust(
            staged.providers,
            staged.upstream_ca.clone(),
        )?);
        let mut ports = BTreeMap::new();
        let mut ids = BTreeMap::new();
        for binding in &staged.bindings {
            let spec = &binding.metadata.binding;
            if spec.port == 53
                || ports
                    .insert(spec.port, spec.scheme)
                    .is_some_and(|old| old != spec.scheme)
            {
                return Err(stage_error());
            }
            if let SecretSource::Exchange { resolver } = &*binding.source
                && !providers.supports(resolver)
            {
                return Err(error(
                    ErrorCode::UnsupportedCapability,
                    "credential exchange resolver is not registered",
                ));
            }
            ids.insert(binding.metadata.id, binding.metadata.revision);
        }
        let source = manager.credential_source()?;
        let authority = Arc::new(SnapshotAuthority::new(
            manager.allocation().sandbox_id,
            self.packets.clone(),
            providers,
            self.audit.clone(),
        )?);
        // Validate every canonical binding before any kernel mutation.
        authority.replace(staged.bindings).await?;
        let ca = Arc::new(CertificateAuthority::open(staged.ca)?);
        let public_ca_sha256 = format!("{:x}", Sha256::digest(ca.public_pem().as_bytes()));
        let definition = manager.install_credential_redirect(revision, ports).await?;
        let mut broker = Broker::new(authority);
        for certificate in staged.upstream_ca {
            broker = broker.with_extra_trust(certificate);
        }
        *self.ingress.active.write().map_err(|_| stage_error())? = Some(Arc::new(ActiveIngress {
            sandbox: manager.allocation().sandbox_id,
            source,
            definition: definition.clone(),
            broker,
            ca,
        }));
        self.activated = true;
        Ok(InstalledCredentials {
            epoch,
            bindings: ids,
            public_ca_sha256,
            redirect: definition,
            observed_at: chrono::Utc::now(),
        })
    }
    pub fn fence(&self) {
        self.packets.fence();
    }
}
