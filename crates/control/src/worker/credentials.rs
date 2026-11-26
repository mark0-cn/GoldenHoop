//! Private broker convergence. No credential intent becomes Active until a
//! fresh owned controller and its native policy have actually acknowledged it.
use super::*;
use goldenhoop_credentials::{
    CredentialBinding, CredentialState, ExchangeProvider, ExchangeRegistry, SecretSource, VaultKey,
};
use goldenhoop_docker::ControllerSession;
use goldenhoop_egress::{InstalledCredentials, controller::Request};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct CredentialSetup {
    pub key: VaultKey,
    pub providers: BTreeMap<String, ExchangeProvider>,
    pub upstream_ca_pem: Vec<String>,
    pub probe: Option<CredentialProbe>,
}
#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialOptions {
    #[serde(default)]
    pub exchanges: BTreeMap<String, ExchangeProvider>,
    #[serde(default)]
    pub upstream_ca_pem: Vec<String>,
    pub probe: Option<CredentialProbe>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProbe {
    pub http_url: String,
    pub https_url: String,
    pub credential: goldenhoop_credentials::Secret,
    pub expected_body: String,
}
impl CredentialProbe {
    pub(super) fn urls(&self) -> Result<[reqwest::Url; 2], ApiError> {
        let invalid = || {
            ApiError::new(
                ErrorCode::InvalidRequest,
                "credential probe requires exact HTTP and HTTPS native endpoints",
            )
        };
        let http = reqwest::Url::parse(&self.http_url).map_err(|_| invalid())?;
        let https = reqwest::Url::parse(&self.https_url).map_err(|_| invalid())?;
        if http.scheme() != "http"
            || https.scheme() != "https"
            || self.expected_body.is_empty()
            || self.expected_body.len() > 128
            || self.expected_body.contains(self.credential.0.as_str())
        {
            return Err(invalid());
        }
        for url in [&http, &https] {
            let ip = url
                .host_str()
                .and_then(|v| v.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
                .ok_or_else(invalid)?;
            if ip.to_canonical() != ip
                || ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || url.query().is_some()
                || url.path().len() > 1024
                || url
                    .port_or_known_default()
                    .is_none_or(|v| v == 0 || v == 53)
            {
                return Err(invalid());
            }
        }
        if http.port_or_known_default() == https.port_or_known_default() {
            return Err(invalid());
        }
        Ok([http, https])
    }
}
impl CredentialSetup {
    pub fn new(key: VaultKey, options: CredentialOptions) -> Result<Self, ApiError> {
        let providers = options.exchanges;
        let _ = ExchangeRegistry::new(providers.clone())?;
        let _ = goldenhoop_credentials::upstream_certificates(options.upstream_ca_pem.clone())?;
        if let Some(probe) = &options.probe {
            probe.urls()?;
        }
        for provider in providers.values() {
            let encoded =
                zeroize::Zeroizing::new(serde_json::to_vec(provider).map_err(|_| unavailable())?);
            if encoded.len() > 64 * 1024 {
                return Err(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "exchange provider exceeds private frame budget",
                ));
            }
        }
        Ok(Self {
            key,
            providers,
            upstream_ca_pem: options.upstream_ca_pem,
            probe: options.probe,
        })
    }
}
fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "credential broker convergence is unconfirmed",
    )
}

pub(super) struct CredentialIntent {
    pub records: Vec<CredentialBinding>,
    pub installation: Option<InstalledCredentials>,
}
impl CredentialIntent {
    pub fn versions(&self) -> BTreeMap<Uuid, (u64, CredentialState)> {
        self.records
            .iter()
            .map(|r| {
                (
                    r.id,
                    (
                        r.revision,
                        match r.state {
                            CredentialState::Active => CredentialState::Pending,
                            CredentialState::Revoking => CredentialState::Revoked,
                            other => other,
                        },
                    ),
                )
            })
            .collect()
    }
}
pub(super) async fn install(
    store: &Store,
    setup: Option<&CredentialSetup>,
    id: Uuid,
    session: &mut ControllerSession,
    revision: u64,
) -> Result<CredentialIntent, ApiError> {
    let records = store.credentials(id).await?;
    let selected: Vec<_> = records
        .iter()
        .filter(|r| matches!(r.state, CredentialState::Pending | CredentialState::Active))
        .collect();
    if selected.is_empty() {
        if setup.is_some() || !records.is_empty() {
            super::network_policy::call(
                session,
                Request::DisableCredentials {
                    expected_revision: revision,
                },
            )
            .await?;
        }
        return Ok(CredentialIntent {
            records,
            installation: None,
        });
    }
    let setup = setup.ok_or_else(|| {
        ApiError::new(
            ErrorCode::UnsupportedCapability,
            "credential vault is not configured on the worker",
        )
    })?;
    let ca = store.credential_ca_material(&setup.key, id).await?;
    let ca_sha256 = format!("{:x}", Sha256::digest(ca.certificate_pem.as_bytes()));
    let epoch = Uuid::new_v4();
    let mut providers = BTreeMap::new();
    let mut bindings = Vec::new();
    for metadata in &selected {
        let source = store
            .credential_secret(&setup.key, id, metadata.id, metadata.revision)
            .await?;
        if let SecretSource::Exchange { resolver } = &source {
            providers.insert(
                resolver.clone(),
                setup
                    .providers
                    .get(resolver)
                    .ok_or_else(|| {
                        ApiError::new(
                            ErrorCode::UnsupportedCapability,
                            "credential exchange resolver is not registered",
                        )
                    })?
                    .clone(),
            );
        }
        let mut metadata = (*metadata).clone();
        metadata.state = CredentialState::Active;
        metadata.applied_revision = Some(metadata.revision);
        bindings.push((metadata, source));
    }
    let expected = bindings
        .iter()
        .map(|(m, _)| (m.id, m.revision))
        .collect::<BTreeMap<_, _>>();
    super::network_policy::call(
        session,
        Request::BeginCredentials {
            epoch,
            ca,
            binding_count: bindings.len() as u16,
            provider_count: providers.len() as u16,
            upstream_ca_pem: setup.upstream_ca_pem.clone(),
        },
    )
    .await?;
    for (name, provider) in providers {
        super::network_policy::call(
            session,
            Request::StageExchangeProvider {
                epoch,
                name,
                provider,
            },
        )
        .await?;
    }
    for (binding, source) in bindings {
        super::network_policy::call(
            session,
            Request::StageCredential {
                epoch,
                binding,
                source,
            },
        )
        .await?;
    }
    let started = Utc::now();
    let receipt: InstalledCredentials = serde_json::from_value(
        super::network_policy::call(
            session,
            Request::ActivateCredentials {
                epoch,
                expected_revision: revision,
            },
        )
        .await?,
    )
    .map_err(|_| unavailable())?;
    if receipt.epoch != epoch
        || receipt.bindings != expected
        || receipt.public_ca_sha256 != ca_sha256
        || receipt.observed_at < started
        || receipt.observed_at > Utc::now()
    {
        return Err(unavailable());
    }
    receipt.redirect.bindings()?;
    Ok(CredentialIntent {
        records,
        installation: Some(receipt),
    })
}

pub(super) async fn poll_audit(
    store: &Store,
    id: Uuid,
    controller: Uuid,
    session: &mut ControllerSession,
    acknowledged: &mut Vec<Uuid>,
) -> Result<(), ApiError> {
    let batch: Vec<goldenhoop_credentials::BrokerAuditDelivery> = serde_json::from_value(
        super::network_policy::call(
            session,
            Request::CredentialAudit {
                acknowledged: std::mem::take(acknowledged),
            },
        )
        .await?,
    )
    .map_err(|_| unavailable())?;
    if batch.len() > 64 {
        return Err(unavailable());
    }
    store
        .append_broker_audit_batch(id, controller, &batch)
        .await?;
    *acknowledged = batch.iter().map(|v| v.id).collect();
    Ok(())
}
