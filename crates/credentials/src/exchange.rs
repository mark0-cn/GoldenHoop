//! Operator-owned exchange endpoints. A binding names a registered resolver;
//! neither workload input nor a binding can choose a URL or authentication key.
use crate::{CredentialBinding, Secret, SecretResolver, error};
use async_trait::async_trait;
use futures_util::StreamExt;
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

fn uncertain() -> ApiError {
    let mut error = error(
        ErrorCode::BackendUnavailable,
        "trusted exchange delivery is uncertain; do not replay automatically",
    );
    error.retryable = false;
    error
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeProvider {
    pub endpoint: String,
    #[serde(default)]
    pub headers: BTreeMap<String, Secret>,
}

struct Provider {
    endpoint: reqwest::Url,
    headers: reqwest::header::HeaderMap,
}
pub struct ExchangeRegistry {
    providers: BTreeMap<String, Provider>,
    client: reqwest::Client,
}

impl ExchangeRegistry {
    pub fn supports(&self, name: &str) -> bool {
        self.providers.contains_key(name)
    }
    pub fn new(providers: BTreeMap<String, ExchangeProvider>) -> Result<Self, ApiError> {
        Self::with_trust(providers, Vec::new())
    }
    pub fn with_trust(
        providers: BTreeMap<String, ExchangeProvider>,
        certificates: Vec<reqwest::Certificate>,
    ) -> Result<Self, ApiError> {
        if providers.len() > 64 {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "exchange provider limit exceeded",
            ));
        }
        let mut values = BTreeMap::new();
        for (name, provider) in providers {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'_' | b'-'))
            {
                return Err(error(
                    ErrorCode::InvalidRequest,
                    "invalid exchange resolver identity",
                ));
            }
            let url = reqwest::Url::parse(&provider.endpoint).map_err(|_| {
                error(
                    ErrorCode::InvalidRequest,
                    "invalid trusted exchange endpoint",
                )
            })?;
            let local = url
                .host_str()
                .and_then(|v| v.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
                .is_some_and(|v| v.is_loopback());
            if !(url.scheme() == "https" || url.scheme() == "http" && local)
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.host().is_none()
                || url.port_or_known_default().is_none_or(|v| v == 0)
            {
                return Err(error(
                    ErrorCode::InvalidRequest,
                    "exchange endpoint requires verified HTTPS or loopback HTTP without embedded credentials",
                ));
            }
            let mut headers = reqwest::header::HeaderMap::new();
            if provider.headers.len() > 32 {
                return Err(error(
                    ErrorCode::QuotaExceeded,
                    "exchange header limit exceeded",
                ));
            }
            for (name, value) in provider.headers {
                let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| error(ErrorCode::InvalidRequest, "invalid exchange header"))?;
                if [
                    "host",
                    "connection",
                    "content-length",
                    "transfer-encoding",
                    "upgrade",
                    "te",
                    "trailer",
                ]
                .contains(&name.as_str())
                {
                    return Err(error(ErrorCode::InvalidRequest, "reserved exchange header"));
                }
                let mut value = reqwest::header::HeaderValue::from_str(&value.0).map_err(|_| {
                    error(
                        ErrorCode::InvalidRequest,
                        "invalid private exchange header value",
                    )
                })?;
                value.set_sensitive(true);
                headers.insert(name, value);
            }
            values.insert(
                name,
                Provider {
                    endpoint: url,
                    headers,
                },
            );
        }
        let mut client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(8))
            .pool_max_idle_per_host(0);
        for certificate in certificates {
            client = client.tls_certs_merge([certificate]);
        }
        let client = client.build().map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "trusted exchange transport unavailable",
            )
        })?;
        Ok(Self {
            providers: values,
            client,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    value: Secret,
}

#[async_trait]
impl SecretResolver for ExchangeRegistry {
    async fn exchange(
        &self,
        resolver: &str,
        binding: &CredentialBinding,
    ) -> Result<Secret, ApiError> {
        let provider = self.providers.get(resolver).ok_or_else(|| {
            error(
                ErrorCode::UnsupportedCapability,
                "trusted exchange resolver is not registered",
            )
        })?;
        let response=self.client.post(provider.endpoint.clone()).headers(provider.headers.clone())
            .json(&serde_json::json!({"sandbox_id":binding.sandbox_id,"binding_id":binding.id,"binding_revision":binding.revision})).send().await
            .map_err(|_|uncertain())?;
        if !response.status().is_success() {
            return Err(error(
                ErrorCode::Forbidden,
                "trusted exchange refused credential resolution",
            ));
        }
        let mut source = response.bytes_stream();
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = source.next().await {
            let chunk = chunk.map_err(|_| uncertain())?;
            if body.len().saturating_add(chunk.len()) > 64 * 1024 {
                return Err(error(
                    ErrorCode::QuotaExceeded,
                    "trusted exchange response exceeds limit",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        let value: Reply = serde_json::from_slice(&body)
            .map_err(|_| error(ErrorCode::Forbidden, "invalid trusted exchange response"))?;
        Ok(value.value)
    }
}
