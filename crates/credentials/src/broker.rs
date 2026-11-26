//! Bound forwarding. The caller supplies an independently verified runtime and
//! original endpoint identity; workload headers never select a sandbox/policy.
use crate::{CredentialBinding, CredentialState, Injection, Scheme, Secret, canonical_host, error};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use goldenhoop_protocol::{ApiError, ErrorCode};
use reqwest::{
    Method, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub type BodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, ApiError>> + Send>>;

#[derive(Clone)]
pub struct RequestIdentity {
    pub sandbox_id: Uuid,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub destination: IpAddr,
    pub tls_server_name: Option<String>,
    pub method: Method,
    pub path_and_query: String,
}

#[derive(Debug, Clone)]
pub struct CredentialGrant {
    pub binding: CredentialBinding,
    pub policy_revision: u64,
    pub epoch: Uuid,
    pub request_id: Uuid,
    pub packet: Option<crate::PacketWitness>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialOutcome {
    Admitted,
    /// Durable authorization to attempt I/O; it is not delivery evidence.
    DispatchIntent,
    /// Historical spelling of a pre-dispatch intent, retained for old audit.
    UpstreamStarted,
    UpstreamResponded {
        status: u16,
    },
    BodyCompleted,
    Revoked,
    DeliveryUnknown,
}

#[async_trait]
pub trait CredentialAuthority: Send + Sync {
    /// Requires current packet/DNS identity and exactly one matching binding.
    async fn admit(&self, request: &RequestIdentity) -> Result<CredentialGrant, ApiError>;
    async fn current(&self, grant: &CredentialGrant) -> Result<(), ApiError>;
    async fn resolve(&self, grant: &CredentialGrant) -> Result<Secret, ApiError>;
    async fn record(
        &self,
        grant: &CredentialGrant,
        outcome: CredentialOutcome,
    ) -> Result<(), ApiError>;
}

pub struct BoundRequest {
    pub identity: RequestIdentity,
    pub headers: HeaderMap,
    pub body: BodyStream,
}
pub struct BrokerResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: BodyStream,
}

#[derive(Clone)]
pub struct Broker {
    authority: Arc<dyn CredentialAuthority>,
    extra_trust: Vec<reqwest::Certificate>,
    requests: Arc<tokio::sync::Semaphore>,
}

fn unknown() -> ApiError {
    let mut error = error(
        ErrorCode::BackendUnavailable,
        "upstream delivery is uncertain; do not replay automatically",
    );
    error.retryable = false;
    error
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    // A Connection token must not nominate an injected end-to-end auth field.
    let nominated: Vec<_> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|v| HeaderName::from_bytes(v.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
    ] {
        headers.remove(name);
    }
}

async fn current(
    authority: &dyn CredentialAuthority,
    grant: &CredentialGrant,
) -> Result<(), ApiError> {
    tokio::time::timeout(Duration::from_millis(500), authority.current(grant))
        .await
        .map_err(|_| error(ErrorCode::Forbidden, "credential authority is unavailable"))?
}

async fn prepare<T, F>(
    authority: &dyn CredentialAuthority,
    grant: &CredentialGrant,
    future: F,
) -> Result<T, ApiError>
where
    F: std::future::Future<Output = Result<T, ApiError>>,
{
    let preparing = tokio::time::timeout(Duration::from_secs(10), future);
    tokio::pin!(preparing);
    loop {
        tokio::select! {
            result=&mut preparing=>return result.map_err(|_|error(ErrorCode::DeadlineExceeded,"credential preparation exceeded deadline"))?,
            _=tokio::time::sleep(Duration::from_millis(200))=>{
                if let Err(error)=current(authority,grant).await {let _=authority.record(grant,CredentialOutcome::Revoked).await;return Err(error);}
            },
        }
    }
}

impl Broker {
    pub fn new(authority: Arc<dyn CredentialAuthority>) -> Self {
        Self {
            authority,
            extra_trust: Vec::new(),
            requests: Arc::new(tokio::sync::Semaphore::new(32)),
        }
    }
    pub fn with_extra_trust(mut self, certificate: reqwest::Certificate) -> Self {
        self.extra_trust.push(certificate);
        self
    }

    pub async fn forward(&self, mut request: BoundRequest) -> Result<BrokerResponse, ApiError> {
        let permit = self.requests.clone().try_acquire_owned().map_err(|_| {
            error(
                ErrorCode::QuotaExceeded,
                "credential broker request limit reached",
            )
        })?;
        let identity = request.identity.clone();
        if identity.path_and_query.len() > 8192 {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "credential request target exceeds limit",
            ));
        }
        let host = canonical_host(&identity.host)?;
        if host != identity.host
            || identity.port == 0
            || identity.method == Method::CONNECT
            || identity.method == Method::TRACE
        {
            return Err(error(
                ErrorCode::Forbidden,
                "invalid credential request identity",
            ));
        }
        if identity.scheme == Scheme::Https {
            let server = identity
                .tls_server_name
                .as_deref()
                .ok_or_else(|| error(ErrorCode::Forbidden, "credential TLS identity is absent"))?;
            if canonical_host(server)? != host {
                return Err(error(
                    ErrorCode::Forbidden,
                    "TLS and HTTP authority disagree",
                ));
            }
        }
        let mut hosts = request.headers.get_all("host").iter();
        if let Some(value) = hosts.next() {
            let authority = value
                .to_str()
                .map_err(|_| error(ErrorCode::Forbidden, "invalid HTTP authority"))?;
            let parsed =
                reqwest::Url::parse(&format!("{}://{authority}/", identity.scheme.as_str()))
                    .map_err(|_| error(ErrorCode::Forbidden, "invalid HTTP authority"))?;
            if hosts.next().is_some()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || canonical_host(
                    parsed
                        .host_str()
                        .ok_or_else(|| error(ErrorCode::Forbidden, "missing HTTP authority"))?
                        .trim_matches(['[', ']']),
                )? != host
                || parsed.port_or_known_default() != Some(identity.port)
            {
                return Err(error(
                    ErrorCode::Forbidden,
                    "HTTP and bound destination disagree",
                ));
            }
        }
        let grant = self.authority.admit(&identity).await?;
        if grant.binding.binding.canonicalize()? != grant.binding.binding {
            return Err(error(
                ErrorCode::Forbidden,
                "noncanonical credential binding",
            ));
        }
        if grant.binding.sandbox_id != identity.sandbox_id
            || grant.binding.state != CredentialState::Active
            || grant.binding.applied_revision != Some(grant.binding.revision)
            || !grant.binding.binding.matches(
                identity.scheme,
                &host,
                identity.port,
                identity.method.as_str(),
                &identity.path_and_query,
            )?
        {
            return Err(error(
                ErrorCode::Forbidden,
                "credential admission identity mismatch",
            ));
        }
        current(self.authority.as_ref(), &grant).await?;
        self.authority
            .record(&grant, CredentialOutcome::Admitted)
            .await?;
        current(self.authority.as_ref(), &grant).await?;
        // Resolver output has no authority of its own. Rotation, revocation or
        // policy changes during exchange must be rechecked before injection.
        let secret = prepare(
            self.authority.as_ref(),
            &grant,
            self.authority.resolve(&grant),
        )
        .await?;
        current(self.authority.as_ref(), &grant).await?;
        strip_hop_headers(&mut request.headers);
        request.headers.remove("host");
        request.headers.remove("content-length");
        prepare(
            self.authority.as_ref(),
            &grant,
            crate::rewrite::rewrite(&mut request, &grant.binding.binding, &secret),
        )
        .await?;
        if request.headers.len() > 128
            || request
                .headers
                .iter()
                .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
                .sum::<usize>()
                > 64 * 1024
        {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "HTTP header limit exceeded",
            ));
        }
        let value = match &grant.binding.binding.injection {
            Injection::Bearer => Zeroizing::new(format!("Bearer {}", secret.0.as_str())),
            Injection::Basic { username } => {
                let raw = Zeroizing::new(format!("{username}:{}", secret.0.as_str()));
                Zeroizing::new(format!("Basic {}", STANDARD.encode(raw.as_bytes())))
            }
            Injection::Header { .. } => Zeroizing::new(secret.0.to_string()),
            Injection::Placeholders => Zeroizing::new(String::new()),
        };
        if !matches!(grant.binding.binding.injection, Injection::Placeholders) {
            let mut header = HeaderValue::from_str(&value).map_err(|_| {
                error(
                    ErrorCode::InvalidRequest,
                    "credential cannot be encoded as a header",
                )
            })?;
            header.set_sensitive(true);
            let name = match &grant.binding.binding.injection {
                Injection::Header { name } => HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| error(ErrorCode::InvalidRequest, "invalid credential header"))?,
                _ => HeaderName::from_static("authorization"),
            };
            request.headers.insert(name, header);
        }
        if request
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
            .sum::<usize>()
            > 64 * 1024
        {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "injected HTTP header limit exceeded",
            ));
        }
        let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]")
        } else {
            host.clone()
        };
        let url = reqwest::Url::parse(&format!(
            "{}://{authority}:{}{}",
            identity.scheme.as_str(),
            identity.port,
            request.identity.path_and_query
        ))
        .map_err(|_| error(ErrorCode::Forbidden, "invalid credential request target"))?;
        let mut client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(0)
            .resolve_to_addrs(
                &host,
                &[SocketAddr::new(identity.destination, identity.port)],
            );
        for cert in &self.extra_trust {
            client = client.tls_certs_merge([cert.clone()]);
        }
        let client = client.build().map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "credential upstream transport unavailable",
            )
        })?;
        let source = request.body;
        let input_authority = self.authority.clone();
        let input_grant = grant.clone();
        let body = async_stream::stream! {
            let mut source=source;
            while let Some(chunk)=source.next().await {
                if let Err(error)=current(input_authority.as_ref(),&input_grant).await {yield Err(error);break;}
                yield chunk;
            }
        };
        current(self.authority.as_ref(), &grant).await?;
        self.authority
            .record(&grant, CredentialOutcome::DispatchIntent)
            .await?;
        // Durable audit acknowledgement is asynchronous authority-neutral work.
        // Revocation during that wait must not dispatch an old credential.
        current(self.authority.as_ref(), &grant).await?;
        let sending = client
            .request(identity.method.clone(), url)
            .headers(request.headers)
            .body(reqwest::Body::wrap_stream(body))
            .send();
        tokio::pin!(sending);
        let response = loop {
            tokio::select! {
                response=&mut sending=>break response,
                _=tokio::time::sleep(Duration::from_millis(200))=>{
                    if current(self.authority.as_ref(),&grant).await.is_err() {
                        let _=self.authority.record(&grant,CredentialOutcome::Revoked).await;
                        return Err(unknown());
                    }
                },
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(_) => {
                let _ = self
                    .authority
                    .record(&grant, CredentialOutcome::DeliveryUnknown)
                    .await;
                return Err(unknown());
            }
        };
        current(self.authority.as_ref(), &grant).await?;
        let mut headers = response.headers().clone();
        strip_hop_headers(&mut headers);
        let mut redactions = vec![
            Zeroizing::new(secret.0.to_string()),
            Zeroizing::new(value.to_string()),
            crate::rewrite::uri_encoded(&secret.0),
        ];
        if let Some(basic) = value.strip_prefix("Basic ") {
            redactions.push(Zeroizing::new(basic.to_owned()));
        }
        let encoded = crate::rewrite::uri_encoded(&secret.0);
        redactions.push(crate::rewrite::lower_escapes(&encoded));
        let form = crate::rewrite::form_encoded(&secret.0);
        redactions.push(crate::rewrite::lower_escapes(&form));
        redactions.push(form);
        let remove: Vec<_> = headers
            .iter()
            .filter(|(_, v)| {
                let bytes = v.as_bytes();
                redactions.iter().any(|secret| {
                    !secret.is_empty()
                        && bytes.windows(secret.len()).any(|w| w == secret.as_bytes())
                })
            })
            .map(|(k, _)| k.clone())
            .collect();
        for name in remove {
            headers.remove(name);
        }
        headers.insert("cache-control", HeaderValue::from_static("no-store"));
        let status = response.status();
        self.authority
            .record(
                &grant,
                CredentialOutcome::UpstreamResponded {
                    status: status.as_u16(),
                },
            )
            .await?;
        current(self.authority.as_ref(), &grant).await?;
        let authority = self.authority.clone();
        let body = async_stream::stream! {
            // Plaintext is bounded to this request. Response bodies are an
            // approved upstream's application data and are not rewritten.
            let _secret=secret;let _value=value;let _client=client;let _permit=permit;let _redactions=redactions;
            let mut source=response.bytes_stream();
            loop {
                if let Err(error)=current(authority.as_ref(),&grant).await {let _=authority.record(&grant,CredentialOutcome::Revoked).await;yield Err(error);break;}
                tokio::select! {
                    chunk=source.next()=>match chunk {
                        Some(Ok(chunk))=>yield Ok(chunk),
                        Some(Err(_))=>{let _=authority.record(&grant,CredentialOutcome::DeliveryUnknown).await;yield Err(unknown());break;},
                        None=>{if authority.record(&grant,CredentialOutcome::BodyCompleted).await.is_err(){yield Err(unknown());}break;},
                    },
                    _=tokio::time::sleep(Duration::from_millis(200))=>{},
                }
            }
        };
        Ok(BrokerResponse {
            status,
            headers,
            body: Box::pin(body),
        })
    }
}
