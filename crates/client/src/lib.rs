//! Cross-platform client. Waiting and observing never imply cancellation.
mod artifacts;
mod events;
pub use events::{EventStream, RunOutput};

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
pub use goldenhoop_protocol::*;
use reqwest::{
    Method, Url,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::de::DeserializeOwned;
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Api(ApiError),
    Transport,
    Protocol(&'static str),
    Timeout(Uuid),
    UncertainRequest(String),
    Observation(Uuid, Box<Error>),
    Artifact(Uuid, Box<Error>),
    Cleanup(Uuid, Box<Error>, Box<Error>),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api(error) => write!(f, "{error}"),
            Self::Transport => write!(f, "API transport is unavailable"),
            Self::Protocol(message) => write!(f, "invalid API response: {message}"),
            Self::Timeout(id) => write!(
                f,
                "wait deadline exceeded for {id}; operation was not cancelled"
            ),
            Self::UncertainRequest(key) => write!(
                f,
                "request outcome is unknown; retry the same request with idempotency key {key}"
            ),
            Self::Observation(id, error) => write!(f, "execution {id} observation failed: {error}"),
            Self::Artifact(id, error) => write!(f, "artifact {id} operation failed: {error}"),
            Self::Cleanup(id, original, error) => write!(
                f,
                "sandbox {id} cleanup is unconfirmed after {original}: {error}"
            ),
        }
    }
}
impl std::error::Error for Error {}

struct Inner {
    http: reqwest::Client,
    base: Url,
}
#[derive(Clone)]
pub struct Client(Arc<Inner>);

impl Client {
    pub fn new(base: &str, token: &str) -> Result<Self> {
        let mut base = Url::parse(base).map_err(|_| Error::Protocol("invalid base URL"))?;
        let loopback = base.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !(base.scheme() == "https" || base.scheme() == "http" && loopback)
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(Error::Protocol(
                "base URL requires HTTPS, or HTTP on loopback, without embedded credentials/query",
            ));
        }
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        if !(32..=512).contains(&token.len())
            || !token.bytes().all(|byte| (33..=126).contains(&byte))
        {
            return Err(Error::Protocol("invalid API token format"));
        }
        let mut bearer = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| Error::Protocol("invalid authentication header"))?;
        bearer.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, bearer);
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Transport)?;
        Ok(Self(Arc::new(Inner { http, base })))
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.0
            .base
            .join(path)
            .map_err(|_| Error::Protocol("invalid resource URL"))
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
        key: Option<&str>,
    ) -> Result<reqwest::Response> {
        if key.is_some_and(|key| {
            key.is_empty() || key.len() > 128 || !key.bytes().all(|byte| (33..=126).contains(&byte))
        }) {
            return Err(Error::Protocol("invalid idempotency key"));
        }
        let url = self.url(path)?;
        for attempt in 0..3 {
            let mut request = self
                .0
                .http
                .request(method.clone(), url.clone())
                .timeout(Duration::from_secs(30));
            if let Some(body) = &body {
                request = request.json(body);
            }
            if let Some(key) = key {
                request = request.header("idempotency-key", key);
            }
            match request.send().await {
                Ok(response) => return Self::checked(response).await,
                Err(_) if key.is_some() && attempt < 2 => {
                    tokio::time::sleep(Duration::from_millis(100 * (1 << attempt))).await
                }
                Err(_) => return Err(Error::Transport),
            }
        }
        Err(Error::Transport)
    }

    async fn checked(response: reqwest::Response) -> Result<reqwest::Response> {
        if response.status().is_success() {
            return Ok(response);
        }
        let body = Self::body(response, 64 * 1024).await?;
        Err(Error::Api(
            serde_json::from_slice(&body).map_err(|_| Error::Protocol("invalid error envelope"))?,
        ))
    }
    async fn body(response: reqwest::Response, max: usize) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(packet) = stream.next().await {
            let packet = packet.map_err(|_| Error::Transport)?;
            if bytes.len() + packet.len() > max {
                return Err(Error::Protocol("response size exceeds limit"));
            }
            bytes.extend_from_slice(&packet);
        }
        Ok(bytes)
    }
    async fn json<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
        serde_json::from_slice(&Self::body(response, 24 * 1024 * 1024).await?)
            .map_err(|_| Error::Protocol("invalid JSON response"))
    }
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        Self::json(self.send(Method::GET, path, None, None).await?).await
    }

    pub async fn profiles(&self) -> Result<Vec<RuntimeProfile>> {
        self.get("v1/profiles").await
    }
    pub async fn create(&self, request: &CreateSandbox, key: &str) -> Result<SandboxCreated> {
        let value: SandboxCreated = Self::json(
            self.send(
                Method::POST,
                "v1/sandboxes",
                Some(
                    serde_json::to_value(request)
                        .map_err(|_| Error::Protocol("invalid create request"))?,
                ),
                Some(key),
            )
            .await?,
        )
        .await?;
        if value.sandbox.id.is_nil()
            || value.operation.resource_id != value.sandbox.id
            || value.sandbox.profile != request.profile
            || value.sandbox.image != request.image
        {
            return Err(Error::Protocol("create response identity mismatch"));
        }
        Ok(value)
    }
    pub async fn sandbox(&self, id: Uuid) -> Result<Sandbox> {
        let value: Sandbox = self.get(&format!("v1/sandboxes/{id}")).await?;
        if value.id != id {
            return Err(Error::Protocol("sandbox identity mismatch"));
        }
        Ok(value)
    }
    pub async fn diagnostics(&self, id: Uuid) -> Result<SandboxDiagnostics> {
        let value: SandboxDiagnostics = self.get(&format!("v1/sandboxes/{id}/diagnostics")).await?;
        if value.sandbox.id != id
            || value
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.sandbox_id != id)
        {
            return Err(Error::Protocol("diagnostics identity mismatch"));
        }
        Ok(value)
    }
    pub async fn list(&self, after: Option<Uuid>, limit: u32) -> Result<SandboxPage> {
        let mut path = format!("v1/sandboxes?limit={limit}");
        if let Some(id) = after {
            path.push_str(&format!("&after={id}"));
        }
        self.get(&path).await
    }
    pub async fn operation(&self, id: Uuid) -> Result<Operation> {
        let value: Operation = self.get(&format!("v1/operations/{id}")).await?;
        if value.id != id {
            return Err(Error::Protocol("operation identity mismatch"));
        }
        Ok(value)
    }
    pub async fn wait_operation(&self, id: Uuid, timeout: Duration) -> Result<Operation> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let value = tokio::time::timeout(remaining, self.operation(id))
                .await
                .map_err(|_| Error::Timeout(id))??;
            if value.state.is_terminal() {
                return if value.state == OperationState::Succeeded {
                    Ok(value)
                } else {
                    Err(Error::Api(value.error.unwrap_or_else(|| {
                        ApiError::new(ErrorCode::InvalidState, "operation did not succeed")
                    })))
                };
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout(id));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    async fn change(&self, id: Uuid, action: &str, key: &str) -> Result<Operation> {
        let (method, path) = if action == "terminate" {
            (Method::DELETE, format!("v1/sandboxes/{id}"))
        } else {
            (Method::POST, format!("v1/sandboxes/{id}/{action}"))
        };
        let value: Operation = Self::json(self.send(method, &path, None, Some(key)).await?).await?;
        if value.resource_id != id {
            return Err(Error::Protocol("operation resource mismatch"));
        }
        Ok(value)
    }
    pub async fn terminate(&self, id: Uuid, key: &str) -> Result<Operation> {
        self.change(id, "terminate", key).await
    }
    pub async fn pause(&self, id: Uuid, key: &str) -> Result<Operation> {
        self.change(id, "pause", key).await
    }
    pub async fn resume(&self, id: Uuid, key: &str) -> Result<Operation> {
        self.change(id, "resume", key).await
    }
    pub async fn start(
        &self,
        sandbox: Uuid,
        command: &CommandSpec,
        key: &str,
    ) -> Result<Execution> {
        let value: Execution = Self::json(
            self.send(
                Method::POST,
                &format!("v1/sandboxes/{sandbox}/commands"),
                Some(
                    serde_json::to_value(command)
                        .map_err(|_| Error::Protocol("invalid command"))?,
                ),
                Some(key),
            )
            .await?,
        )
        .await?;
        if value.sandbox_id != sandbox || value.id.is_nil() {
            return Err(Error::Protocol("execution identity mismatch"));
        }
        Ok(value)
    }
    pub async fn execution(&self, id: Uuid) -> Result<Execution> {
        let value: Execution = self.get(&format!("v1/executions/{id}")).await?;
        if value.id != id {
            return Err(Error::Protocol("execution identity mismatch"));
        }
        Ok(value)
    }
    pub async fn cancel(&self, id: Uuid) -> Result<Execution> {
        let value: Execution = Self::json(
            self.send(
                Method::POST,
                &format!("v1/executions/{id}/cancel"),
                None,
                None,
            )
            .await?,
        )
        .await?;
        if value.id != id {
            return Err(Error::Protocol("cancel response identity mismatch"));
        }
        Ok(value)
    }
    pub async fn wait_execution(&self, id: Uuid, timeout: Duration) -> Result<Execution> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let value = tokio::time::timeout(remaining, self.execution(id))
                .await
                .map_err(|_| Error::Timeout(id))??;
            if value.state.is_terminal() {
                if value.cleanup != CleanupState::Complete {
                    return Err(Error::Protocol("terminal result has unconfirmed cleanup"));
                }
                return Ok(value);
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout(id));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    pub async fn write_file(&self, id: Uuid, path: &str, bytes: &[u8]) -> Result<()> {
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(Error::Protocol("file exceeds 16 MiB transfer limit"));
        }
        self.send(
            Method::PUT,
            &format!("v1/sandboxes/{id}/files"),
            Some(serde_json::json!({"path":path,"data_base64":STANDARD.encode(bytes)})),
            None,
        )
        .await?;
        Ok(())
    }
    pub async fn read_file(&self, id: Uuid, path: &str, max: u64) -> Result<Vec<u8>> {
        let mut url = self.url(&format!("v1/sandboxes/{id}/files"))?;
        url.query_pairs_mut()
            .append_pair("path", path)
            .append_pair("max_bytes", &max.to_string());
        let response = Self::checked(
            self.0
                .http
                .get(url)
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .map_err(|_| Error::Transport)?,
        )
        .await?;
        let file: FileData = Self::json(response).await?;
        let bytes = STANDARD
            .decode(file.data_base64)
            .map_err(|_| Error::Protocol("invalid binary file encoding"))?;
        if bytes.len() as u64 > max || bytes.len() > 16 * 1024 * 1024 {
            return Err(Error::Protocol("file exceeds requested transfer limit"));
        }
        Ok(bytes)
    }
    pub async fn list_files(&self, id: Uuid, path: &str) -> Result<Vec<FileInfo>> {
        let mut url = self.url(&format!("v1/sandboxes/{id}/directories"))?;
        url.query_pairs_mut().append_pair("path", path);
        Self::json(
            Self::checked(
                self.0
                    .http
                    .get(url)
                    .timeout(Duration::from_secs(30))
                    .send()
                    .await
                    .map_err(|_| Error::Transport)?,
            )
            .await?,
        )
        .await
    }
    pub async fn remove_file(&self, id: Uuid, path: &str) -> Result<()> {
        let mut url = self.url(&format!("v1/sandboxes/{id}/files"))?;
        url.query_pairs_mut().append_pair("path", path);
        Self::checked(
            self.0
                .http
                .delete(url)
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .map_err(|_| Error::Transport)?,
        )
        .await?;
        Ok(())
    }
    pub async fn lease(&self, request: &CreateSandbox) -> Result<SandboxLease> {
        let key = Uuid::new_v4().to_string();
        let created = match self.create(request, &key).await {
            Ok(created) => created,
            Err(Error::Transport) => return Err(Error::UncertainRequest(key)),
            Err(Error::Api(error)) if error.code == ErrorCode::BackendUnavailable => {
                return Err(Error::UncertainRequest(key));
            }
            Err(error) => return Err(error),
        };
        let mut lease = SandboxLease {
            client: self.clone(),
            id: created.sandbox.id,
            delete_key: Uuid::new_v4().to_string(),
            closed: false,
        };
        let ready = async {
            self.wait_operation(created.operation.id, Duration::from_secs(60))
                .await?;
            if self.sandbox(lease.id).await?.state != SandboxState::Running {
                return Err(Error::Protocol("sandbox is not running after create"));
            }
            Ok(())
        }
        .await;
        if let Err(original) = ready {
            if let Err(cleanup) = lease.close().await {
                return Err(Error::Cleanup(
                    lease.id,
                    Box::new(original),
                    Box::new(cleanup),
                ));
            }
            return Err(original);
        }
        Ok(lease)
    }
}

pub struct SandboxLease {
    client: Client,
    id: Uuid,
    delete_key: String,
    closed: bool,
}
impl SandboxLease {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        let operation = self.client.terminate(self.id, &self.delete_key).await?;
        self.client
            .wait_operation(operation.id, Duration::from_secs(60))
            .await?;
        let sandbox = self.client.sandbox(self.id).await?;
        if sandbox.cleanup != CleanupState::Complete
            || !matches!(
                sandbox.state,
                SandboxState::Terminated | SandboxState::Failed
            )
        {
            return Err(Error::Protocol("sandbox cleanup is not confirmed"));
        }
        self.closed = true;
        Ok(())
    }
}
impl Drop for SandboxLease {
    fn drop(&mut self) {
        if !self.closed
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let client = self.client.clone();
            let id = self.id;
            let key = self.delete_key.clone();
            // Best effort only. Use close().await when confirmed cleanup is required.
            runtime.spawn(async move {
                if let Ok(operation) = client.terminate(id, &key).await {
                    let _ = client
                        .wait_operation(operation.id, Duration::from_secs(60))
                        .await;
                }
            });
        }
    }
}
