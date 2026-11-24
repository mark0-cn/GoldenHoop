//! Private installation-owned blobs. Public artifact metadata belongs to control state.
use std::{path::Path as FsPath, sync::Arc, time::Duration};

use bytes::Bytes;
use futures_util::StreamExt;
use goldenhoop_protocol::{ApiError, ErrorCode};
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, path::Path};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const MAX_BLOB_BYTES: usize = 16 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    pub id: Uuid,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Explicit static credentials; this type deliberately does not implement Debug.
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

#[derive(Clone)]
pub struct BlobStore {
    backend: Arc<dyn ObjectStore>,
    installation: Uuid,
    binding: String,
    probe_scope: bool,
}

#[derive(Debug)]
struct DirectConnector(reqwest::Client);
impl object_store::client::HttpConnector for DirectConnector {
    fn connect(
        &self,
        _options: &object_store::ClientOptions,
    ) -> object_store::Result<object_store::client::HttpClient> {
        Ok(object_store::client::HttpClient::new(self.0.clone()))
    }
}

fn invalid(message: &str) -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest, message)
}
fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "artifact storage is unavailable; reconcile the same blob ID before retrying",
    )
}
fn corrupt() -> ApiError {
    ApiError::new(ErrorCode::Conflict, "artifact integrity check failed")
}
fn backend(error: object_store::Error) -> ApiError {
    match error {
        object_store::Error::NotFound { .. } => {
            ApiError::new(ErrorCode::NotFound, "artifact blob is absent")
        }
        object_store::Error::AlreadyExists { .. } => {
            ApiError::new(ErrorCode::Conflict, "artifact blob already exists")
        }
        _ => unavailable(),
    }
}

impl BlobStore {
    /// The root and its parents must be trusted host directories, never workload mounts.
    pub fn local(root: &FsPath, installation: Uuid) -> Result<Self, ApiError> {
        if installation.is_nil() {
            return Err(invalid("installation UUID must not be nil"));
        }
        let mut directories = std::fs::DirBuilder::new();
        directories.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directories.mode(0o700);
        }
        directories.create(root).map_err(|_| unavailable())?;
        let metadata = std::fs::symlink_metadata(root).map_err(|_| unavailable())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid("artifact root must be a private directory"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(invalid(
                    "artifact root permissions must exclude group and other users",
                ));
            }
        }
        let backend = object_store::local::LocalFileSystem::new_with_prefix(root)
            .map_err(backend)?
            .with_fsync(true)
            .with_automatic_cleanup(true);
        let canonical = root.canonicalize().map_err(|_| unavailable())?;
        let mut digest = Sha256::new();
        digest.update(b"local\0");
        digest.update(canonical.as_os_str().as_encoded_bytes());
        Self::new(
            Arc::new(backend),
            installation,
            format!("{:x}", digest.finalize()),
        )
    }

    /// S3-compatible path-style endpoint with conditional writes; never falls back locally.
    pub fn s3(config: S3Config, installation: Uuid) -> Result<Self, ApiError> {
        if installation.is_nil() {
            return Err(invalid("installation UUID must not be nil"));
        }
        use object_store::aws::{AmazonS3Builder, S3ConditionalPut};
        let endpoint = reqwest::Url::parse(&config.endpoint)
            .map_err(|_| invalid("invalid artifact endpoint"))?;
        let loopback = endpoint.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if !(endpoint.scheme() == "https" || endpoint.scheme() == "http" && loopback)
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(invalid(
                "artifact endpoint requires HTTPS, or HTTP on loopback, without embedded credentials/query",
            ));
        }
        if config.access_key_id.is_empty()
            || config.secret_access_key.is_empty()
            || config.region.is_empty()
            || config.bucket.is_empty()
        {
            return Err(invalid(
                "explicit artifact bucket, region and credentials are required",
            ));
        }
        let binding=format!("{:x}",Sha256::digest(serde_json::to_vec(&serde_json::json!({"kind":"s3","endpoint":endpoint.as_str().trim_end_matches('/'),"bucket":config.bucket,"region":config.region})).map_err(|_|invalid("invalid artifact namespace"))?));
        let options = object_store::ClientOptions::new()
            .with_timeout(Duration::from_secs(20))
            .with_connect_timeout(Duration::from_secs(5));
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| unavailable())?;
        let mut builder = AmazonS3Builder::new()
            .with_endpoint(config.endpoint)
            .with_bucket_name(config.bucket)
            .with_region(config.region)
            .with_access_key_id(config.access_key_id)
            .with_secret_access_key(config.secret_access_key)
            .with_allow_http(endpoint.scheme() == "http")
            .with_virtual_hosted_style_request(false)
            .with_conditional_put(S3ConditionalPut::ETagMatch)
            .with_http_connector(DirectConnector(http))
            .with_client_options(options)
            .with_retry(object_store::RetryConfig {
                max_retries: 2,
                ..Default::default()
            });
        if let Some(token) = config.session_token {
            builder = builder.with_token(token);
        }
        Self::new(
            Arc::new(builder.build().map_err(backend)?),
            installation,
            binding,
        )
    }

    fn new(
        backend: Arc<dyn ObjectStore>,
        installation: Uuid,
        binding: String,
    ) -> Result<Self, ApiError> {
        if installation.is_nil() {
            return Err(invalid("installation UUID must not be nil"));
        }
        Ok(Self {
            backend,
            installation,
            binding,
            probe_scope: false,
        })
    }
    /// Namespace identity excludes credentials, so key rotation does not move data.
    pub fn binding(&self) -> &str {
        &self.binding
    }
    pub fn installation_id(&self) -> Uuid {
        self.installation
    }
    fn path(&self, id: Uuid) -> Result<Path, ApiError> {
        if id.is_nil() {
            return Err(invalid("blob UUID must not be nil"));
        }
        Ok(if self.probe_scope {
            Path::from(format!("goldenhoop/{}/probes/{id}", self.installation))
        } else {
            Path::from(format!("goldenhoop/{}/{id}", self.installation))
        })
    }
    /// Bounded listing of canonical IDs in this store's own namespace.
    pub async fn ids(&self) -> Result<Vec<Uuid>, ApiError> {
        let prefix = Path::from(if self.probe_scope {
            format!("goldenhoop/{}/probes", self.installation)
        } else {
            format!("goldenhoop/{}", self.installation)
        });
        let list = async {
            let mut objects = self.backend.list(Some(&prefix));
            let mut ids = Vec::new();
            for _ in 0..1024 {
                let Some(object) = objects.next().await else {
                    break;
                };
                let object = object.map_err(backend)?;
                let key = object.location.to_string();
                if let Some(id) = key
                    .rsplit('/')
                    .next()
                    .and_then(|value| value.parse::<Uuid>().ok())
                    && !id.is_nil()
                    && self.path(id)? == object.location
                {
                    ids.push(id);
                }
            }
            Ok(ids)
        };
        tokio::time::timeout(DEADLINE, list)
            .await
            .map_err(|_| unavailable())?
    }
    /// Controller maintenance only; call when this installation has no active probe.
    pub async fn clear_probe_residue(&self) -> Result<(), ApiError> {
        let mut probe = self.clone();
        probe.probe_scope = true;
        for id in probe.ids().await? {
            probe.delete(id).await?;
        }
        Ok(())
    }
    fn validate(reference: &BlobRef) -> Result<(), ApiError> {
        if reference.size_bytes > MAX_BLOB_BYTES as u64
            || reference.sha256.len() != 64
            || !reference
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid("invalid artifact blob reference"));
        }
        Ok(())
    }

    pub async fn put(&self, id: Uuid, data: &[u8]) -> Result<BlobRef, ApiError> {
        if data.len() > MAX_BLOB_BYTES {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "artifact exceeds 16 MiB transfer limit",
            ));
        }
        let path = self.path(id)?;
        let reference = BlobRef {
            id,
            sha256: format!("{:x}", Sha256::digest(data)),
            size_bytes: data.len() as u64,
        };
        let outcome = tokio::time::timeout(
            DEADLINE,
            self.backend.put_opts(
                &path,
                Bytes::copy_from_slice(data).into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            ),
        )
        .await
        .map_err(|_| unavailable())?;
        match outcome {
            Ok(_) => {}
            Err(object_store::Error::AlreadyExists { .. }) => {
                self.read(&reference).await.map_err(|error| {
                    if error.code == ErrorCode::Conflict {
                        ApiError::new(ErrorCode::Conflict, "blob ID already holds different bytes")
                    } else {
                        error
                    }
                })?;
                return Ok(reference);
            }
            Err(error) => return Err(backend(error)),
        }
        // A backend acknowledgement alone is insufficient: verify stored bytes.
        self.read(&reference).await?;
        Ok(reference)
    }

    pub async fn read(&self, reference: &BlobRef) -> Result<Vec<u8>, ApiError> {
        Self::validate(reference)?;
        let path = self.path(reference.id)?;
        let fetch = async {
            let result = self.backend.get(&path).await.map_err(backend)?;
            if result.meta.size != reference.size_bytes {
                return Err(corrupt());
            }
            let mut stream = result.into_stream();
            let mut data = Vec::new();
            let mut hash = Sha256::new();
            while let Some(packet) = stream.next().await {
                let packet = packet.map_err(backend)?;
                if data.len() + packet.len() > MAX_BLOB_BYTES
                    || (data.len() + packet.len()) as u64 > reference.size_bytes
                {
                    return Err(corrupt());
                }
                hash.update(&packet);
                data.extend_from_slice(&packet);
            }
            if data.len() as u64 != reference.size_bytes
                || format!("{:x}", hash.finalize()) != reference.sha256
            {
                return Err(corrupt());
            }
            Ok(data)
        };
        tokio::time::timeout(DEADLINE, fetch)
            .await
            .map_err(|_| unavailable())?
    }

    /// Return only after a fresh HEAD confirms absence of this installation's key.
    pub async fn delete(&self, id: Uuid) -> Result<(), ApiError> {
        let path = self.path(id)?;
        let remove = async {
            match self.backend.delete(&path).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(error) => return Err(backend(error)),
            }
            match self.backend.head(&path).await {
                Err(object_store::Error::NotFound { .. }) => Ok(()),
                Ok(_) => Err(unavailable()),
                Err(error) => Err(backend(error)),
            }
        };
        tokio::time::timeout(DEADLINE, remove)
            .await
            .map_err(|_| unavailable())?
    }

    /// Actual read/write/delete probe; cleanup follows both success and failure.
    pub async fn probe(&self) -> Result<(), ApiError> {
        let mut probe = self.clone();
        probe.probe_scope = true;
        let id = Uuid::new_v4();
        let result = async {
            let reference = probe.put(id, b"GoldenHoop artifact probe\x00\xff").await?;
            if probe.read(&reference).await? != b"GoldenHoop artifact probe\x00\xff" {
                return Err(corrupt());
            }
            if !probe.ids().await?.contains(&id) {
                return Err(unavailable());
            }
            Ok(())
        }
        .await;
        if probe.delete(id).await.is_err() {
            return Err(ApiError::new(
                ErrorCode::BackendUnavailable,
                format!("artifact probe cleanup is unconfirmed for blob {id}"),
            ));
        }
        result
    }
}
