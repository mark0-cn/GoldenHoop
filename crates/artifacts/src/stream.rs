//! Host-only, immutable large objects. The caller journals the full reference
//! before upload and fences all writers/readers before explicit collection.
//! Downloads go to private staging: bytes are trusted only after final success.
use super::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const LARGE_CHUNK_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_LARGE_BLOB_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const LARGE_DEADLINE: Duration = Duration::from_secs(15 * 60);

/// Internal storage identity, not workload authorization. A new generation has
/// its own keys, so a failed allocation cannot collect another version's data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LargeBlobRef {
    pub installation_id: Uuid,
    pub storage_binding: String,
    pub id: Uuid,
    pub generation: Uuid,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Chunk {
    sha256: String,
    size_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    reference: LargeBlobRef,
    chunk_bytes: usize,
    chunks: Vec<Chunk>,
}

fn sha(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn uncertain() -> ApiError {
    let mut error = ApiError::new(
        ErrorCode::BackendUnavailable,
        "large artifact operation is unconfirmed; reconcile its journaled generation",
    );
    error.retryable = false;
    error
}
fn storage_error(error: object_store::Error) -> ApiError {
    match error {
        object_store::Error::NotFound { .. } => {
            ApiError::new(ErrorCode::NotFound, "large artifact object is absent")
        }
        _ => uncertain(),
    }
}

impl BlobStore {
    /// Allocates no storage. Persist this reference before starting the upload.
    pub fn large_reference(
        &self,
        id: Uuid,
        sha256: String,
        size_bytes: u64,
    ) -> Result<LargeBlobRef, ApiError> {
        let reference = LargeBlobRef {
            installation_id: self.installation,
            storage_binding: self.binding.clone(),
            id,
            generation: Uuid::new_v4(),
            sha256,
            size_bytes,
        };
        self.large_prefix(&reference)?;
        Ok(reference)
    }

    fn large_prefix(&self, reference: &LargeBlobRef) -> Result<Path, ApiError> {
        if self.probe_scope
            || reference.installation_id != self.installation
            || reference.storage_binding != self.binding
            || reference.id.is_nil()
            || reference.generation.is_nil()
            || !valid_sha(&reference.sha256)
            || reference.size_bytes > MAX_LARGE_BLOB_BYTES
        {
            return Err(invalid("invalid or foreign large artifact reference"));
        }
        Ok(Path::from(format!(
            "goldenhoop/{}/large/{}/{}",
            self.installation, reference.id, reference.generation
        )))
    }

    async fn bounded_object(&self, path: &Path, limit: usize) -> Result<Vec<u8>, ApiError> {
        let result = self.backend.get(path).await.map_err(storage_error)?;
        if result.meta.size > limit as u64 {
            return Err(corrupt());
        }
        let expected = result.meta.size as usize;
        let mut stream = result.into_stream();
        let mut bytes = Vec::with_capacity(expected);
        while let Some(packet) = stream.next().await {
            let packet = packet.map_err(storage_error)?;
            if packet.len() > expected.saturating_sub(bytes.len()) {
                return Err(corrupt());
            }
            bytes.extend_from_slice(&packet);
        }
        if bytes.len() != expected {
            return Err(corrupt());
        }
        Ok(bytes)
    }

    async fn immutable_object(&self, path: &Path, bytes: Bytes) -> Result<(), ApiError> {
        let expected_len = bytes.len();
        let expected_sha = sha(&bytes);
        match self
            .backend
            .put_opts(
                path,
                bytes.into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await
        {
            Ok(_) | Err(object_store::Error::AlreadyExists { .. }) => {}
            Err(error) => return Err(storage_error(error)),
        }
        let stored = self.bounded_object(path, expected_len).await?;
        if stored.len() != expected_len || sha(&stored) != expected_sha {
            return Err(corrupt());
        }
        Ok(())
    }

    fn large_chunks(reference: &LargeBlobRef) -> usize {
        reference.size_bytes.div_ceil(LARGE_CHUNK_BYTES as u64) as usize
    }
    fn chunk_path(prefix: &Path, index: usize) -> Path {
        prefix.clone().join(format!("chunk-{index:08}"))
    }
    fn chunk_len(reference: &LargeBlobRef, index: usize) -> u64 {
        (reference.size_bytes - index as u64 * LARGE_CHUNK_BYTES as u64)
            .min(LARGE_CHUNK_BYTES as u64)
    }

    async fn large_manifest(
        &self,
        prefix: &Path,
        reference: &LargeBlobRef,
    ) -> Result<Manifest, ApiError> {
        let bytes = self
            .bounded_object(&prefix.clone().join("manifest"), MAX_MANIFEST_BYTES)
            .await?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
        if manifest.format != 1
            || manifest.reference != *reference
            || manifest.chunk_bytes != LARGE_CHUNK_BYTES
            || manifest.chunks.len() != Self::large_chunks(reference)
            || manifest.chunks.iter().enumerate().any(|(index, chunk)| {
                !valid_sha(&chunk.sha256) || chunk.size_bytes != Self::chunk_len(reference, index)
            })
        {
            return Err(corrupt());
        }
        Ok(manifest)
    }

    /// Same-reference retries are immutable. An interrupted upload stays
    /// uncommitted and can be resumed or explicitly collected after fencing.
    /// No S3 multipart session is created or left for a bucket-wide collector.
    pub async fn put_large(
        &self,
        reference: &LargeBlobRef,
        mut input: impl AsyncRead + Unpin,
    ) -> Result<(), ApiError> {
        let prefix = self.large_prefix(reference)?;
        let transfer = async {
            let intent =
                serde_json::to_vec(reference).map_err(|_| invalid("invalid upload intent"))?;
            self.immutable_object(&prefix.clone().join("intent"), intent.into())
                .await?;
            let mut chunks = Vec::with_capacity(Self::large_chunks(reference));
            let mut whole = Sha256::new();
            for index in 0..Self::large_chunks(reference) {
                let mut bytes = vec![0; Self::chunk_len(reference, index) as usize];
                input
                    .read_exact(&mut bytes)
                    .await
                    .map_err(|_| invalid("large artifact input ended early or failed"))?;
                whole.update(&bytes);
                chunks.push(Chunk {
                    sha256: sha(&bytes),
                    size_bytes: bytes.len() as u64,
                });
                self.immutable_object(&Self::chunk_path(&prefix, index), bytes.into())
                    .await?;
            }
            let mut extra = [0; 1];
            if input.read(&mut extra).await.map_err(|_| uncertain())? != 0 {
                return Err(invalid("large artifact input exceeds declared length"));
            }
            if format!("{:x}", whole.finalize()) != reference.sha256 {
                return Err(corrupt());
            }
            let manifest = Manifest {
                format: 1,
                reference: reference.clone(),
                chunk_bytes: LARGE_CHUNK_BYTES,
                chunks,
            };
            let bytes = serde_json::to_vec(&manifest).map_err(|_| corrupt())?;
            if bytes.len() > MAX_MANIFEST_BYTES {
                return Err(invalid("large artifact manifest exceeds limit"));
            }
            // This is the only publication point, after every chunk readback
            // and the whole input digest. It never overwrites an old manifest.
            self.immutable_object(&prefix.clone().join("manifest"), bytes.into())
                .await?;
            self.large_manifest(&prefix, reference).await?;
            Ok(())
        };
        tokio::time::timeout(LARGE_DEADLINE, transfer)
            .await
            .map_err(|_| uncertain())?
    }

    /// Write only into private staging. A failed download may have partial bytes;
    /// its caller must collect staging and must not expose it to a workload.
    pub async fn download_large(
        &self,
        reference: &LargeBlobRef,
        mut output: impl AsyncWrite + Unpin,
    ) -> Result<(), ApiError> {
        let prefix = self.large_prefix(reference)?;
        let transfer = async {
            let manifest = self.large_manifest(&prefix, reference).await?;
            let mut whole = Sha256::new();
            for (index, chunk) in manifest.chunks.iter().enumerate() {
                let bytes = self
                    .bounded_object(&Self::chunk_path(&prefix, index), LARGE_CHUNK_BYTES)
                    .await?;
                if bytes.len() as u64 != chunk.size_bytes || sha(&bytes) != chunk.sha256 {
                    return Err(corrupt());
                }
                whole.update(&bytes);
                output.write_all(&bytes).await.map_err(|_| uncertain())?;
            }
            if format!("{:x}", whole.finalize()) != reference.sha256 {
                return Err(corrupt());
            }
            output.flush().await.map_err(|_| uncertain())?;
            Ok(())
        };
        tokio::time::timeout(LARGE_DEADLINE, transfer)
            .await
            .map_err(|_| uncertain())?
    }

    async fn remove_large_key(&self, path: &Path) -> Result<(), ApiError> {
        match self.backend.delete(path).await {
            Ok(_) | Err(object_store::Error::NotFound { .. }) => {}
            Err(error) => return Err(storage_error(error)),
        }
        match self.backend.head(path).await {
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            _ => Err(uncertain()),
        }
    }

    async fn large_keys(&self, prefix: &Path, chunks: usize) -> Result<Vec<Path>, ApiError> {
        let mut listing = self.backend.list(Some(prefix));
        let mut keys = Vec::new();
        let start = format!("{prefix}/");
        while let Some(item) = listing.next().await {
            let key = item.map_err(storage_error)?.location;
            let name = key.as_ref().strip_prefix(&start).ok_or_else(corrupt)?;
            let canonical = name == "intent"
                || name == "manifest"
                || name
                    .strip_prefix("chunk-")
                    .and_then(|index| index.parse::<usize>().ok())
                    .is_some_and(|index| index < chunks && name == format!("chunk-{index:08}"));
            if keys.len() >= chunks + 2 || !canonical {
                return Err(corrupt());
            }
            keys.push(key);
        }
        Ok(keys)
    }

    /// Controller maintenance only, after the journal owner fences all users of
    /// this generation. Retain the journal until this returns confirmed absence.
    /// It never lists/deletes another generation, installation or small artifact.
    pub async fn collect_large(&self, reference: &LargeBlobRef) -> Result<(), ApiError> {
        let prefix = self.large_prefix(reference)?;
        let collect = async {
            let has_intent = match self
                .bounded_object(&prefix.clone().join("intent"), 4096)
                .await
            {
                Ok(bytes) => {
                    let intent: LargeBlobRef =
                        serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
                    if intent != *reference {
                        return Err(corrupt());
                    }
                    true
                }
                Err(error) if error.code == ErrorCode::NotFound => false,
                Err(error) => return Err(error),
            };
            // Validate the scoped key set before deleting any object. A foreign
            // or malformed object is evidence, not permission for prefix pruning.
            let keys = self
                .large_keys(&prefix, Self::large_chunks(reference))
                .await?;
            if !has_intent && !keys.is_empty() {
                return Err(corrupt());
            }
            self.remove_large_key(&prefix.clone().join("manifest"))
                .await?;
            for index in 0..Self::large_chunks(reference) {
                self.remove_large_key(&Self::chunk_path(&prefix, index))
                    .await?;
            }
            self.remove_large_key(&prefix.clone().join("intent"))
                .await?;
            if !self
                .large_keys(&prefix, Self::large_chunks(reference))
                .await?
                .is_empty()
            {
                return Err(uncertain());
            }
            Ok(())
        };
        tokio::time::timeout(LARGE_DEADLINE, collect)
            .await
            .map_err(|_| uncertain())?
    }
}
