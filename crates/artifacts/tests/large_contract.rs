use goldenhoop_artifacts::{BlobStore, LARGE_CHUNK_BYTES, LargeBlobRef, MAX_LARGE_BLOB_BYTES};
use goldenhoop_protocol::ErrorCode;
use sha2::{Digest, Sha256};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

struct Pattern {
    size: u64,
    position: u64,
    fail_at: Option<u64>,
}
impl Pattern {
    fn new(size: u64) -> Self {
        Self {
            size,
            position: 0,
            fail_at: None,
        }
    }
    fn digest(size: u64) -> String {
        let mut hash = Sha256::new();
        for start in (0..size).step_by(65536) {
            let block: Vec<_> = (start..size.min(start + 65536))
                .map(|n| (n % 251) as u8)
                .collect();
            hash.update(block);
        }
        format!("{:x}", hash.finalize())
    }
}
impl AsyncRead for Pattern {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        assert!(
            output.remaining() <= LARGE_CHUNK_BYTES,
            "read must remain chunk bounded"
        );
        if self.fail_at.is_some_and(|at| self.position >= at) {
            return Poll::Ready(Err(io::Error::other("injected source disconnect")));
        }
        let end = self.size.min(self.fail_at.unwrap_or(self.size));
        let count = (end - self.position).min(output.remaining() as u64) as usize;
        let bytes = output.initialize_unfilled_to(count);
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = ((self.position + index as u64) % 251) as u8;
        }
        output.advance(count);
        self.position += count as u64;
        Poll::Ready(Ok(()))
    }
}
#[derive(Default)]
struct CheckOutput {
    position: u64,
}
impl AsyncWrite for CheckOutput {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        assert!(
            bytes.len() <= LARGE_CHUNK_BYTES,
            "write must remain chunk bounded"
        );
        assert!(
            bytes
                .iter()
                .enumerate()
                .all(|(index, byte)| *byte == ((self.position + index as u64) % 251) as u8)
        );
        self.position += bytes.len() as u64;
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
fn prefix(root: &std::path::Path, reference: &LargeBlobRef) -> std::path::PathBuf {
    root.join("goldenhoop")
        .join(reference.installation_id.to_string())
        .join("large")
        .join(reference.id.to_string())
        .join(reference.generation.to_string())
}

#[tokio::test]
async fn streams_over_16mib_reopens_and_confirms_collection_without_touching_other_generations() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_owned();
    let root = path.join("objects");
    let installation = Uuid::new_v4();
    let store = BlobStore::local(&root, installation).unwrap();
    let size = 25 * 1024 * 1024 + 123;
    let digest = Pattern::digest(size);
    let reference = store
        .large_reference(Uuid::new_v4(), digest.clone(), size)
        .unwrap();
    // This is the reference the controller must journal before any upload.
    let saved = serde_json::to_vec(&reference).unwrap();
    store
        .put_large(&reference, Pattern::new(size))
        .await
        .unwrap();
    assert!(
        store.ids().await.unwrap().is_empty(),
        "large keys never become small public artifacts"
    );
    let other = store.large_reference(reference.id, digest, size).unwrap();
    store.put_large(&other, Pattern::new(size)).await.unwrap();
    let small = store
        .put(Uuid::new_v4(), b"retained small artifact")
        .await
        .unwrap();
    drop(store);
    let reopened = BlobStore::local(&root, installation).unwrap();
    let reference: LargeBlobRef = serde_json::from_slice(&saved).unwrap();
    reopened
        .put_large(&reference, Pattern::new(size))
        .await
        .unwrap();
    let mut output = CheckOutput::default();
    reopened
        .download_large(&reference, &mut output)
        .await
        .unwrap();
    assert_eq!(output.position, size);
    let stranger = BlobStore::local(&root, Uuid::new_v4()).unwrap();
    assert_eq!(
        stranger.collect_large(&reference).await.unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    reopened.collect_large(&reference).await.unwrap();
    reopened.collect_large(&reference).await.unwrap();
    assert!(!prefix(&root, &reference).exists());
    assert!(prefix(&root, &other).join("manifest").exists());
    assert_eq!(
        reopened.read(&small).await.unwrap(),
        b"retained small artifact"
    );
    reopened
        .download_large(&other, tokio::io::sink())
        .await
        .unwrap();
    reopened.collect_large(&other).await.unwrap();
    reopened.delete(small.id).await.unwrap();
    assert!(std::fs::read_dir(&root).unwrap().next().is_none());
    drop(stranger);
    drop(reopened);
    directory.close().unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn failed_input_does_not_publish_and_same_journaled_generation_resumes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_owned();
    let root = path.join("objects");
    let installation = Uuid::new_v4();
    let store = BlobStore::local(&root, installation).unwrap();
    let size = 2 * LARGE_CHUNK_BYTES as u64 + 7;
    let reference = store
        .large_reference(Uuid::new_v4(), Pattern::digest(size), size)
        .unwrap();
    let mut failed = Pattern::new(size);
    failed.fail_at = Some(LARGE_CHUNK_BYTES as u64 + 123);
    assert_eq!(
        store.put_large(&reference, failed).await.unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    assert!(prefix(&root, &reference).join("chunk-00000000").exists());
    assert!(!prefix(&root, &reference).join("manifest").exists());
    assert_eq!(
        store
            .download_large(&reference, tokio::io::sink())
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    drop(store);
    let reopened = BlobStore::local(&root, installation).unwrap();
    reopened
        .put_large(&reference, Pattern::new(size))
        .await
        .unwrap();
    reopened
        .download_large(&reference, CheckOutput::default())
        .await
        .unwrap();
    reopened.collect_large(&reference).await.unwrap();
    assert!(!prefix(&root, &reference).exists());
    drop(reopened);
    directory.close().unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn corruption_wrong_intent_unknown_keys_and_lengths_cannot_become_success() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_owned();
    let root = path.join("objects");
    let store = BlobStore::local(&root, Uuid::new_v4()).unwrap();
    let size = LARGE_CHUNK_BYTES as u64 + 7;
    let reference = store
        .large_reference(Uuid::new_v4(), Pattern::digest(size), size)
        .unwrap();
    store
        .put_large(&reference, Pattern::new(size))
        .await
        .unwrap();
    let owned = prefix(&root, &reference);
    let chunk = owned.join("chunk-00000000");
    let original = std::fs::read(&chunk).unwrap();
    let mut changed = original.clone();
    changed[0] ^= 1;
    std::fs::write(&chunk, &changed).unwrap();
    let mut output = CheckOutput::default();
    assert_eq!(
        store
            .download_large(&reference, &mut output)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(output.position, 0);
    assert_eq!(
        store
            .put_large(&reference, Pattern::new(size))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    std::fs::write(&chunk, &original).unwrap();
    let mut wrong = reference.clone();
    wrong.sha256 = "0".repeat(64);
    assert_eq!(
        store.collect_large(&wrong).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    assert!(owned.join("manifest").exists());
    let unexpected = owned.join("foreign-evidence");
    std::fs::write(&unexpected, b"test-owned evidence").unwrap();
    assert_eq!(
        store.collect_large(&reference).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    assert!(chunk.exists());
    std::fs::remove_file(&unexpected).unwrap();
    assert!(!unexpected.exists());
    store.collect_large(&reference).await.unwrap();
    for declared in [size - 1, size + 1] {
        let reference = store
            .large_reference(Uuid::new_v4(), Pattern::digest(size), declared)
            .unwrap();
        assert_eq!(
            store
                .put_large(&reference, Pattern::new(size))
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );
        assert!(!prefix(&root, &reference).join("manifest").exists());
        store.collect_large(&reference).await.unwrap();
    }
    let wrong = store
        .large_reference(Uuid::new_v4(), "0".repeat(64), size)
        .unwrap();
    assert_eq!(
        store
            .put_large(&wrong, Pattern::new(size))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    store.collect_large(&wrong).await.unwrap();
    assert!(std::fs::read_dir(&root).unwrap().next().is_none());
    drop(store);
    directory.close().unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn invalid_references_are_side_effect_free_and_empty_content_is_verified() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_owned();
    let root = path.join("objects");
    let store = BlobStore::local(&root, Uuid::new_v4()).unwrap();
    for (id, hash, size) in [
        (Uuid::nil(), Pattern::digest(0), 0),
        (Uuid::new_v4(), "bad".into(), 1),
        (Uuid::new_v4(), Pattern::digest(0), MAX_LARGE_BLOB_BYTES + 1),
    ] {
        assert_eq!(
            store.large_reference(id, hash, size).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }
    assert!(std::fs::read_dir(&root).unwrap().next().is_none());
    let reference = store
        .large_reference(Uuid::new_v4(), Pattern::digest(0), 0)
        .unwrap();
    store
        .put_large(&reference, tokio::io::empty())
        .await
        .unwrap();
    store
        .download_large(&reference, CheckOutput::default())
        .await
        .unwrap();
    store.collect_large(&reference).await.unwrap();
    assert!(std::fs::read_dir(&root).unwrap().next().is_none());
    drop(store);
    directory.close().unwrap();
    assert!(!path.exists());
}
