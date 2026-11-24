//! Only a fresh test bucket/installation; the outer harness owns its backend.
use futures_util::FutureExt;
use goldenhoop_artifacts::{BlobStore, S3Config};
use goldenhoop_protocol::ErrorCode;
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn store(installation: Uuid) -> Result<BlobStore> {
    Ok(BlobStore::s3(
        S3Config {
            endpoint: std::env::var("GOLDENHOOP_ARTIFACT_ENDPOINT")?,
            bucket: std::env::var("GOLDENHOOP_ARTIFACT_BUCKET")?,
            region: "us-east-1".into(),
            access_key_id: std::env::var("GOLDENHOOP_ARTIFACT_ACCESS_KEY")?,
            secret_access_key: std::env::var("GOLDENHOOP_ARTIFACT_SECRET_KEY")?,
            session_token: None,
        },
        installation,
    )?)
}

async fn exercise(backend: &BlobStore, installation: Uuid, ids: &[Uuid]) -> Result<()> {
    backend.probe().await?;
    let data = (0..1024 * 1024)
        .map(|n| (n % 256) as u8)
        .collect::<Vec<_>>();
    let (first, repeated) = tokio::join!(backend.put(ids[0], &data), backend.put(ids[0], &data));
    let reference = first?;
    assert_eq!(reference, repeated?);
    assert_eq!(
        backend.put(ids[0], b"different").await.unwrap_err().code,
        ErrorCode::Conflict
    );
    assert_eq!(store(installation)?.read(&reference).await?, data);
    let stranger = store(Uuid::new_v4())?;
    assert_eq!(
        stranger.read(&reference).await.unwrap_err().code,
        ErrorCode::NotFound
    );
    stranger.delete(ids[0]).await?;
    assert_eq!(backend.read(&reference).await?, data);
    let mut wrong = reference.clone();
    wrong.sha256 = "0".repeat(64);
    assert_eq!(
        backend.read(&wrong).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    let empty = backend.put(ids[1], b"").await?;
    assert!(backend.read(&empty).await?.is_empty());
    backend.delete(ids[0]).await?;
    backend.delete(ids[0]).await?;
    assert_eq!(
        backend.read(&reference).await.unwrap_err().code,
        ErrorCode::NotFound
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let installation = std::env::var("GOLDENHOOP_ARTIFACT_INSTALLATION")?.parse()?;
    let backend = store(installation)?;
    let ids = [Uuid::new_v4(), Uuid::new_v4()];
    let result = std::panic::AssertUnwindSafe(exercise(&backend, installation, &ids))
        .catch_unwind()
        .await;
    let mut cleanup_error = None;
    for id in ids {
        if let Err(error) = backend.delete(id).await {
            cleanup_error = cleanup_error.or(Some(error));
        }
    }
    if let Some(error) = cleanup_error {
        return Err(error.into());
    }
    match result {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    println!(
        "{}",
        serde_json::json!({"suite":"artifact-s3-contract","result":"passed","cleanup":"complete",
        "installation_id":installation,"cases":["actual_probe","binary_put_and_integrity_read","concurrent_same_id","different_content_refusal",
        "client_reconnect","installation_prefix_isolation","incorrect_digest_refusal","empty_blob","confirmed_repeat_delete"]})
    );
    Ok(())
}
