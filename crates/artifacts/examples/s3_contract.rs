//! Only a fresh test bucket/installation; the outer harness owns its backend.
use futures_util::FutureExt;
use goldenhoop_artifacts::{BlobStore, LargeBlobRef, S3Config};
use goldenhoop_protocol::ErrorCode;
use sha2::{Digest, Sha256};
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

async fn exercise(
    backend: &BlobStore,
    installation: Uuid,
    ids: &[Uuid],
    large: &[LargeBlobRef],
    large_data: &[u8],
) -> Result<()> {
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
    let (first, repeated) = tokio::join!(
        backend.put_large(&large[0], large_data),
        backend.put_large(&large[0], large_data)
    );
    first?;
    repeated?;
    backend.put_large(&large[1], large_data).await?;
    let reopened = store(installation)?;
    let mut output = Vec::new();
    reopened.download_large(&large[0], &mut output).await?;
    assert_eq!(output, large_data);
    let mut wrong = large[0].clone();
    wrong.sha256 = "0".repeat(64);
    assert_eq!(
        backend
            .download_large(&wrong, tokio::io::sink())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        stranger.collect_large(&large[0]).await.unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    backend.collect_large(&large[0]).await?;
    backend.collect_large(&large[0]).await?;
    reopened
        .download_large(&large[1], tokio::io::sink())
        .await?;
    assert_eq!(
        backend
            .put_large(&large[2], &large_data[..large_data.len() - 1])
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        backend
            .download_large(&large[2], tokio::io::sink())
            .await
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    reopened.put_large(&large[2], large_data).await?;
    reopened
        .download_large(&large[2], tokio::io::sink())
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let installation = std::env::var("GOLDENHOOP_ARTIFACT_INSTALLATION")?.parse()?;
    let backend = store(installation)?;
    let ids = [Uuid::new_v4(), Uuid::new_v4()];
    let large_data = (0..17 * 1024 * 1024 + 13)
        .map(|n| (n % 251) as u8)
        .collect::<Vec<_>>();
    let digest = format!("{:x}", Sha256::digest(&large_data));
    let object = Uuid::new_v4();
    let large = (0..3)
        .map(|_| backend.large_reference(object, digest.clone(), large_data.len() as u64))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let result =
        std::panic::AssertUnwindSafe(exercise(&backend, installation, &ids, &large, &large_data))
            .catch_unwind()
            .await;
    let mut cleanup_error = None;
    for reference in &large {
        if let Err(error) = backend.collect_large(reference).await {
            cleanup_error = cleanup_error.or(Some(error));
        }
    }
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
        "client_reconnect","installation_prefix_isolation","incorrect_digest_refusal","empty_blob","confirmed_repeat_delete",
        "large_stream_over_16mib","large_conditional_concurrent_same_generation","large_client_reconnect","large_wrong_manifest_refusal",
        "large_foreign_installation_refusal","large_independent_generations","large_interrupted_upload_unpublished",
        "large_same_generation_resume","large_confirmed_scoped_collection"]})
    );
    Ok(())
}
