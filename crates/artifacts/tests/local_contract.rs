use goldenhoop_artifacts::{BlobStore, MAX_BLOB_BYTES, S3Config};
use goldenhoop_protocol::ErrorCode;
use uuid::Uuid;

#[tokio::test]
async fn local_restart_races_integrity_isolation_and_confirmed_deletion() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_owned();
    let root = path.join("objects");
    let installation = Uuid::new_v4();
    let store = BlobStore::local(&root, installation).unwrap();
    store.probe().await.unwrap();
    let id = Uuid::new_v4();
    let data = b"\x00\xff\x80GoldenHoop\n";
    let (first, second) = tokio::join!(store.put(id, data), store.put(id, data));
    let reference = first.unwrap();
    assert_eq!(reference, second.unwrap());
    assert_eq!(
        store.put(id, b"different").await.unwrap_err().code,
        ErrorCode::Conflict
    );
    drop(store);
    let reopened = BlobStore::local(&root, installation).unwrap();
    assert_eq!(reopened.read(&reference).await.unwrap(), data);
    let stranger = BlobStore::local(&root, Uuid::new_v4()).unwrap();
    assert_eq!(
        stranger.read(&reference).await.unwrap_err().code,
        ErrorCode::NotFound
    );
    stranger.delete(id).await.unwrap();
    assert_eq!(reopened.read(&reference).await.unwrap(), data);
    // An unexpected host-side mutation must never become trusted artifact bytes.
    let object = root
        .join("goldenhoop")
        .join(installation.to_string())
        .join(id.to_string());
    let changed = vec![b'x'; data.len()];
    std::fs::write(&object, &changed).unwrap();
    assert_eq!(
        reopened.read(&reference).await.unwrap_err().code,
        ErrorCode::Conflict
    );
    reopened.delete(id).await.unwrap();
    reopened.delete(id).await.unwrap();
    assert!(!object.exists());
    assert_eq!(
        reopened.read(&reference).await.unwrap_err().code,
        ErrorCode::NotFound
    );
    let empty = reopened.put(Uuid::new_v4(), b"").await.unwrap();
    assert!(reopened.read(&empty).await.unwrap().is_empty());
    reopened.delete(empty.id).await.unwrap();
    assert!(std::fs::read_dir(&root).unwrap().next().is_none());
    drop(stranger);
    drop(reopened);
    directory.close().unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn oversized_invalid_and_nil_references_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_owned();
    let store = BlobStore::local(&path.join("objects"), Uuid::new_v4()).unwrap();
    assert_eq!(
        store.put(Uuid::nil(), b"").await.unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        store
            .put(Uuid::new_v4(), &vec![0; MAX_BLOB_BYTES + 1])
            .await
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    drop(store);
    directory.close().unwrap();
    assert!(!path.exists());
}

#[test]
fn s3_refuses_remote_plaintext_and_credentials_in_urls() {
    for endpoint in [
        "http://example.com",
        "https://user:password@example.com",
        "https://example.com?token=secret",
    ] {
        let config = S3Config {
            endpoint: endpoint.into(),
            bucket: "goldenhoop-test".into(),
            region: "us-east-1".into(),
            access_key_id: "test-key".into(),
            secret_access_key: "test-secret".into(),
            session_token: None,
        };
        assert!(BlobStore::s3(config, Uuid::new_v4()).is_err());
    }
}

#[cfg(unix)]
#[test]
fn local_root_rejects_public_permissions_and_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().to_owned();
    let root = path.join("objects");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(BlobStore::local(&root, Uuid::new_v4()).is_err());
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = path.join("link");
    symlink(&root, &link).unwrap();
    assert!(BlobStore::local(&link, Uuid::new_v4()).is_err());
    directory.close().unwrap();
    assert!(!path.exists());
}
