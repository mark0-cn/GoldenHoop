use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{Router, http::StatusCode, routing::any};
use goldenhoop_artifacts::{BlobRef, BlobStore, S3Config};
use goldenhoop_protocol::ErrorCode;
use uuid::Uuid;

struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn server(router: Router) -> (String, Server) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (endpoint, Server(task))
}
fn store(endpoint: String) -> BlobStore {
    BlobStore::s3(
        S3Config {
            endpoint,
            bucket: "goldenhoop-test".into(),
            region: "us-east-1".into(),
            access_key_id: "test-access".into(),
            secret_access_key: "test-secret".into(),
            session_token: None,
        },
        Uuid::new_v4(),
    )
    .unwrap()
}

#[tokio::test]
async fn deletion_acknowledgement_without_confirmed_absence_is_not_success() {
    // Protocol fault injection, not an S3 backend compatibility test.
    let router = Router::new().fallback(any(|method: axum::http::Method| async move {
        if method == axum::http::Method::DELETE {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::FORBIDDEN
        }
    }));
    let (endpoint, _server) = server(router).await;
    assert_eq!(
        store(endpoint)
            .delete(Uuid::new_v4())
            .await
            .unwrap_err()
            .code,
        ErrorCode::BackendUnavailable
    );
}

#[tokio::test]
async fn signed_storage_requests_do_not_follow_redirects() {
    let forwarded = Arc::new(AtomicUsize::new(0));
    let counter = forwarded.clone();
    let target = Router::new().fallback(any(move || {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            StatusCode::OK
        }
    }));
    let (destination, _target) = server(target).await;
    let source = Router::new().fallback(any(move || {
        let destination = destination.clone();
        async move { (StatusCode::TEMPORARY_REDIRECT, [("location", destination)]) }
    }));
    let (endpoint, _source) = server(source).await;
    let reference = BlobRef {
        id: Uuid::new_v4(),
        sha256: "0".repeat(64),
        size_bytes: 0,
    };
    let result = store(endpoint).read(&reference).await;
    assert!(result.is_err());
    assert_eq!(forwarded.load(Ordering::SeqCst), 0);
}
