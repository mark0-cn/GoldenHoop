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
async fn large_collection_does_not_accept_delete_ack_when_head_still_finds_the_object() {
    use axum::{
        http::{Method, Uri, header},
        response::IntoResponse,
    };
    let deletes = Arc::new(AtomicUsize::new(0));
    let heads = Arc::new(AtomicUsize::new(0));
    let deleted = deletes.clone();
    let observed = heads.clone();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let trace = seen.clone();
    // Protocol fault injection only. Listing reports an empty upload scope,
    // DELETE acknowledges, but a real subsequent HEAD observes an object.
    let router=Router::new().fallback(any(move |method:Method,uri:Uri,body:axum::body::Bytes|{
        let deleted=deleted.clone();let observed=observed.clone();let trace=trace.clone();
        async move {
            trace.lock().unwrap().push(format!("{method} {uri}"));
            if method==Method::GET && uri.query().is_some_and(|query|query.contains("list-type=2")) {
                (StatusCode::OK,[(header::CONTENT_TYPE,"application/xml")],
                    "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><IsTruncated>false</IsTruncated></ListBucketResult>").into_response()
            }else if method==Method::GET {
                (StatusCode::NOT_FOUND,[(header::CONTENT_TYPE,"application/xml")],"<Error><Code>NoSuchKey</Code></Error>").into_response()
            }else if method==Method::POST && uri.query()==Some("delete") {
                deleted.fetch_add(1,Ordering::SeqCst);
                let text=std::str::from_utf8(&body).unwrap();
                let key=text.split("<Key>").nth(1).unwrap().split("</Key>").next().unwrap();
                (StatusCode::OK,[(header::CONTENT_TYPE,"application/xml")],format!("<DeleteResult><Deleted><Key>{key}</Key></Deleted></DeleteResult>")).into_response()
            }else if method==Method::HEAD {
                observed.fetch_add(1,Ordering::SeqCst);
                (StatusCode::OK,[(header::CONTENT_LENGTH,"0"),(header::LAST_MODIFIED,"Thu, 01 Jan 1970 00:00:00 GMT"),(header::ETAG,"\"fixture\"")]).into_response()
            }else {StatusCode::METHOD_NOT_ALLOWED.into_response()}
        }
    }));
    let (endpoint, _server) = server(router).await;
    let backend = store(endpoint);
    let reference = backend
        .large_reference(Uuid::new_v4(), "0".repeat(64), 0)
        .unwrap();
    let error = backend.collect_large(&reference).await.unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable);
    assert!(!error.retryable);
    assert_eq!(
        deletes.load(Ordering::SeqCst),
        1,
        "{:?}",
        seen.lock().unwrap()
    );
    assert_eq!(heads.load(Ordering::SeqCst), 1);
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
