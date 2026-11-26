//! Actual loopback HTTP forwarding; policy identity is a synthetic authority.
//! Transparent interception and native source enforcement have separate gates.
use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::any,
};
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt};
use goldenhoop_credentials::*;
use goldenhoop_protocol::{ApiError, ErrorCode};
use reqwest::Method;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use uuid::Uuid;
use zeroize::Zeroizing;

struct Authority {
    binding: CredentialBinding,
    current: AtomicBool,
    resolutions: AtomicU64,
    delay: AtomicBool,
    started: Notify,
    release: Notify,
}
#[async_trait]
impl CredentialAuthority for Authority {
    async fn admit(&self, _: &RequestIdentity) -> Result<CredentialGrant, ApiError> {
        Ok(CredentialGrant {
            binding: self.binding.clone(),
            policy_revision: 1,
            epoch: self.binding.id,
        })
    }
    async fn current(&self, _: &CredentialGrant) -> Result<(), ApiError> {
        if self.current.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ApiError::new(
                ErrorCode::Forbidden,
                "test authority revoked",
            ))
        }
    }
    async fn resolve(&self, _: &CredentialGrant) -> Result<Secret, ApiError> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        if self.delay.load(Ordering::SeqCst) {
            self.release.notified().await;
        }
        Ok(Secret(Zeroizing::new(
            "fixture-provider-private-value".into(),
        )))
    }
    async fn record(&self, _: &CredentialGrant, _: CredentialOutcome) -> Result<(), ApiError> {
        Ok(())
    }
}

async fn fixture() -> (
    std::net::SocketAddr,
    Arc<AtomicU64>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let calls = Arc::new(AtomicU64::new(0));
    let counter = calls.clone();
    let app=Router::new().fallback(any(move |headers:HeaderMap,uri:axum::http::Uri| {
        let counter=counter.clone();async move {
            counter.fetch_add(1,Ordering::SeqCst);
            assert_eq!(headers.get("authorization").unwrap(),"Bearer fixture-provider-private-value");
            if uri.path()=="/v1/redirect" {
                Response::builder().status(StatusCode::TEMPORARY_REDIRECT).header("location","http://attacker.invalid/steal").header("x-reflected-secret","fixture-provider-private-value").body(Body::empty()).unwrap()
            } else {
                let stream=async_stream::stream! {yield Ok::<Bytes,std::io::Error>(Bytes::from_static(b"event: accepted\n\n"));std::future::pending::<()>().await;};
                Response::builder().header("content-type","text/event-stream").body(Body::from_stream(stream)).unwrap()
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, done) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = done.await;
            })
            .await
            .unwrap();
    });
    (address, calls, stop, task)
}
fn authority(port: u16) -> Arc<Authority> {
    let id = Uuid::new_v4();
    let sandbox = Uuid::new_v4();
    Arc::new(Authority {
        binding: CredentialBinding {
            id,
            sandbox_id: sandbox,
            revision: 1,
            applied_revision: Some(1),
            state: CredentialState::Active,
            binding: BindingSpec {
                scheme: Scheme::Http,
                host: "service.example.test".into(),
                port,
                methods: ["POST".into()].into(),
                path_prefix: "/v1/".into(),
                injection: Injection::Bearer,
            },
        },
        current: AtomicBool::new(true),
        resolutions: AtomicU64::new(0),
        delay: AtomicBool::new(false),
        started: Notify::new(),
        release: Notify::new(),
    })
}
fn request(authority: &Authority, path: &str) -> BoundRequest {
    BoundRequest {
        identity: RequestIdentity {
            sandbox_id: authority.binding.sandbox_id,
            scheme: Scheme::Http,
            host: "service.example.test".into(),
            port: authority.binding.binding.port,
            destination: "127.0.0.1".parse().unwrap(),
            tls_server_name: None,
            method: Method::POST,
            path_and_query: path.into(),
        },
        headers: HeaderMap::new(),
        body: Box::pin(futures_util::stream::empty()),
    }
}

#[tokio::test]
async fn actual_upstream_gets_injection_redirect_is_not_followed_and_response_headers_are_redacted()
{
    let (address, calls, stop, task) = fixture().await;
    let authority = authority(address.port());
    let broker = Broker::new(authority.clone());
    let result = std::panic::AssertUnwindSafe(async {
        let response = broker
            .forward(request(&authority, "/v1/redirect"))
            .await
            .unwrap();
        assert_eq!(response.status, StatusCode::TEMPORARY_REDIRECT);
        assert!(!response.headers.contains_key("x-reflected-secret"));
        assert_eq!(
            response.headers.get("location").unwrap(),
            "http://attacker.invalid/steal"
        );
        let bytes = response.body.collect::<Vec<_>>().await;
        assert!(bytes.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    })
    .catch_unwind()
    .await;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn delayed_exchange_cannot_restore_revoked_authority_and_no_upstream_delivery_occurs() {
    let (address, calls, stop, task) = fixture().await;
    let authority = authority(address.port());
    authority.delay.store(true, Ordering::SeqCst);
    let broker = Broker::new(authority.clone());
    let input = request(&authority, "/v1/stream");
    let forwarding = tokio::spawn(async move { broker.forward(input).await });
    authority.started.notified().await;
    authority.current.store(false, Ordering::SeqCst);
    authority.release.notify_one();
    let result = forwarding.await.unwrap();
    assert!(matches!(
        result,
        Err(ApiError {
            code: ErrorCode::Forbidden,
            ..
        })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn actual_idle_stream_is_collected_on_revocation_and_origin_confusion_never_resolves_a_secret()
 {
    let (address, calls, stop, task) = fixture().await;
    let authority = authority(address.port());
    let broker = Broker::new(authority.clone());
    let result = std::panic::AssertUnwindSafe(async {
        let mut confused = request(&authority, "/v1/stream");
        confused
            .headers
            .insert("host", "attacker.invalid".parse().unwrap());
        assert!(broker.forward(confused).await.is_err());
        assert_eq!(authority.resolutions.load(Ordering::SeqCst), 0);
        let mut confused = request(&authority, "/v1/stream");
        confused.identity.scheme = Scheme::Https;
        confused.identity.tls_server_name = Some("attacker.invalid".into());
        assert!(broker.forward(confused).await.is_err());
        assert_eq!(authority.resolutions.load(Ordering::SeqCst), 0);
        let mut response = broker
            .forward(request(&authority, "/v1/stream"))
            .await
            .unwrap();
        assert_eq!(
            response.body.next().await.unwrap().unwrap(),
            Bytes::from_static(b"event: accepted\n\n")
        );
        authority.current.store(false, Ordering::SeqCst);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), response.body.next())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    })
    .catch_unwind()
    .await;
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
