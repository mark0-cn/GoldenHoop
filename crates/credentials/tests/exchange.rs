use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
    routing::any,
};
use futures_util::FutureExt;
use goldenhoop_credentials::*;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use uuid::Uuid;
use zeroize::Zeroizing;

#[tokio::test]
async fn actual_operator_exchange_is_named_authenticated_and_never_follows_redirects() {
    let hits = Arc::new(AtomicU64::new(0));
    let leaks = Arc::new(AtomicU64::new(0));
    let receiver_hits = hits.clone();
    let receiver_leaks = leaks.clone();
    let sandbox = Uuid::new_v4();
    let binding = Uuid::new_v4();
    let app = Router::new().fallback(any(move |request: Request<Body>| {
        let hits = receiver_hits.clone();
        let leaks = receiver_leaks.clone();
        async move {
            if request.uri().path() == "/leak" {
                leaks.fetch_add(1, Ordering::SeqCst);
                return axum::http::Response::new(Body::empty());
            }
            hits.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                request.headers()["authorization"],
                "Bearer private-resolver-test-key"
            );
            if request.uri().path() == "/redirect" {
                return axum::http::Response::builder()
                    .status(307)
                    .header("location", "/leak")
                    .body(Body::empty())
                    .unwrap();
            }
            let body = to_bytes(request.into_body(), 65536).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["sandbox_id"], sandbox.to_string());
            assert_eq!(value["binding_id"], binding.to_string());
            assert_eq!(value["binding_revision"], 7);
            axum::http::Response::builder()
                .header("content-type", "application/json")
                .body(Body::from("{\"value\":\"private-issued-test-value\"}"))
                .unwrap()
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, done) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = done.await;
            })
            .await
            .unwrap();
    });
    let result = std::panic::AssertUnwindSafe(async {
        let metadata = CredentialBinding {
            id: binding,
            sandbox_id: sandbox,
            revision: 7,
            applied_revision: Some(7),
            state: CredentialState::Active,
            binding: BindingSpec {
                scheme: Scheme::Https,
                host: "service.example.test".into(),
                port: 443,
                methods: ["POST".into()].into(),
                path_prefix: "/".into(),
                injection: Injection::Bearer,
                substitutions: Vec::new(),
            },
        };
        let providers = [("good", "exchange"), ("redirect", "redirect")]
            .into_iter()
            .map(|(name, path)| {
                (
                    name.to_owned(),
                    ExchangeProvider {
                        endpoint: format!("http://{address}/{path}"),
                        headers: BTreeMap::from([(
                            "authorization".into(),
                            Secret(Zeroizing::new("Bearer private-resolver-test-key".into())),
                        )]),
                    },
                )
            })
            .collect();
        let registry = ExchangeRegistry::new(providers).unwrap();
        let value = registry.exchange("good", &metadata).await.unwrap();
        assert_eq!(value.0.as_str(), "private-issued-test-value");
        assert!(registry.exchange("redirect", &metadata).await.is_err());
        assert!(registry.exchange("unknown", &metadata).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(leaks.load(Ordering::SeqCst), 0);
        let invalid = BTreeMap::from([(
            "bad".into(),
            ExchangeProvider {
                endpoint: "http://remote.example.test/exchange".into(),
                headers: BTreeMap::new(),
            },
        )]);
        assert!(ExchangeRegistry::new(invalid).is_err());
    })
    .catch_unwind()
    .await;
    let _ = stop.send(());
    tokio::time::timeout(std::time::Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
