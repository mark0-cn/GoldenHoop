//! Actual HTTP receiver checks transformations; packet identity is synthetic.
use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
    routing::any,
};
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt};
use goldenhoop_credentials::*;
use goldenhoop_protocol::ApiError;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

struct Authority {
    binding: CredentialBinding,
}
#[async_trait]
impl CredentialAuthority for Authority {
    async fn admit(&self, _: &RequestIdentity) -> Result<CredentialGrant, ApiError> {
        Ok(CredentialGrant {
            binding: self.binding.clone(),
            policy_revision: 1,
            epoch: self.binding.id,
            request_id: Uuid::new_v4(),
            packet: None,
        })
    }
    async fn current(&self, _: &CredentialGrant) -> Result<(), ApiError> {
        Ok(())
    }
    async fn resolve(&self, _: &CredentialGrant) -> Result<Secret, ApiError> {
        Ok(Secret(Zeroizing::new("private-AB/foo".into())))
    }
    async fn record(&self, _: &CredentialGrant, _: CredentialOutcome) -> Result<(), ApiError> {
        Ok(())
    }
}

#[tokio::test]
async fn placeholders_basic_and_custom_headers_reach_only_the_bound_receiver_and_reflections_are_removed()
 {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let app = Router::new().fallback(any(|request: Request<Body>| async move {
        let (parts, body) = request.into_parts();
        let body = to_bytes(body, 2 * 1024 * 1024).await.unwrap();
        if parts.uri.path().starts_with("/v1/") {
            assert_eq!(parts.uri.path(), "/v1/private-AB%2Ffoo");
            assert_eq!(parts.uri.query(), Some("q=private-AB%2Ffoo"));
            assert_eq!(parts.headers["x-api-placeholder"], "private-AB/foo");
            assert_eq!(body, b"{\"token\":\"private-AB/foo\"}".as_slice());
        } else if parts.uri.path() == "/large" {
            assert_eq!(parts.headers["x-api-placeholder"], "private-AB/foo");
            assert!(body.len() > 1024 * 1024);
            assert!(body.starts_with(b"TOKEN"));
            assert!(body.ends_with(b"TOKEN"));
        } else if let Some(auth) = parts.headers.get("authorization") {
            let raw = auth.to_str().unwrap();
            if let Some(value) = raw.strip_prefix("Basic ") {
                assert_eq!(STANDARD.decode(value).unwrap(), b"user:private-AB/foo");
            } else {
                assert_eq!(raw, "Bearer private-AB/foo");
            }
        } else {
            assert_eq!(parts.headers["x-api-key"], "private-AB/foo");
        }
        let bare_basic = STANDARD.encode("user:private-AB/foo");
        axum::http::Response::builder()
            .header("location", "/v1/private-AB%2ffoo")
            .header("x-reflected-basic", bare_basic)
            .body(Body::from("upstream-nonce"))
            .unwrap()
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
    let result = std::panic::AssertUnwindSafe(async {
        for (index, injection) in [
            Injection::Bearer,
            Injection::Basic {
                username: "user".into(),
            },
            Injection::Header {
                name: "x-api-key".into(),
            },
            Injection::Placeholders,
            Injection::Placeholders,
        ]
        .into_iter()
        .enumerate()
        {
            let substitutions = if index >= 3 {
                vec![
                    Substitution {
                        placeholder: "TOKEN".into(),
                        at: SubstituteAt::Path,
                    },
                    Substitution {
                        placeholder: "TOKEN".into(),
                        at: SubstituteAt::Query { name: "q".into() },
                    },
                    Substitution {
                        placeholder: "TOKEN".into(),
                        at: SubstituteAt::Header {
                            name: "x-api-placeholder".into(),
                        },
                    },
                    Substitution {
                        placeholder: "TOKEN".into(),
                        at: SubstituteAt::Body,
                    },
                ]
            } else {
                Vec::new()
            };
            let sandbox_id = Uuid::new_v4();
            let id = Uuid::new_v4();
            let binding = CredentialBinding {
                id,
                sandbox_id,
                revision: 1,
                applied_revision: Some(1),
                state: CredentialState::Active,
                binding: BindingSpec {
                    scheme: Scheme::Http,
                    host: "service.example.test".into(),
                    port: address.port(),
                    methods: ["POST".into()].into(),
                    path_prefix: "/".into(),
                    injection,
                    substitutions,
                },
            };
            let broker = Broker::new(Arc::new(Authority { binding }));
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert("x-api-placeholder", "TOKEN".parse().unwrap());
            let path = if index == 3 {
                "/v1/TOKEN?q=TOKEN"
            } else if index == 4 {
                "/large"
            } else {
                "/modes"
            };
            let data = if index == 4 {
                let mut v = b"TOKEN".to_vec();
                v.extend(vec![b'x'; 1024 * 1024]);
                v.extend_from_slice(b"TOKEN");
                v
            } else {
                b"{\"token\":\"TOKEN\"}".to_vec()
            };
            let request = BoundRequest {
                identity: RequestIdentity {
                    sandbox_id,
                    scheme: Scheme::Http,
                    host: "service.example.test".into(),
                    port: address.port(),
                    destination: address.ip(),
                    tls_server_name: None,
                    method: reqwest::Method::POST,
                    path_and_query: path.into(),
                },
                headers,
                body: Box::pin(futures_util::stream::once(
                    async move { Ok(Bytes::from(data)) },
                )),
            };
            let response = broker.forward(request).await.unwrap();
            assert_eq!(response.status, 200);
            assert!(!response.headers.contains_key("location"));
            if index == 1 {
                assert!(!response.headers.contains_key("x-reflected-basic"));
            }
            let chunks = response.body.collect::<Vec<_>>().await;
            assert!(chunks.iter().all(Result::is_ok));
            assert_eq!(
                chunks
                    .into_iter()
                    .flat_map(|v| v.unwrap().to_vec())
                    .collect::<Vec<_>>(),
                b"upstream-nonce"
            );
        }
    })
    .catch_unwind()
    .await;
    let _ = stop.send(());
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
