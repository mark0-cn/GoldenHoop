//! Actual guest and upstream TLS with synthetic packet authority.
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::FutureExt;
use goldenhoop_credentials::*;
use goldenhoop_protocol::{ApiError, ErrorCode};
use http_body_util::{BodyExt, Full};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio_rustls::rustls::{
    self,
    pki_types::{ServerName, pem::PemObject},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

struct Authority {
    binding: CredentialBinding,
    current: AtomicBool,
    completed: AtomicU64,
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
        if self.current.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ApiError::new(ErrorCode::Forbidden, "fixture revoked"))
        }
    }
    async fn resolve(&self, _: &CredentialGrant) -> Result<Secret, ApiError> {
        Ok(Secret(Zeroizing::new(
            "fixture-tls-provider-private-value".into(),
        )))
    }
    async fn record(
        &self,
        _: &CredentialGrant,
        outcome: CredentialOutcome,
    ) -> Result<(), ApiError> {
        if outcome == CredentialOutcome::BodyCompleted {
            self.completed.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

async fn upstream() -> (
    std::net::SocketAddr,
    Arc<CertificateAuthority>,
    Arc<AtomicU64>,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    let ca =
        Arc::new(CertificateAuthority::open(CertificateAuthority::generate().unwrap()).unwrap());
    let config = ca.server_config("service.example.test").unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicU64::new(0));
    let task_calls = calls.clone();
    let stop = CancellationToken::new();
    let task_stop = stop.clone();
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _=task_stop.cancelled()=>break,
                Some(_)=tasks.join_next()=>{},
                accepted=listener.accept()=>{
                    let (stream,_)=accepted.unwrap();let acceptor=tokio_rustls::TlsAcceptor::from(config.clone());let calls=task_calls.clone();
                    tasks.spawn(async move {
                        let Ok(Ok(stream))=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(stream)).await else{return};
                        let service=hyper::service::service_fn(move |request:hyper::Request<hyper::body::Incoming>| {
                            let calls=calls.clone();async move {
                                calls.fetch_add(1,Ordering::SeqCst);
                                assert_eq!(request.headers()["authorization"],"Bearer fixture-tls-provider-private-value");
                                let mut response=hyper::Response::new(Full::new(if request.uri().path()=="/v1/empty" || request.uri().path()=="/v1/no-content" {Bytes::new()} else {Bytes::from_static(b"approved-upstream-nonce")}));
                                if request.uri().path()=="/v1/no-content" {*response.status_mut()=hyper::StatusCode::NO_CONTENT;}
                                Ok::<_,std::convert::Infallible>(response)
                            }
                        });
                        let _=Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(stream),service).await;
                    });
                },
            }
        }
        tasks.shutdown().await;
    });
    (address, ca, calls, stop, task)
}

type TestError = Box<dyn std::error::Error + Send + Sync>;
async fn guest(
    address: std::net::SocketAddr,
    original_port: u16,
    ca: &CertificateAuthority,
    h2: bool,
    host: &str,
    method: &str,
    path: &str,
) -> Result<(u16, Vec<u8>), TestError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(ca.public_pem().as_bytes()) {
        roots.add(cert?)?;
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![if h2 {
        b"h2".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = connector
        .connect(
            ServerName::try_from("service.example.test".to_owned())?,
            tokio::net::TcpStream::connect(address).await?,
        )
        .await?;
    let io = TokioIo::new(stream);
    let request = hyper::Request::builder()
        .method(method)
        .uri(if h2 {
            format!("https://{host}:{original_port}{path}")
        } else {
            path.into()
        })
        .header("host", format!("{host}:{original_port}"))
        .body(Full::new(Bytes::new()))?;
    if h2 {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
        let task = tokio::spawn(connection);
        let result = async {
            let response = sender.send_request(request).await?;
            let status = response.status().as_u16();
            let body = response.into_body().collect().await?;
            Ok::<_, TestError>((status, body.to_bytes().to_vec()))
        }
        .await;
        drop(sender);
        task.abort();
        let _ = task.await;
        result
    } else {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
        let task = tokio::spawn(connection);
        let result = async {
            let response = sender.send_request(request).await?;
            let status = response.status().as_u16();
            let body = response.into_body().collect().await?;
            Ok::<_, TestError>((status, body.to_bytes().to_vec()))
        }
        .await;
        drop(sender);
        task.abort();
        let _ = task.await;
        result
    }
}

#[tokio::test]
async fn real_tls_h1_h2_upstream_verification_and_host_sni_mismatch() {
    let (original, upstream_ca, calls, upstream_stop, upstream_task) = upstream().await;
    let id = Uuid::new_v4();
    let sandbox_id = Uuid::new_v4();
    let authority = Arc::new(Authority {
        binding: CredentialBinding {
            id,
            sandbox_id,
            revision: 1,
            applied_revision: Some(1),
            state: CredentialState::Active,
            binding: BindingSpec {
                scheme: Scheme::Https,
                host: "service.example.test".into(),
                port: original.port(),
                methods: ["POST".into(), "HEAD".into()].into(),
                path_prefix: "/v1/".into(),
                injection: Injection::Bearer,
                substitutions: Vec::new(),
            },
        },
        current: AtomicBool::new(true),
        completed: AtomicU64::new(0),
    });
    let untrusted_broker = Broker::new(authority.clone());
    let broker = Broker::new(authority.clone()).with_extra_trust(
        reqwest::Certificate::from_pem(upstream_ca.public_pem().as_bytes()).unwrap(),
    );
    let ca =
        Arc::new(CertificateAuthority::open(CertificateAuthority::generate().unwrap()).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let task_stop = stop.clone();
    let task_ca = ca.clone();
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _=task_stop.cancelled()=>break,
                Some(_)=tasks.join_next()=>{},
                accepted=listener.accept()=>{
                    let (stream,_)=accepted.unwrap();let broker=broker.clone();let ca=task_ca.clone();let stop=task_stop.clone();
                    tasks.spawn(async move{let _=frontend::serve_connection(stream,broker,ca,frontend::ConnectionIdentity{sandbox_id,original,tls:true},stop).await;});
                },
            }
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    });
    let result = std::panic::AssertUnwindSafe(async {
        tokio::time::timeout(Duration::from_secs(15), async {
            let input = BoundRequest {
                identity: RequestIdentity {
                    sandbox_id,
                    scheme: Scheme::Https,
                    host: "service.example.test".into(),
                    port: original.port(),
                    destination: original.ip(),
                    tls_server_name: Some("service.example.test".into()),
                    method: reqwest::Method::POST,
                    path_and_query: "/v1/tls".into(),
                },
                headers: reqwest::header::HeaderMap::new(),
                body: Box::pin(futures_util::stream::empty()),
            };
            let denied = untrusted_broker.forward(input).await;
            assert!(matches!(
                denied,
                Err(ApiError {
                    retryable: false,
                    ..
                })
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            let cases = [false, true].into_iter().flat_map(|h2| {
                [
                    (
                        "POST",
                        "/v1/tls",
                        200,
                        b"approved-upstream-nonce".as_slice(),
                    ),
                    ("POST", "/v1/empty", 200, b"".as_slice()),
                    ("POST", "/v1/no-content", 204, b"".as_slice()),
                    ("HEAD", "/v1/tls", 200, b"".as_slice()),
                ]
                .into_iter()
                .map(move |case| (h2, case))
            });
            for (index, (h2, (method, path, expected_status, expected_body))) in cases.enumerate() {
                let (status, body) = guest(
                    address,
                    original.port(),
                    &ca,
                    h2,
                    "service.example.test",
                    method,
                    path,
                )
                .await
                .unwrap();
                assert_eq!(status, expected_status);
                assert_eq!(body, expected_body);
                tokio::time::timeout(Duration::from_secs(1), async {
                    while authority.completed.load(Ordering::SeqCst) != index as u64 + 1 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .unwrap_or_else(|_| {
                    panic!("a fully consumed {method} {path} (h2={h2}) needs its completion audit")
                });
            }
            assert_eq!(calls.load(Ordering::SeqCst), 8);
            let (status, _) = guest(
                address,
                original.port(),
                &ca,
                true,
                "attacker.example.test",
                "POST",
                "/v1/tls",
            )
            .await
            .unwrap();
            assert_eq!(status, 403);
            assert_eq!(calls.load(Ordering::SeqCst), 8);
            let wrong_ca =
                CertificateAuthority::open(CertificateAuthority::generate().unwrap()).unwrap();
            assert!(
                guest(
                    address,
                    original.port(),
                    &wrong_ca,
                    false,
                    "service.example.test",
                    "POST",
                    "/v1/tls"
                )
                .await
                .is_err()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 8);
        })
        .await
        .unwrap();
    })
    .catch_unwind()
    .await;
    stop.cancel();
    upstream_stop.cancel();
    tokio::time::timeout(Duration::from_secs(14), task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), upstream_task)
        .await
        .unwrap()
        .unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[test]
fn ca_restore_refuses_mismatched_keys_and_non_ca_certificates() {
    let first = CertificateAuthority::generate().unwrap();
    let other = CertificateAuthority::generate().unwrap();
    assert!(
        CertificateAuthority::open(CaMaterial {
            certificate_pem: first.certificate_pem,
            signing_key: other.signing_key
        })
        .is_err()
    );
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["service.example.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    assert!(
        CertificateAuthority::open(CaMaterial {
            certificate_pem: certificate.pem(),
            signing_key: Secret(Zeroizing::new(key.serialize_pem()))
        })
        .is_err()
    );
}
