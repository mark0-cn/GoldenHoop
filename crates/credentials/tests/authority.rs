//! Generation/authority races, without claiming a native packet witness.
use async_trait::async_trait;
use goldenhoop_credentials::*;
use goldenhoop_protocol::{ApiError, ErrorCode};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use uuid::Uuid;
use zeroize::Zeroizing;

struct Packets {
    deadline: Instant,
    delay: AtomicBool,
    started: Notify,
    release: Notify,
}
#[async_trait]
impl PacketAuthority for Packets {
    async fn admit(&self, request: &RequestIdentity) -> Result<PacketWitness, ApiError> {
        Ok(PacketWitness {
            epoch: Uuid::new_v4(),
            revision: 1,
            destination: SocketAddr::new(request.destination, request.port),
            source_name: Some(request.host.clone()),
            expires_at: self.deadline,
        })
    }
    async fn current(&self, _: &PacketWitness) -> Result<(), ApiError> {
        if self.delay.load(Ordering::SeqCst) {
            self.started.notify_one();
            self.release.notified().await;
        }
        Ok(())
    }
}
struct Sink;
#[async_trait]
impl CredentialAudit for Sink {
    async fn append(&self, _: BrokerAudit) -> Result<(), ApiError> {
        Ok(())
    }
}
fn loaded(sandbox: Uuid, id: Uuid) -> LoadedBinding {
    LoadedBinding {
        metadata: CredentialBinding {
            id,
            sandbox_id: sandbox,
            revision: 1,
            applied_revision: Some(1),
            state: CredentialState::Active,
            binding: BindingSpec {
                scheme: Scheme::Https,
                host: "api.example.test".into(),
                port: 443,
                methods: ["POST".into()].into(),
                path_prefix: "/v1/".into(),
                injection: Injection::Bearer,
                substitutions: Vec::new(),
            },
        },
        source: Arc::new(SecretSource::Literal {
            value: Secret(Zeroizing::new("private-fixture-credential".into())),
        }),
    }
}
fn request(sandbox: Uuid) -> RequestIdentity {
    RequestIdentity {
        sandbox_id: sandbox,
        scheme: Scheme::Https,
        host: "api.example.test".into(),
        port: 443,
        destination: "203.0.113.7".parse().unwrap(),
        tls_server_name: Some("api.example.test".into()),
        method: reqwest::Method::POST,
        path_and_query: "/v1/task".into(),
    }
}
fn packets() -> Arc<Packets> {
    Arc::new(Packets {
        deadline: Instant::now() + Duration::from_secs(60),
        delay: AtomicBool::new(false),
        started: Notify::new(),
        release: Notify::new(),
    })
}

#[tokio::test]
async fn ambiguous_matches_are_denied_and_empty_fence_cannot_retain_authority() {
    let sandbox = Uuid::new_v4();
    let authority =
        SnapshotAuthority::new(sandbox, packets(), Arc::new(NoExchanges), Arc::new(Sink)).unwrap();
    authority
        .replace(vec![
            loaded(sandbox, Uuid::new_v4()),
            loaded(sandbox, Uuid::new_v4()),
        ])
        .await
        .unwrap();
    assert!(matches!(
        authority.admit(&request(sandbox)).await,
        Err(ApiError {
            code: ErrorCode::Forbidden,
            ..
        })
    ));
    authority
        .replace(vec![loaded(sandbox, Uuid::new_v4())])
        .await
        .unwrap();
    let grant = authority.admit(&request(sandbox)).await.unwrap();
    let mut generations = authority.subscribe();
    authority.current(&grant).await.unwrap();
    authority.resolve(&grant).await.unwrap();
    authority.fence().await;
    assert!(generations.has_changed().unwrap());
    generations.borrow_and_update();
    assert!(authority.current(&grant).await.is_err());
    assert!(authority.resolve(&grant).await.is_err());
    assert!(authority.admit(&request(sandbox)).await.is_err());
}

#[tokio::test]
async fn late_packet_check_cannot_resurrect_a_fenced_credential_generation() {
    let sandbox = Uuid::new_v4();
    let packet = packets();
    let authority = Arc::new(
        SnapshotAuthority::new(
            sandbox,
            packet.clone(),
            Arc::new(NoExchanges),
            Arc::new(Sink),
        )
        .unwrap(),
    );
    authority
        .replace(vec![loaded(sandbox, Uuid::new_v4())])
        .await
        .unwrap();
    let grant = authority.admit(&request(sandbox)).await.unwrap();
    packet.delay.store(true, Ordering::SeqCst);
    let checking = authority.clone();
    let task = tokio::spawn(async move { checking.current(&grant).await });
    packet.started.notified().await;
    authority.fence().await;
    packet.release.notify_one();
    assert!(task.await.unwrap().is_err());
}

#[tokio::test]
async fn expired_packet_witness_and_wrong_sandbox_never_acquire_a_secret() {
    let sandbox = Uuid::new_v4();
    let expired = Arc::new(Packets {
        deadline: Instant::now() - Duration::from_secs(1),
        delay: AtomicBool::new(false),
        started: Notify::new(),
        release: Notify::new(),
    });
    let authority =
        SnapshotAuthority::new(sandbox, expired, Arc::new(NoExchanges), Arc::new(Sink)).unwrap();
    authority
        .replace(vec![loaded(sandbox, Uuid::new_v4())])
        .await
        .unwrap();
    assert!(authority.admit(&request(sandbox)).await.is_err());
    assert!(authority.admit(&request(Uuid::new_v4())).await.is_err());
}
