//! Public HTTP/transport authorization over synthetic domain state. Native
//! workload and credential datapath acceptance is a separate stage gate.
use std::{collections::BTreeSet, time::Duration};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chrono::Utc;
use goldenhoop_control::api;
use goldenhoop_protocol::*;
use goldenhoop_store::Store;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const ADMIN: &str = "security-http-bootstrap-token-0123456789abcdef";

async fn call(
    app: &Router,
    token: &str,
    method: &str,
    path: &str,
    value: Option<Value>,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .header("idempotency-key", "security-http-request")
                .body(value.map_or_else(Body::empty, |v| Body::from(v.to_string())))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn source(store: &Store, key: &str) -> Uuid {
    let profile:RuntimeProfile=serde_json::from_value(json!({"id":"fixture","placement":"local","isolation":"gvisor","availability":"available","capabilities":["commands","files","shell_sessions","network_isolation"],"max_resources":{"cpu_millis":16000,"memory_bytes":17179869184_u64,"pids":4096},"max_ttl_seconds":86400})).unwrap();
    let created = store
        .create_sandbox(&profile, &CreateSandbox::new("fixture", "fixture"), key)
        .await
        .unwrap();
    let id = created.sandbox.id;
    let mut stored = store.sandbox(id).await.unwrap();
    stored.sandbox.state = SandboxState::Starting;
    store.observe(stored.clone()).await.unwrap();
    stored.sandbox.state = SandboxState::Running;
    store.observe(stored).await.unwrap();
    id
}

async fn issue(
    store: &Store,
    resources: KeyResources,
    permissions: impl IntoIterator<Item = KeyPermission>,
) -> ApiKeyIssued {
    store
        .issue_api_key(
            &CreateApiKey {
                resources,
                permissions: permissions.into_iter().collect(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn grants_cover_resource_ownership_collections_mutations_and_key_management() {
    let store = Store::memory().await.unwrap();
    let left = source(&store, "left").await;
    let right = source(&store, "right").await;
    let command = store
        .create_execution(left, &CommandSpec::new(["true"]), "command")
        .await
        .unwrap();
    let other = store
        .create_execution(right, &CommandSpec::new(["true"]), "command")
        .await
        .unwrap();
    let issued = issue(
        &store,
        KeyResources::Sandboxes(BTreeSet::from([left])),
        [KeyPermission::Read],
    )
    .await;
    let app = api::router(store.clone(), ADMIN).unwrap();
    for (method, path, status) in [
        ("GET", format!("/v1/sandboxes/{left}"), StatusCode::OK),
        (
            "GET",
            format!("/v1/sandboxes/{right}"),
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            format!("/v1/executions/{}", command.id),
            StatusCode::OK,
        ),
        (
            "GET",
            format!("/v1/executions/{}", other.id),
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            format!("/v1/sandboxes/{left}/isolated-sessions"),
            StatusCode::FORBIDDEN,
        ),
        ("GET", "/v1/sandboxes".into(), StatusCode::FORBIDDEN),
        (
            "GET",
            format!("/v1/sessions?sandbox_id={left}"),
            StatusCode::OK,
        ),
        (
            "GET",
            format!("/v1/sessions?sandbox_id={right}"),
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            format!("/v1/sessions?sandbox_id={left}&sandbox_id={right}"),
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            format!("/v1/sandboxes/{left}/commands"),
            StatusCode::FORBIDDEN,
        ),
        (
            "DELETE",
            format!("/v1/sandboxes/{left}"),
            StatusCode::FORBIDDEN,
        ),
        (
            "PUT",
            format!("/v1/sandboxes/{left}/network-policy"),
            StatusCode::FORBIDDEN,
        ),
        ("POST", "/v1/api-keys".into(), StatusCode::FORBIDDEN),
        ("GET", "/v1/audit".into(), StatusCode::FORBIDDEN),
        (
            "GET",
            format!("/v1/api-keys/{}", issued.key.id),
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(
            call(&app, &issued.token, method, &path, None)
                .await
                .status(),
            status,
            "{method} {path}"
        );
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header("authorization", format!("Bearer {ADMIN}"))
                .header("authorization", format!("Bearer {}", issued.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let events = store.audit_page(0, 1000).await.unwrap();
    let serialized = serde_json::to_string(&events).unwrap();
    assert!(!serialized.contains(&issued.token));
    assert!(!serialized.contains(ADMIN));
    assert!(
        events
            .items
            .iter()
            .any(|r| r.event.key_id == Some(issued.key.id)
                && r.event.phase == AuditPhase::AuthorizationDenied)
    );
    store.close().await;
}

#[tokio::test]
async fn api_mints_once_returns_only_metadata_on_read_and_revoke_denies_future_requests() {
    let store = Store::memory().await.unwrap();
    let app = api::router(store.clone(), ADMIN).unwrap();
    let response=call(&app,ADMIN,"POST","/v1/api-keys",Some(json!({"permissions":["read"],"resources":"all","expires_at":Utc::now()+chrono::Duration::minutes(10)}))).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let issued: ApiKeyIssued =
        serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
    assert_eq!(
        call(&app, &issued.token, "GET", "/healthz", None)
            .await
            .status(),
        StatusCode::OK
    );
    let path = format!("/v1/api-keys/{}", issued.key.id);
    let response = call(&app, ADMIN, "GET", &path, None).await;
    let metadata = to_bytes(response.into_body(), 16384).await.unwrap();
    assert!(!String::from_utf8_lossy(&metadata).contains(&issued.token));
    assert_eq!(
        call(&app, ADMIN, "DELETE", &path, None).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        call(&app, &issued.token, "GET", "/healthz", None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, ADMIN, "DELETE", &path, None).await.status(),
        StatusCode::OK
    );
    store.close().await;
}

#[tokio::test]
async fn revocation_collects_an_already_polled_idle_sse_body_without_cancelling_execution() {
    let store = Store::memory().await.unwrap();
    let id = source(&store, "source").await;
    let command = store
        .create_execution(id, &CommandSpec::new(["sleep", "100"]), "run")
        .await
        .unwrap();
    let issued = issue(
        &store,
        KeyResources::Sandboxes(BTreeSet::from([id])),
        [KeyPermission::Read],
    )
    .await;
    let app = api::router(store.clone(), ADMIN).unwrap();
    let response = call(
        &app,
        &issued.token,
        "GET",
        &format!("/v1/executions/{}/events", command.id),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let reading = tokio::spawn(to_bytes(response.into_body(), 16384));
    // Remain open across repeated authorization checks before revocation.
    // An unfinished idle body read must not pin the sole store connection.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert!(!reading.is_finished());
    let start = std::time::Instant::now();
    store
        .revoke_api_key(issued.key.id, Uuid::new_v4())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), reading)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(!store.execution(command.id).await.unwrap().cancel_requested);
    assert!(
        store
            .audit_page(0, 1000)
            .await
            .unwrap()
            .items
            .iter()
            .any(|r| r.event.phase == AuditPhase::StreamRevoked)
    );
    store.close().await;
}

#[tokio::test]
async fn revocation_closes_a_real_websocket_and_rejects_later_controls() {
    use futures_util::{FutureExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let store = Store::memory().await.unwrap();
    let id = source(&store, "socket-source").await;
    let session = store
        .create_session(id, &SessionSpec::shell(), "shell")
        .await
        .unwrap();
    let issued = issue(
        &store,
        KeyResources::Sandboxes(BTreeSet::from([id])),
        [KeyPermission::Execute],
    )
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = api::router(store.clone(), ADMIN).unwrap();
    let (shutdown, done) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = done.await;
            })
            .await
            .unwrap()
    });
    let result = std::panic::AssertUnwindSafe(async {
        let mut request = format!("ws://{address}/v1/sessions/{}/socket", session.execution.id)
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {}", issued.token).parse().unwrap(),
        );
        let (mut socket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        let initial = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(initial.is_text());
        let started = std::time::Instant::now();
        store
            .revoke_api_key(issued.key.id, Uuid::new_v4())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(Ok(message)) = socket.next().await {
                if message.is_close() {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(
            !store
                .execution(session.execution.id)
                .await
                .unwrap()
                .cancel_requested
        );
        drop(socket);
    })
    .catch_unwind()
    .await;
    let _ = shutdown.send(());
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    store.close().await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn expiry_is_enforced_after_issuance_and_audit_exports_have_a_frozen_upper_bound() {
    let store = Store::memory().await.unwrap();
    let app = api::router(store.clone(), ADMIN).unwrap();
    let issued = store
        .issue_api_key(
            &CreateApiKey {
                permissions: [KeyPermission::Read].into(),
                resources: KeyResources::All,
                expires_at: Utc::now() + chrono::Duration::milliseconds(100),
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(
        call(&app, &issued.token, "GET", "/healthz", None)
            .await
            .status(),
        StatusCode::OK
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        call(&app, &issued.token, "GET", "/healthz", None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = call(&app, ADMIN, "GET", "/v1/audit?limit=1", None).await;
    let first: AuditPage =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    let through = first.through_sequence;
    let mut cursor = first.items.last().unwrap().sequence;
    loop {
        let path = format!("/v1/audit?after={cursor}&limit=1&through={through}");
        let response = call(&app, ADMIN, "GET", &path, None).await;
        let page: AuditPage =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(page.through_sequence, through);
        for item in &page.items {
            assert!(item.sequence > cursor && item.sequence <= through);
            cursor = item.sequence;
        }
        if page.next_after.is_none() {
            break;
        }
    }
    assert_eq!(cursor, through);
    assert!(store.audit_page(0, 1000).await.unwrap().through_sequence > through);
    store.close().await;
}

#[tokio::test]
async fn create_body_cannot_bypass_network_permission_on_roots_or_children() {
    let store = Store::memory().await.unwrap();
    let id = source(&store, "parent").await;
    let issued = issue(&store, KeyResources::All, [KeyPermission::Write]).await;
    let app = api::router(store.clone(), ADMIN).unwrap();
    let input = json!({"profile":"fixture","image":"fixture","network":{"default_action":"allow","rules":[]}});
    assert_eq!(
        call(&app, &issued.token, "POST", "/v1/sandboxes", Some(input))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let input = json!({"network":{"default_action":"allow","rules":[]}});
    assert_eq!(
        call(
            &app,
            &issued.token,
            "POST",
            &format!("/v1/sandboxes/{id}/isolated-sessions"),
            Some(input)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    // A default-deny create still reaches the normal unavailable-worker check.
    let input = json!({"profile":"fixture","image":"fixture"});
    assert_eq!(
        call(&app, &issued.token, "POST", "/v1/sandboxes", Some(input))
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    store.close().await;
}
