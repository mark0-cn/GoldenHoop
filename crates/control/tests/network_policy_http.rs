//! Actual in-process HTTP routing over synthetic domain metadata. This does not
//! establish a native lease or advertise runtime NetworkPolicy support.
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use goldenhoop_control::api;
use goldenhoop_protocol::*;
use goldenhoop_store::Store;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;
const TOKEN: &str = "network-policy-http-test-token-0123456789";
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    authenticated: bool,
    key: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);
    if authenticated {
        request = request.header("authorization", format!("Bearer {TOKEN}"));
    }
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    let body = if let Some(body) = body {
        request = request.header("content-type", "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
#[tokio::test]
async fn desired_metadata_survives_worker_absence_and_unbound_mutations_never_enable_networking() {
    let store = Store::memory().await.unwrap();
    let profile:RuntimeProfile=serde_json::from_value(json!({"id":"fixture","placement":"local","isolation":"gvisor","availability":"available","capabilities":["commands","network_isolation"],"max_resources":{"cpu_millis":1000,"memory_bytes":1073741824,"pids":256},"max_ttl_seconds":3600})).unwrap();
    let id = store
        .create_sandbox(
            &profile,
            &CreateSandbox::new("fixture", "fixture"),
            "create",
        )
        .await
        .unwrap()
        .sandbox
        .id;
    let app = api::router(store.clone(), TOKEN).unwrap();
    let path = format!("/v1/sandboxes/{id}/network-policy");
    assert_eq!(
        call(&app, "GET", &path, None, false, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, state) = call(&app, "GET", &path, None, true, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        state,
        json!({"sandbox_id":id,"revision":0,"policy":{"default_action":"deny","rules":[]}})
    );
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/v1/sandboxes/{}/network-policy", Uuid::new_v4()),
            None,
            true,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let request = json!({"expected_revision":0,"policy":{"default_action":"allow","rules":[]}});
    assert_eq!(
        call(&app, "PUT", &path, Some(request.clone()), true, None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &path,
            Some(
                json!({"expected_revision":0,"policy":{"default_action":"deny"},"allow_always":[]})
            ),
            true,
            Some("unknown")
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (_, error) = call(&app, "PUT", &path, Some(request), true, Some("unbound")).await;
    assert_eq!(error["code"], "invalid_state");
    assert_eq!(store.public_network_policy(id).await.unwrap().revision, 0);
    assert_eq!(call(&app,"PUT",&path,Some(json!({"expected_revision":0,"policy":{"default_action":"deny","rules":[],"padding":"x".repeat(65536)}})),true,Some("oversize")).await.0,StatusCode::PAYLOAD_TOO_LARGE);
    let mut sandbox = store.sandbox(id).await.unwrap();
    sandbox.sandbox.state = SandboxState::Starting;
    store.observe(sandbox.clone()).await.unwrap();
    sandbox.sandbox.state = SandboxState::Running;
    store.observe(sandbox).await.unwrap();
    let (_, error) = call(
        &app,
        "PUT",
        &path,
        Some(json!({"expected_revision":0,"policy":{"default_action":"deny"}})),
        true,
        Some("unsupported"),
    )
    .await;
    assert_eq!(error["code"], "unsupported_capability");
    assert_eq!(store.public_network_policy(id).await.unwrap().revision, 0);
    store.close().await;
}
