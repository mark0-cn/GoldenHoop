use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Response,
};
use chrono::Utc;
use goldenhoop_control::api;
use goldenhoop_protocol::*;
use goldenhoop_store::{Store, WorkerRegistration};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "contexts-http-contract-token-0123456789abcdef";

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    key: Option<&str>,
    cursor: Option<String>,
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {TOKEN}"));
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    if let Some(cursor) = cursor {
        request = request.header("last-event-id", cursor);
    }
    let body = if let Some(body) = body {
        request = request.header("content-type", "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    app.clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn offline_replays_close_intent_and_history_remain_available_without_enabling_new_work() {
    let store = Store::memory().await.unwrap();
    let profile = RuntimeProfile {
        id: "fixture".into(),
        placement: Placement::Local,
        isolation: Isolation::Gvisor,
        availability: Availability::Available,
        capabilities: BTreeSet::from([Capability::Commands, Capability::NetworkIsolation]),
        max_resources: ResourceLimits::default(),
        max_ttl_seconds: 86400,
        reason: None,
    };
    let source = store
        .create_sandbox(
            &profile,
            &CreateSandbox::new("fixture", "fixture"),
            "source",
        )
        .await
        .unwrap()
        .sandbox
        .id;
    let mut parent = store.sandbox(source).await.unwrap();
    parent.sandbox.state = SandboxState::Starting;
    store.observe(parent.clone()).await.unwrap();
    parent.sandbox.state = SandboxState::Running;
    store.observe(parent).await.unwrap();
    let spec = CodeContextSpec::default();
    let mut context = store
        .create_code_context(source, &spec, "context")
        .await
        .unwrap();
    store.dispatch_code_context(context.id).await.unwrap();
    context.state = CodeContextState::Ready;
    context.ready_at = Some(Utc::now());
    context.kernel_info = Some(json!({"language_info":{"name":"python"}}));
    store
        .append_code_context_events(
            context.id,
            &[CodeContextEvent {
                sequence: 1,
                context_id: context.id,
                run_id: None,
                timestamp: Utc::now(),
                kind: CodeContextEventKind::Ready,
                data: json!(context),
            }],
        )
        .await
        .unwrap();
    let run_spec = CodeRunSpec::new("42");
    let run = store
        .create_code_run(context.id, &run_spec, "run")
        .await
        .unwrap();
    let app = api::router(store.clone(), TOKEN).unwrap();
    let context_path = format!("/v1/code-contexts/{}", context.id);
    let runs_path = format!("{context_path}/runs");
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v1/sandboxes/{source}/code-contexts"),
            Some(json!(spec)),
            Some("context"),
            None
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );
    let replay = call(
        &app,
        "POST",
        &runs_path,
        Some(json!(run_spec)),
        Some("run"),
        None,
    )
    .await;
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    let replay: CodeRun =
        serde_json::from_slice(&to_bytes(replay.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!((replay.id, replay.events_after), (run.id, 1));
    assert_eq!(
        call(
            &app,
            "POST",
            &runs_path,
            Some(json!(CodeRunSpec::new("different"))),
            Some("run"),
            None
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &runs_path,
            Some(json!(run_spec)),
            Some("new"),
            None
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    store
        .register_worker(&WorkerRegistration {
            id: Uuid::new_v4(),
            endpoint: "http://127.0.0.1:1/".into(),
            token: TOKEN.into(),
            heartbeat: Utc::now(),
            profiles: vec![profile],
        })
        .await
        .unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            &runs_path,
            Some(json!(run_spec)),
            Some("unadvertised"),
            None
        )
        .await
        .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut streams = Vec::new();
    for _ in 0..16 {
        let response = call(
            &app,
            "GET",
            &format!("{context_path}/events"),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        streams.push(response);
    }
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("{context_path}/events"),
            None,
            None,
            None
        )
        .await
        .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    drop(streams);
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("{context_path}/events?after=2"),
            None,
            None,
            None
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("{context_path}/events?after=0"),
            None,
            None,
            Some(format!("{}:0", Uuid::new_v4()))
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("{context_path}/events?after=0"),
            None,
            None,
            Some(format!("{}:1", context.id))
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let closing = call(&app, "DELETE", &context_path, None, Some("close"), None).await;
    assert_eq!(closing.status(), StatusCode::ACCEPTED);
    let closing: CodeContext =
        serde_json::from_slice(&to_bytes(closing.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(closing.desired_state, CodeContextDesiredState::Closed);
    assert_eq!(closing.cleanup, CleanupState::Pending);
    store
        .finish_code_context_absent(context.id, "fixture observed runtime absence")
        .await
        .unwrap();
    let response = call(
        &app,
        "GET",
        &format!("{context_path}/events"),
        None,
        None,
        Some(format!("{}:1", context.id)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(!body.contains("\"kind\":\"ready\""));
    assert!(body.contains("\"kind\":\"run_completed\"") && body.contains("\"kind\":\"closed\""));
    assert!(
        body.contains(&format!("id: {}:2", context.id))
            && body.contains(&format!("id: {}:3", context.id))
    );
    let response = call(
        &app,
        "GET",
        &format!("/v1/code-contexts?sandbox_id={source}&limit=1"),
        None,
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    store.close().await;
}
