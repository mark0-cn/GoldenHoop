//! Real HTTP/SQLite boundaries; private worker/runtime observations are synthetic.
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
    routing::post,
};
use chrono::Utc;
use futures_util::FutureExt;
use goldenhoop_control::{InternalSnapshotCall, api};
use goldenhoop_protocol::*;
use goldenhoop_runtime::RuntimeHandle;
use goldenhoop_store::{Store, WorkerRegistration};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    future::Future,
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tower::ServiceExt;
use uuid::Uuid;

const ADMIN: &str = "snapshot-http-admin-token-0123456789abcdef";
const PRIVATE: &str = "snapshot-http-private-token-0123456789abcdef";
fn profile() -> RuntimeProfile {
    serde_json::from_value(json!({"id":"snapshot-http-fixture","placement":"local","isolation":"firecracker","availability":"available","capabilities":["commands","files","pause","network_isolation","memory_snapshot"],"max_resources":{"cpu_millis":4000,"memory_bytes":4294967296_u64,"pids":1024},"max_ttl_seconds":3600})).unwrap()
}
fn intent() -> CreateSnapshot {
    CreateSnapshot {
        kind: SnapshotKind::MemoryAndDisk,
    }
}
async fn source(store: &Store, key: &str) -> Uuid {
    let id = store
        .create_sandbox(
            &profile(),
            &CreateSandbox::new(profile().id, "synthetic-image"),
            key,
        )
        .await
        .unwrap()
        .sandbox
        .id;
    let mut row = store.sandbox(id).await.unwrap();
    row.sandbox.state = SandboxState::Starting;
    store.observe(row.clone()).await.unwrap();
    row.sandbox.state = SandboxState::Running;
    row.handle = Some(RuntimeHandle {
        sandbox_id: id,
        profile: profile().id,
        backend_ref: format!("private-generation-{}", Uuid::new_v4()),
    });
    store.observe(row).await.unwrap();
    id
}
async fn checked<F, Fut>(test: F)
where
    F: FnOnce(Store, std::path::PathBuf) -> Fut,
    Fut: Future<Output = ()>,
{
    let directory = tempfile::Builder::new()
        .prefix("gh-snapshot-http-")
        .tempdir()
        .unwrap();
    let path = directory.path().join("control.db");
    let store = Store::open(&path).await.unwrap();
    let result = AssertUnwindSafe(test(store.clone(), path))
        .catch_unwind()
        .await;
    store.close().await;
    let root = directory.path().to_owned();
    directory.close().unwrap();
    assert!(!root.exists());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
async fn call(
    app: &Router,
    token: Option<&str>,
    method: &str,
    path: &str,
    value: Option<Value>,
    key: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(value.map_or_else(Body::empty, |v| Body::from(v.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let data = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&data)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&data)})),
    )
}
struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn key(store: &Store, source: Uuid, write: bool) -> String {
    store
        .issue_api_key(
            &CreateApiKey {
                resources: KeyResources::Sandboxes(BTreeSet::from([source])),
                permissions: if write {
                    BTreeSet::from([KeyPermission::Read, KeyPermission::Write])
                } else {
                    BTreeSet::from([KeyPermission::Read])
                },
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap()
        .token
}

#[tokio::test]
async fn durable_gateway_retry_survives_lost_private_reply_and_worker_retirement_without_private_leak()
 {
    checked(|store, _| async move {
        let src = source(&store, "source").await;
        let calls = Arc::new(AtomicUsize::new(0));
        let lose = Arc::new(AtomicBool::new(true));
        let handler_store = store.clone();
        let handler_calls = calls.clone();
        let handler_lose = lose.clone();
        let private = Router::new().route(
            "/internal/snapshots",
            post(
                move |headers: HeaderMap, Json(call): Json<InternalSnapshotCall>| {
                    let store = handler_store.clone();
                    let calls = handler_calls.clone();
                    let lose = handler_lose.clone();
                    async move {
                        assert_eq!(headers["authorization"], format!("Bearer {PRIVATE}"));
                        calls.fetch_add(1, Ordering::SeqCst);
                        let created = store
                            .create_snapshot(
                                &profile(),
                                call.sandbox_id,
                                &call.request,
                                &call.idempotency_key,
                            )
                            .await
                            .unwrap();
                        if lose.swap(false, Ordering::SeqCst) {
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(json!(ApiError::new(
                                    ErrorCode::BackendUnavailable,
                                    "synthetic reply lost after admission"
                                ))),
                            );
                        }
                        let mut value = json!(created);
                        value["private_host_path"] = "/operator/private".into();
                        value["snapshot"]["source_handle"] = "private-generation".into();
                        (StatusCode::ACCEPTED, Json(value))
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let _server = Server(tokio::spawn(async move {
            axum::serve(listener, private).await.unwrap();
        }));
        let mut registration = WorkerRegistration {
            id: Uuid::new_v4(),
            endpoint,
            token: PRIVATE.into(),
            heartbeat: Utc::now(),
            profiles: vec![profile()],
        };
        store.register_worker(&registration).await.unwrap();
        let app = api::router(store.clone(), ADMIN).unwrap();
        let path = format!("/v1/sandboxes/{src}/snapshots");
        assert_eq!(
            call(
                &app,
                None,
                "POST",
                &path,
                Some(json!(intent())),
                Some("capture")
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                &app,
                Some(ADMIN),
                "POST",
                &path,
                Some(json!({"kind":"memory_and_disk","host_path":"forbidden"})),
                Some("bad")
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let oversized = call(
            &app,
            Some(ADMIN),
            "POST",
            &path,
            Some(json!({"kind":"memory_and_disk","padding":"x".repeat(10000)})),
            Some("too-large"),
        )
        .await
        .0;
        assert!(oversized.is_client_error());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            call(
                &app,
                Some(ADMIN),
                "POST",
                &path,
                Some(json!({"kind":"rootfs"})),
                Some("unsupported")
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            call(
                &app,
                Some(ADMIN),
                "POST",
                &path,
                Some(json!(intent())),
                Some("capture")
            )
            .await
            .0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let saved = store
            .prior_snapshot_request(src, &intent(), "capture")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        registration.heartbeat = Utc::now() - chrono::Duration::minutes(1);
        registration.profiles.clear();
        store.register_worker(&registration).await.unwrap();
        let (status, retry) = call(
            &app,
            Some(ADMIN),
            "POST",
            &path,
            Some(json!(intent())),
            Some("capture"),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(retry["snapshot"]["id"], json!(saved.snapshot.id));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            call(
                &app,
                Some(ADMIN),
                "POST",
                &path,
                Some(json!({"kind":"volumes"})),
                Some("capture")
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let (status, op) = call(
            &app,
            Some(ADMIN),
            "DELETE",
            &format!("/v1/snapshots/{}", saved.snapshot.id),
            None,
            Some("delete"),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(op["state"], "succeeded");
        assert_eq!(
            store.sandbox(src).await.unwrap().sandbox.desired_state,
            DesiredState::Running
        );
        let (status, visible) = call(
            &app,
            Some(ADMIN),
            "GET",
            &format!("/v1/snapshots/{}", saved.snapshot.id),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(visible["state"], "collected");
        assert!(
            !visible.to_string().contains("private-generation")
                && !visible.to_string().contains("source_handle")
        );
        // A successful private reply is cross-checked against durable admission.
        let other = source(&store, "other").await;
        registration.heartbeat = Utc::now();
        registration.profiles = vec![profile()];
        store.register_worker(&registration).await.unwrap();
        let (_, created) = call(
            &app,
            Some(ADMIN),
            "POST",
            &format!("/v1/sandboxes/{other}/snapshots"),
            Some(json!(intent())),
            Some("second"),
        )
        .await;
        assert!(created.get("snapshot").is_some());
        assert!(
            !created.to_string().contains("/operator/private")
                && !created.to_string().contains("source_handle")
        );
    })
    .await;
}

#[tokio::test]
async fn snapshot_resources_collections_and_both_operations_inherit_original_source_grant() {
    checked(|store, _| async move {
        let left = source(&store, "left").await;
        let right = source(&store, "right").await;
        let one = store
            .create_snapshot(&profile(), left, &intent(), "capture")
            .await
            .unwrap();
        let two = store
            .create_snapshot(&profile(), right, &intent(), "capture")
            .await
            .unwrap();
        let read = key(&store, left, false).await;
        let write = key(&store, left, true).await;
        let foreign = key(&store, right, false).await;
        let app = api::router(store.clone(), ADMIN).unwrap();
        for (path, status) in [
            (format!("/v1/snapshots/{}", one.snapshot.id), StatusCode::OK),
            (
                format!("/v1/snapshots/{}", two.snapshot.id),
                StatusCode::FORBIDDEN,
            ),
            (
                format!("/v1/operations/{}", one.operation.id),
                StatusCode::OK,
            ),
            (
                format!("/v1/operations/{}", two.operation.id),
                StatusCode::FORBIDDEN,
            ),
            (format!("/v1/snapshots?sandbox_id={left}"), StatusCode::OK),
            ("/v1/snapshots".into(), StatusCode::FORBIDDEN),
            (
                format!("/v1/snapshots?sandbox_id={right}"),
                StatusCode::FORBIDDEN,
            ),
            (
                format!("/v1/snapshots?sandbox_id={left}&sandbox_id={right}"),
                StatusCode::FORBIDDEN,
            ),
            (
                format!("/v1/snapshots?sandbox_id={left}&unknown=true"),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            assert_eq!(
                call(&app, Some(&read), "GET", &path, None, None).await.0,
                status,
                "{path}"
            );
        }
        let path = format!("/v1/snapshots/{}", one.snapshot.id);
        assert_eq!(
            call(&app, Some(&read), "DELETE", &path, None, Some("delete"))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        let (status, op) = call(&app, Some(&write), "DELETE", &path, None, Some("delete")).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let op_path = format!("/v1/operations/{}", op["id"].as_str().unwrap());
        assert_eq!(
            call(&app, Some(&read), "GET", &op_path, None, None).await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(&app, Some(&foreign), "GET", &op_path, None, None)
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&app, Some(&foreign), "DELETE", &path, None, Some("foreign"))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            store.sandbox(left).await.unwrap().sandbox.state,
            SandboxState::Running
        );
    })
    .await;
}

#[tokio::test]
async fn operation_authority_uses_snapshot_kind_even_when_another_sandbox_shares_target_uuid() {
    use sqlx::Connection;
    checked(|store,path|async move {
        let owner=source(&store,"owner").await;let foreign=source(&store,"foreign").await;
        let created=store.create_snapshot(&profile(),owner,&intent(),"capture").await.unwrap();
        let mut db=sqlx::SqliteConnection::connect_with(&sqlx::sqlite::SqliteConnectOptions::new().filename(&path)).await.unwrap();
        sqlx::query("UPDATE snapshots SET id=?,payload=json_set(payload,'$.id',?) WHERE id=?").bind(foreign.to_string()).bind(foreign.to_string()).bind(created.snapshot.id.to_string()).execute(&mut db).await.unwrap();
        sqlx::query("UPDATE operations SET resource_id=?,payload=json_set(payload,'$.resource_id',?) WHERE id=?").bind(foreign.to_string()).bind(foreign.to_string()).bind(created.operation.id.to_string()).execute(&mut db).await.unwrap();db.close().await.unwrap();
        let owner_key=key(&store,owner,false).await;let foreign_key=key(&store,foreign,false).await;let app=api::router(store.clone(),ADMIN).unwrap();let path=format!("/v1/operations/{}",created.operation.id);
        assert_eq!(call(&app,Some(&owner_key),"GET",&path,None,None).await.0,StatusCode::OK);
        assert_eq!(call(&app,Some(&foreign_key),"GET",&path,None,None).await.0,StatusCode::FORBIDDEN);
    }).await;
}
