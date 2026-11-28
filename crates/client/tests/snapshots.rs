//! Actual loopback client protocol; runtime snapshot evidence is synthetic.
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use goldenhoop_client::*;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use uuid::Uuid;
struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn server(router: Router) -> (Client, Server) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    (
        Client::new(&url, "snapshot-client-token-0123456789abcdef").unwrap(),
        Server(tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        })),
    )
}
fn snapshot(id: Uuid, source: Uuid) -> Value {
    json!({"id":id,"source_sandbox_id":source,"kind":"memory_and_disk","state":"ready","cleanup":"pending","created_at":"2026-01-01T00:00:00Z","observed_at":null,"error":null,
        "manifest":{"format_version":1,"id":id,"source_sandbox_id":source,"kind":"memory_and_disk","driver":"fixture","architecture":"x86_64","image_digest":"sha256:fixture","objects":{"state":format!("sha256:{}","a".repeat(64)),"memory":format!("sha256:{}","b".repeat(64)),"disk":format!("sha256:{}","c".repeat(64))},"runtime_version":"fixture","created_at":"2026-01-01T00:00:00Z"}})
}
fn operation(op: Uuid, id: Uuid, state: &str) -> Value {
    json!({"id":op,"resource_id":id,"state":state,"created_at":"2026-01-01T00:00:00Z","finished_at":null,"error":null})
}

fn restoration(snapshot: Uuid, target: Uuid, op: Uuid, old: Uuid, new: Uuid) -> Value {
    json!({"snapshot_id":snapshot,"sandbox":{"id":target,"profile":"fixture","image":"fixture-image","state":"pending","desired_state":"running","cleanup":"pending","created_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:30:00Z","observed_at":null,"resources":{"cpu_millis":1000,"memory_bytes":1073741824_u64,"pids":256},"metadata":{},"reason":null},"operation":operation(op,target,"pending"),"executions":[{"source_execution_id":old,"execution":{"id":new,"sandbox_id":target,"state":"unknown","exit_code":null,"created_at":"2026-01-01T00:00:00Z","started_at":"2025-12-31T23:59:00Z","finished_at":null,"output_truncated":false,"cleanup":"pending","reason":null}}]})
}

#[tokio::test]
async fn restoration_retry_keeps_the_same_target_and_explicit_retained_execution_binding() {
    let (snapshot, target, op, old, new) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    let recorded = seen.clone();
    let count = calls.clone();
    let router = Router::new()
        .route(
            &format!("/v1/snapshots/{snapshot}/restore"),
            post(move |headers: HeaderMap, Json(request): Json<Value>| {
                let seen = recorded.clone();
                let calls = count.clone();
                async move {
                    seen.lock()
                        .unwrap()
                        .push(headers["idempotency-key"].to_str().unwrap().to_owned());
                    assert_eq!(request["target"]["image"], "fixture-image");
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!(ApiError::new(
                                ErrorCode::BackendUnavailable,
                                "synthetic restore reply loss"
                            ))),
                        );
                    }
                    (
                        StatusCode::ACCEPTED,
                        Json(restoration(snapshot, target, op, old, new)),
                    )
                }
            }),
        )
        .route(
            &format!("/v1/sandboxes/{target}/restoration"),
            get(move || async move { Json(restoration(snapshot, target, op, old, new)) }),
        );
    let (client, _server) = server(router).await;
    let intent = RestoreSnapshot {
        target: CreateSandbox::new("fixture", "fixture-image"),
    };
    assert!(matches!(
        client.restore_snapshot(snapshot, &intent, "stable").await,
        Err(Error::Api(_))
    ));
    let restored = client
        .restore_snapshot(snapshot, &intent, "stable")
        .await
        .unwrap();
    assert_eq!(restored.sandbox.id, target);
    assert_eq!(restored.executions[0].source_execution_id, old);
    assert_eq!(restored.executions[0].execution.id, new);
    assert_eq!(
        client
            .snapshot_restoration(target)
            .await
            .unwrap()
            .operation
            .id,
        op
    );
    assert_eq!(*seen.lock().unwrap(), vec!["stable", "stable"]);
}

#[tokio::test]
async fn foreign_restoration_targets_and_execution_aliases_are_protocol_errors() {
    let (snapshot, target, op, old, new) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let mode = Arc::new(AtomicUsize::new(0));
    let selected = mode.clone();
    let router = Router::new().route(
        &format!("/v1/snapshots/{snapshot}/restore"),
        post(move || {
            let mode = selected.clone();
            async move {
                let mut value = restoration(snapshot, target, op, old, new);
                match mode.load(Ordering::SeqCst) {
                    0 => value["snapshot_id"] = json!(Uuid::new_v4()),
                    1 => value["operation"]["resource_id"] = json!(Uuid::new_v4()),
                    2 => value["executions"][0]["execution"]["sandbox_id"] = json!(Uuid::new_v4()),
                    3 => value["executions"][0]["execution"]["id"] = json!(old),
                    4 => value["executions"][0]["source_execution_id"] = json!(Uuid::nil()),
                    5 => value["sandbox"]["profile"] = json!("foreign"),
                    6 => {
                        let duplicate = value["executions"][0].clone();
                        value["executions"].as_array_mut().unwrap().push(duplicate);
                    }
                    _ => unreachable!(),
                }
                Json(value)
            }
        }),
    );
    let (client, _server) = server(router).await;
    let intent = RestoreSnapshot {
        target: CreateSandbox::new("fixture", "fixture-image"),
    };
    for variant in 0..7 {
        mode.store(variant, Ordering::SeqCst);
        assert!(
            matches!(
                client.restore_snapshot(snapshot, &intent, "key").await,
                Err(Error::Protocol(_))
            ),
            "variant {variant}"
        );
    }
}

#[tokio::test]
async fn explicit_capture_retry_and_deletion_preserve_keys_and_never_delete_source() {
    let (id, source, op, delete) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    let capture_seen = seen.clone();
    let capture_calls = calls.clone();
    let delete_seen = seen.clone();
    let router=Router::new().route(&format!("/v1/sandboxes/{source}/snapshots"),post(move|headers:HeaderMap,Json(body):Json<Value>| {
        let seen=capture_seen.clone();let calls=capture_calls.clone();async move {
            seen.lock().unwrap().push(headers["idempotency-key"].to_str().unwrap().to_owned());assert_eq!(body,json!({"kind":"memory_and_disk"}));
            if calls.fetch_add(1,Ordering::SeqCst)==0 {return (StatusCode::SERVICE_UNAVAILABLE,Json(json!(ApiError::new(ErrorCode::BackendUnavailable,"synthetic lost reply"))));}
            (StatusCode::ACCEPTED,Json(json!({"snapshot":snapshot(id,source),"operation":operation(op,id,"succeeded")})))
        }
    })).route(&format!("/v1/snapshots/{id}"),get(move||async move{Json(snapshot(id,source))}).delete(move|headers:HeaderMap| {
        let seen=delete_seen.clone();async move{seen.lock().unwrap().push(headers["idempotency-key"].to_str().unwrap().to_owned());Json(operation(delete,id,"pending"))}
    })).route("/v1/snapshots",get(move||async move {Json(json!({"items":[snapshot(id,source)],"next_cursor":null}))}));
    let (client, _server) = server(router).await;
    let request = CreateSnapshot {
        kind: SnapshotKind::MemoryAndDisk,
    };
    assert!(matches!(
        client
            .create_snapshot(source, &request, "stable-capture")
            .await,
        Err(Error::Api(_))
    ));
    let created = client
        .create_snapshot(source, &request, "stable-capture")
        .await
        .unwrap();
    assert_eq!(created.snapshot.id, id);
    assert_eq!(created.operation.id, op);
    assert_eq!(client.snapshot(id).await.unwrap().source_sandbox_id, source);
    assert_eq!(
        client
            .list_snapshots(Some(source), None, 100)
            .await
            .unwrap()
            .items
            .len(),
        1
    );
    assert_eq!(
        client
            .delete_snapshot(id, "stable-delete")
            .await
            .unwrap()
            .state,
        OperationState::Pending
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec!["stable-capture", "stable-capture", "stable-delete"]
    );
}

#[tokio::test]
async fn forged_source_operation_manifest_and_cleanup_receipts_are_protocol_errors() {
    let (id, source, op) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let mode = Arc::new(AtomicUsize::new(0));
    let selected = mode.clone();
    let router=Router::new().route(&format!("/v1/sandboxes/{source}/snapshots"),post(move|| {
        let selected=selected.clone();async move {
            let mut value=json!({"snapshot":snapshot(id,source),"operation":operation(op,id,"succeeded")});
            match selected.load(Ordering::SeqCst) {
                0=>value["snapshot"]["source_sandbox_id"]=json!(Uuid::new_v4()),
                1=>value["operation"]["resource_id"]=json!(Uuid::new_v4()),
                2=>value["snapshot"]["manifest"]=Value::Null,
                3=>{value["snapshot"]["state"]="collected".into();value["snapshot"]["cleanup"]="unknown".into();},
                4=>value["snapshot"]["manifest"]["source_sandbox_id"]=json!(Uuid::new_v4()),
                5=>value["snapshot"]["manifest"]["objects"]["state"]="sha256:invalid".into(),
                6=>value["snapshot"]["manifest"]["format_version"]=2.into(),
                7=>value["snapshot"]["kind"]="rootfs".into(),
                _=>unreachable!(),
            }
            Json(value)
        }
    }));
    let (client, _server) = server(router).await;
    for variant in 0..8 {
        mode.store(variant, Ordering::SeqCst);
        assert!(
            matches!(
                client
                    .create_snapshot(
                        source,
                        &CreateSnapshot {
                            kind: SnapshotKind::MemoryAndDisk
                        },
                        "same-key"
                    )
                    .await,
                Err(Error::Protocol(_))
            ),
            "variant {variant}"
        );
    }
}

#[tokio::test]
async fn page_cursor_and_source_validation_refuse_cross_source_or_repeated_results() {
    let (id, source) = (Uuid::new_v4(), Uuid::new_v4());
    let mode = Arc::new(AtomicUsize::new(0));
    let selected = mode.clone();
    let router=Router::new().route("/v1/snapshots",get(move|| {let selected=selected.clone();async move {
        let value=match selected.load(Ordering::SeqCst) {
            0=>json!({"items":[snapshot(id,Uuid::new_v4())],"next_cursor":null}),
            1=>json!({"items":[snapshot(id,source)],"next_cursor":Uuid::new_v4()}),
            _=>json!({"items":[snapshot(id,source),snapshot(id,source)],"next_cursor":null}),
        };Json(value)
    }}));
    let (client, _server) = server(router).await;
    for variant in 0..3 {
        mode.store(variant, Ordering::SeqCst);
        assert!(matches!(
            client
                .list_snapshots(Some(source), None, if variant == 2 { 2 } else { 1 })
                .await,
            Err(Error::Protocol(_))
        ));
    }
}
