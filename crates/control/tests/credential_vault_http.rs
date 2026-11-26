//! Vault intent over actual HTTP routing and encrypted SQL storage. This does
//! not grant SecretInjection or attest an installed transparent broker.
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use goldenhoop_control::api;
use goldenhoop_credentials::*;
use goldenhoop_protocol::*;
use goldenhoop_store::Store;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const ADMIN: &str = "credential-vault-http-test-admin-0123456789";
async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    input: Option<Value>,
) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {ADMIN}"))
                .header("content-type", "application/json")
                .body(input.map_or_else(Body::empty, |v| Body::from(v.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn encrypted_intent_replay_conflict_rotation_and_revocation_never_publish_unobserved_readiness()
 {
    let store = Store::memory().await.unwrap();
    let master = VaultKey::from_bytes([31; 32]);
    let profile:RuntimeProfile=serde_json::from_value(json!({"id":"fixture","placement":"local","isolation":"gvisor","availability":"available","capabilities":["commands","network_isolation"],"max_resources":{"cpu_millis":1000,"memory_bytes":1073741824,"pids":256},"max_ttl_seconds":3600})).unwrap();
    let id = store
        .create_sandbox(
            &profile,
            &CreateSandbox::new("fixture", "fixture"),
            "source",
        )
        .await
        .unwrap()
        .sandbox
        .id;
    let binding = Uuid::new_v4();
    let path = format!("/v1/sandboxes/{id}/credentials/{binding}");
    let mut input = json!({"expected_revision":0,"binding":{"scheme":"https","host":"api.example.test","port":443,"methods":["POST"],"path_prefix":"/v1/","injection":{"kind":"bearer"}},"secret":{"kind":"literal","value":"provider-fixture-secret-ONE"}});
    let unavailable = api::router(store.clone(), ADMIN).unwrap();
    assert_eq!(
        call(&unavailable, "PUT", &path, Some(input.clone()))
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let app = api::router_with_vault(store.clone(), ADMIN, Some(master.clone())).unwrap();
    let (status, first) = call(&app, "PUT", &path, Some(input.clone())).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(first["state"], "pending");
    assert!(first["applied_revision"].is_null());
    assert!(!first.to_string().contains("provider-fixture"));
    let (_, replay) = call(&app, "PUT", &path, Some(input.clone())).await;
    assert_eq!(first, replay);
    input["secret"]["value"] = json!("provider-fixture-secret-TWO");
    assert_eq!(
        call(&app, "PUT", &path, Some(input.clone())).await.0,
        StatusCode::CONFLICT
    );
    input["expected_revision"] = json!(1);
    let (status, second) = call(&app, "PUT", &path, Some(input.clone())).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(second["revision"], 2);
    assert!(
        store
            .credential_secret(&master, id, binding, 1)
            .await
            .is_err()
    );
    let SecretSource::Literal { value } = store
        .credential_secret(&master, id, binding, 2)
        .await
        .unwrap()
    else {
        panic!("wrong private source");
    };
    assert_eq!(value.0.as_str(), "provider-fixture-secret-TWO");
    let wrong = VaultKey::from_bytes([32; 32]);
    assert!(
        store
            .credential_secret(&wrong, id, binding, 2)
            .await
            .is_err()
    );
    let (status, revoking) = call(&app, "DELETE", &path, None).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(revoking["state"], "revoking");
    assert!(
        store
            .credential_secret(&master, id, binding, 2)
            .await
            .is_err()
    );
    assert_eq!(
        call(&app, "PUT", &path, Some(input)).await.0,
        StatusCode::CONFLICT
    );
    let (_, metadata) = call(&app, "GET", &path, None).await;
    assert!(!metadata.to_string().contains("provider-fixture"));
    let audit = store.audit_page(0, 1000).await.unwrap();
    assert!(
        !serde_json::to_string(&audit)
            .unwrap()
            .contains("provider-fixture")
    );
    let credential_events: Vec<_> = audit
        .items
        .iter()
        .filter(|r| r.event.action == AuditAction::Credential)
        .collect();
    assert_eq!(credential_events.len(), 3);
    store.close().await;
}
