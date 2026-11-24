use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use goldenhoop_control::api;
use goldenhoop_store::Store;
use tower::ServiceExt;

const TOKEN: &str = "local-http-contract-token-0123456789abcdef";

#[tokio::test]
async fn authentication_precedes_routing_and_private_worker_metadata_is_not_public() {
    let store = Store::memory().await.unwrap();
    let app = api::router(store.clone(), TOKEN).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/profiles")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let error: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(error["code"], "unauthorized");
    assert!(error["request_id"].is_string());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/profiles")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let error: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(error["code"], "backend_unavailable");
    assert!(!error.to_string().contains(TOKEN));
    store.close().await;
}

#[tokio::test]
async fn invalid_json_paths_queries_and_missing_idempotency_use_typed_errors() {
    let store = Store::memory().await.unwrap();
    let app = api::router(store.clone(), TOKEN).unwrap();
    for (method, path, body) in [
        ("GET", "/v1/sandboxes/not-a-uuid", ""),
        ("GET", "/v1/sandboxes?limit=bad", ""),
        ("POST", "/v1/sandboxes", "{"),
        (
            "POST",
            "/v1/sandboxes",
            "{\"profile\":\"local-gvisor\",\"image\":\"test\"}",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {TOKEN}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(error["code"], "invalid_request");
    }
    store.close().await;
}
