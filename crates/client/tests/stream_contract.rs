use std::sync::{Arc, Mutex};

use axum::{
    Router,
    http::HeaderMap,
    routing::{get, post},
};
use futures_util::StreamExt;
use goldenhoop_client::{Client, CommandSpec, Error, ExecutionState};
use serde_json::{Value, json};
use uuid::Uuid;

const TOKEN: &str = "test-credential-0000000000000000000000000";
struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn server(router: Router) -> (Client, Server) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (Client::new(&url, TOKEN).unwrap(), Server(task))
}
fn execution(sandbox: Uuid, id: Uuid, terminal: bool) -> Value {
    json!({"id":id,"sandbox_id":sandbox,"state":if terminal {"succeeded"}else{"pending"},
        "exit_code":if terminal {Some(0)}else{None},"created_at":"2026-01-01T00:00:00Z",
        "started_at":null,"finished_at":null,"output_truncated":false,
        "cleanup":if terminal {"complete"}else{"pending"},"reason":null})
}
fn frame(id: Uuid, sequence: u64, kind: &str, data: Value) -> String {
    let event = json!({"execution_id":id,"sequence":sequence,"kind":kind,"data":data,"timestamp":"2026-01-01T00:00:00Z"});
    format!("id: {id}:{sequence}\nevent: execution\ndata: {event}\n\n")
}

#[tokio::test]
async fn reconnect_uses_last_confirmed_cursor_and_never_duplicates_output() {
    let sandbox = Uuid::new_v4();
    let id = Uuid::new_v4();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let output = frame(id, 1, "stdout", json!({"encoding":"base64","data":"AP8="}));
    let completion = frame(id, 2, "completed", execution(sandbox, id, true));
    let seen_route = seen.clone();
    let router = Router::new()
        .route(
            &format!("/v1/sandboxes/{sandbox}/commands"),
            post(move || async move { axum::Json(execution(sandbox, id, false)) }),
        )
        .route(
            &format!("/v1/executions/{id}/events"),
            get(move |headers: HeaderMap| {
                let seen = seen_route.clone();
                let output = output.clone();
                let completion = completion.clone();
                async move {
                    let cursor = headers
                        .get("last-event-id")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string();
                    let body = if cursor.ends_with(":0") {
                        format!("{output}data: {{\"partial\"")
                    } else {
                        completion
                    };
                    seen.lock().unwrap().push(cursor);
                    ([("content-type", "text/event-stream")], body)
                }
            }),
        );
    let (client, _server) = server(router).await;
    let result = client
        .run(sandbox, &CommandSpec::new(["true"]))
        .await
        .unwrap();
    assert_eq!(result.execution.state, ExecutionState::Succeeded);
    assert_eq!(result.stdout, [0, 255]);
    assert_eq!(
        *seen.lock().unwrap(),
        [format!("{id}:0"), format!("{id}:1")]
    );
}

#[tokio::test]
async fn clean_eof_without_completion_is_an_observation_failure() {
    let sandbox = Uuid::new_v4();
    let id = Uuid::new_v4();
    let router = Router::new()
        .route(
            &format!("/v1/sandboxes/{sandbox}/commands"),
            post(move || async move { axum::Json(execution(sandbox, id, false)) }),
        )
        .route(
            &format!("/v1/executions/{id}/events"),
            get(|| async { ([("content-type", "text/event-stream")], ": heartbeat\n\n") }),
        );
    let (client, _server) = server(router).await;
    let error = client
        .run(sandbox, &CommandSpec::new(["true"]))
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::Observation(actual,_) if actual == id));
}

#[tokio::test]
async fn wrong_resource_or_event_sequence_is_rejected() {
    let id = Uuid::new_v4();
    let router = Router::new().route(
        &format!("/v1/executions/{id}/events"),
        get(move || async move {
            (
                [("content-type", "text/event-stream")],
                frame(id, 2, "stdout", json!({"encoding":"base64","data":""})),
            )
        }),
    );
    let (client, _server) = server(router).await;
    let mut events = client.events(id, None).await.unwrap();
    assert!(matches!(events.next().await, Some(Err(Error::Protocol(_)))));
}

#[tokio::test]
async fn wait_deadline_also_bounds_a_stalled_http_request() {
    let id = Uuid::new_v4();
    let router = Router::new().route(
        &format!("/v1/executions/{id}"),
        get(move || async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            axum::Json(json!({}))
        }),
    );
    let (client, _server) = server(router).await;
    let started = std::time::Instant::now();
    assert!(
        matches!(client.wait_execution(id,std::time::Duration::from_millis(50)).await,Err(Error::Timeout(actual)) if actual == id)
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn endpoint_credentials_and_remote_plaintext_are_rejected() {
    for url in [
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com/?token=secret",
    ] {
        assert!(Client::new(url, TOKEN).is_err());
    }
}
