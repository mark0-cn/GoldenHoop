use axum::{
    Router,
    http::HeaderMap,
    routing::{get, post},
};
use goldenhoop_client::{Client, CodeRunSpec, CodeRunState, Error};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
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
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (
        Client::new(&url, "code-context-test-token-00000000000000000000").unwrap(),
        Server(task),
    )
}
fn context(id: Uuid, sandbox: Uuid) -> Value {
    json!({"id":id,"sandbox_id":sandbox,"spec":{"language":"python","cwd":"/workspace"},"state":"ready","desired_state":"open","cleanup":"pending","created_at":"2026-01-01T00:00:00Z","ready_at":"2026-01-01T00:00:01Z","finished_at":null,"kernel_info":{},"reason":null})
}
fn run(id: Uuid, context: Uuid, complete: bool) -> Value {
    json!({"id":id,"context_id":context,"events_after":4,"state":if complete {"kernel_succeeded"} else {"pending"},"created_at":"2026-01-01T00:00:01Z","started_at":if complete {Some("2026-01-01T00:00:02Z")} else {None},"finished_at":if complete {Some("2026-01-01T00:00:03Z")} else {None},"output_truncated":false,"kernel_status":if complete {Some("ok")} else {None},"reason":null})
}
fn frame(context: Uuid, id: Uuid, sequence: u64, kind: &str, data: Value) -> String {
    let event = json!({"context_id":context,"run_id":id,"sequence":sequence,"kind":kind,"data":data,"timestamp":"2026-01-01T00:00:02Z"});
    format!("id: {context}:{sequence}\nevent: code_context\ndata: {event}\n\n")
}

#[tokio::test]
async fn replay_and_partial_reconnect_use_acceptance_and_last_whole_cursors() {
    let (context_id, sandbox, id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let route = seen.clone();
    let router = Router::new()
        .route(
            &format!("/v1/code-contexts/{context_id}"),
            get(move || async move { axum::Json(context(context_id, sandbox)) }),
        )
        .route(
            &format!("/v1/code-contexts/{context_id}/runs"),
            post(move || async move { axum::Json(run(id, context_id, true)) }),
        )
        .route(
            &format!("/v1/code-contexts/{context_id}/events"),
            get(move |headers: HeaderMap| {
                let route = route.clone();
                async move {
                    let cursor = headers["last-event-id"].to_str().unwrap().to_string();
                    let value = if cursor.ends_with(":4") {
                        format!(
                            "{}data: {{\"partial\"",
                            frame(
                                context_id,
                                id,
                                5,
                                "stdout",
                                json!({"late":false,"content":{"text":"once"}})
                            )
                        )
                    } else {
                        frame(
                            context_id,
                            id,
                            6,
                            "run_completed",
                            run(id, context_id, true),
                        )
                    };
                    route.lock().unwrap().push(cursor);
                    ([("content-type", "text/event-stream")], value)
                }
            }),
        );
    let (client, _server) = server(router).await;
    let output = client
        .run_code_with_key(context_id, &CodeRunSpec::new("do_not_repeat()"), "old-key")
        .await
        .unwrap();
    assert_eq!(output.stdout, "once");
    assert_eq!(output.run.state, CodeRunState::KernelSucceeded);
    assert_eq!(
        *seen.lock().unwrap(),
        [format!("{context_id}:4"), format!("{context_id}:5")]
    );
}

#[tokio::test]
async fn clean_context_eof_and_unknown_results_never_become_kernel_success() {
    for unknown in [false, true] {
        let (context_id, sandbox, id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let router = Router::new()
            .route(
                &format!("/v1/code-contexts/{context_id}"),
                get(move || async move { axum::Json(context(context_id, sandbox)) }),
            )
            .route(
                &format!("/v1/code-contexts/{context_id}/runs"),
                post(move || async move { axum::Json(run(id, context_id, false)) }),
            )
            .route(
                &format!("/v1/code-contexts/{context_id}/events"),
                get(move || async move {
                    let value = if unknown {
                        let mut value = run(id, context_id, true);
                        value["state"] = json!("unknown");
                        value["kernel_status"] = Value::Null;
                        frame(context_id, id, 5, "run_completed", value)
                    } else {
                        ": heartbeat\n\n".into()
                    };
                    ([("content-type", "text/event-stream")], value)
                }),
            );
        let (client, _server) = server(router).await;
        assert!(
            matches!(client.run_code(context_id,&CodeRunSpec::new("maybe()")).await,Err(Error::CodeObservation(actual,_)) if actual==id)
        );
    }
}

#[tokio::test]
async fn context_wait_deadlines_bound_stalled_http_observation() {
    let id = Uuid::new_v4();
    let router = Router::new().route(
        &format!("/v1/code-contexts/{id}"),
        get(|| async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            axum::Json(json!({}))
        }),
    );
    let (client, _server) = server(router).await;
    let started = std::time::Instant::now();
    assert!(
        matches!(client.wait_code_context_ready(id,std::time::Duration::from_millis(30)).await,Err(Error::Timeout(actual)) if actual==id)
    );
    assert!(
        matches!(client.wait_code_context_closed(id,std::time::Duration::from_millis(30)).await,Err(Error::Timeout(actual)) if actual==id)
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}
