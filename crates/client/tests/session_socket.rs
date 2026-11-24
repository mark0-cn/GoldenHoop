use axum::{
    Router,
    extract::ws::{Message, WebSocketUpgrade},
    http::HeaderMap,
    routing::get,
};
use goldenhoop_client::*;
use serde_json::{Value, json};
use uuid::Uuid;

const TOKEN: &str = "socket-test-credential-0000000000000000";
struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn server(id: Uuid, messages: Vec<Value>) -> (Client, Server) {
    let router = Router::new().route(
        &format!("/v1/sessions/{id}/socket"),
        get(move |headers: HeaderMap, upgrade: WebSocketUpgrade| {
            let messages = messages.clone();
            async move {
                assert_eq!(
                    headers.get("authorization").unwrap(),
                    &format!("Bearer {TOKEN}")
                );
                upgrade.on_upgrade(move |mut socket| async move {
                    for message in messages {
                        socket
                            .send(Message::Text(message.to_string().into()))
                            .await
                            .unwrap();
                    }
                    let _ = socket.send(Message::Close(None)).await;
                })
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = Client::new(&format!("http://{}", listener.local_addr().unwrap()), TOKEN).unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (client, Server(task))
}
fn session(id: Uuid, sandbox: Uuid) -> Value {
    json!({"kind":"session","value":{"execution":{"id":id,"sandbox_id":sandbox,"state":"running","exit_code":null,"created_at":"2026-01-01T00:00:00Z","started_at":null,"finished_at":null,"output_truncated":false,"cleanup":"pending","reason":null},"spec":{"command":{"argv":["/bin/sh"]},"terminal":null}}})
}
#[tokio::test]
async fn socket_eof_without_completion_is_not_success() {
    let id = Uuid::new_v4();
    let sandbox = Uuid::new_v4();
    let (client, _server) = server(id, vec![session(id, sandbox)]).await;
    let mut socket = client.session_socket(id, 0).await.unwrap();
    assert!(matches!(
        socket.recv().await.unwrap(),
        Some(SessionSocketServerMessage::Session(_))
    ));
    assert!(matches!(socket.recv().await, Err(Error::Protocol(_))));
}
#[tokio::test]
async fn socket_refuses_wrong_resource_and_sequence_gaps() {
    for (event_id, sequence) in [(Uuid::new_v4(), 1), (Uuid::nil(), 2)] {
        let id = Uuid::new_v4();
        let sandbox = Uuid::new_v4();
        let event_id = if event_id.is_nil() { id } else { event_id };
        let bad = json!({"kind":"event","value":{"execution_id":event_id,"sequence":sequence,"kind":"stdout","timestamp":"2026-01-01T00:00:00Z","data":{"encoding":"base64","data":"YQ=="}}});
        let (client, _server) = server(id, vec![session(id, sandbox), bad]).await;
        let mut socket = client.session_socket(id, 0).await.unwrap();
        socket.recv().await.unwrap();
        assert!(matches!(socket.recv().await, Err(Error::Protocol(_))));
    }
}
