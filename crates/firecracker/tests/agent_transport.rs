//! Controlled real Unix sockets test transport authority and dispatch phases.
//! They do not emulate or accept the AF_VSOCK/KVM guest runtime.
#![cfg(target_os = "linux")]

use goldenhoop_firecracker::{
    DispatchState,
    agent::AgentClient,
    api::{ApiClient, PeerIdentity},
    control::GuestAuthorityTransfer,
    models::{InstanceInfo, InstanceState},
    vsock::read_frame,
};
use goldenhoop_protocol::{AgentReply, AgentRequest, AgentResponse, ApiError, ErrorCode};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
    task::JoinHandle,
};
use uuid::Uuid;

#[derive(Clone, Copy)]
enum Behavior {
    Success,
    GuestRefusal,
    BadAck,
    Truncated,
    BeforeAckDeadline,
    AfterPayloadDeadline,
}

struct Fixture {
    directory: Option<tempfile::TempDir>,
    api: PathBuf,
    vsock: PathBuf,
    peer: PeerIdentity,
    api_task: Option<JoinHandle<()>>,
    vsock_task: Option<JoinHandle<Vec<u8>>>,
    connections: Arc<AtomicUsize>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(task) = &self.api_task {
            task.abort();
        }
        if let Some(task) = &self.vsock_task {
            task.abort();
        }
    }
}

impl Fixture {
    fn new(state: InstanceState, behavior: Behavior) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let api = directory.path().join("api.sock");
        let vsock = directory.path().join("vsock.sock");
        let api_listener = UnixListener::bind(&api).unwrap();
        let vsock_listener = UnixListener::bind(&vsock).unwrap();
        let peer = PeerIdentity {
            pid: std::process::id(),
            uid: unsafe { libc::geteuid() },
            instance: Uuid::new_v4(),
        };
        let connections = Arc::new(AtomicUsize::new(0));
        let captured = connections.clone();
        let api_task = tokio::spawn(async move {
            let (stream, _) = api_listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(line, "GET / HTTP/1.1\r\n");
            loop {
                line.clear();
                assert!(stream.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
            }
            let body = serde_json::to_vec(&InstanceInfo {
                app_name: "Firecracker".into(),
                id: peer.instance.to_string(),
                state,
                vmm_version: "1.18.0".into(),
            })
            .unwrap();
            stream
                .get_mut()
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.get_mut().write_all(&body).await.unwrap();
            stream.get_mut().shutdown().await.unwrap();
        });
        let vsock_task = tokio::spawn(async move {
            let (stream, _) = vsock_listener.accept().await.unwrap();
            captured.fetch_add(1, Ordering::SeqCst);
            let mut stream = BufReader::new(stream);
            assert_eq!(read_frame(&mut stream, 32).await.unwrap(), b"CONNECT 52\n");
            if matches!(behavior, Behavior::BeforeAckDeadline | Behavior::BadAck) {
                if matches!(behavior, Behavior::BadAck) {
                    stream.get_mut().write_all(b"OK 00052\n").await.unwrap();
                }
                let mut remaining = Vec::new();
                stream.read_to_end(&mut remaining).await.unwrap();
                return remaining;
            }
            stream
                .get_mut()
                .write_all(b"OK 1073741824\n")
                .await
                .unwrap();
            let request = read_frame(&mut stream, 1024).await.unwrap();
            if matches!(behavior, Behavior::AfterPayloadDeadline) {
                let mut remaining = Vec::new();
                stream.read_to_end(&mut remaining).await.unwrap();
                assert!(remaining.is_empty());
                return request;
            }
            let mut response = match behavior {
                Behavior::Success => {
                    serde_json::to_vec(&AgentReply::Success(AgentResponse::Ok)).unwrap()
                }
                Behavior::GuestRefusal => serde_json::to_vec(&AgentReply::Error(ApiError::new(
                    ErrorCode::Conflict,
                    "definite guest refusal",
                )))
                .unwrap(),
                Behavior::Truncated => b"{\"status\":\"success\"".to_vec(),
                _ => unreachable!(),
            };
            if !matches!(behavior, Behavior::Truncated) {
                response.push(b'\n');
            }
            stream.get_mut().write_all(&response).await.unwrap();
            stream.get_mut().shutdown().await.unwrap();
            request
        });
        Self {
            directory: Some(directory),
            api,
            vsock,
            peer,
            api_task: Some(api_task),
            vsock_task: Some(vsock_task),
            connections,
        }
    }

    fn client(&self) -> AgentClient {
        let api = ApiClient::new(self.api.clone(), self.peer, Duration::from_secs(3)).unwrap();
        AgentClient::new(api, self.vsock.clone(), 52, Duration::from_secs(2)).unwrap()
    }

    async fn observed_request(&mut self) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(3), self.vsock_task.take().unwrap())
            .await
            .unwrap()
            .unwrap()
    }

    async fn finish(mut self) {
        let task = self.api_task.take().unwrap();
        task.abort();
        let _ = task.await;
        if let Some(task) = self.vsock_task.take() {
            task.abort();
            let _ = task.await;
        }
        let path = self.directory.as_ref().unwrap().path().to_owned();
        self.directory.take().unwrap().close().unwrap();
        assert!(!path.exists());
    }
}

fn request() -> AgentRequest {
    AgentRequest::WriteFile {
        path: "nonce.txt".into(),
        data_base64: "bm9uY2U=".into(),
    }
}

fn assert_scoped_request(observed: &[u8], peer: PeerIdentity) {
    assert!(observed.ends_with(b"\n"));
    let actual: serde_json::Value = serde_json::from_slice(observed).unwrap();
    assert_eq!(
        actual,
        serde_json::json!({"guest_rpc": {
            "generation": peer.instance,
            "request": {"method":"write_file", "path":"nonce.txt", "data_base64":"bm9uY2U="}
        }})
    );
}

#[tokio::test]
async fn guest_success_and_definite_refusal_remain_typed_without_replay() {
    for behavior in [Behavior::Success, Behavior::GuestRefusal] {
        let mut fixture = Fixture::new(InstanceState::Running, behavior);
        let reply = fixture.client().rpc_reply(&request()).await.unwrap();
        match (behavior, reply) {
            (Behavior::Success, AgentReply::Success(AgentResponse::Ok)) => (),
            (Behavior::GuestRefusal, AgentReply::Error(error)) => {
                assert_eq!(error.code, ErrorCode::Conflict)
            }
            _ => panic!("transport changed the guest reply"),
        }
        let observed = fixture.observed_request().await;
        assert_scoped_request(&observed, fixture.peer);
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn paused_vm_and_invalid_handshake_do_not_send_the_mutation() {
    let fixture = Fixture::new(InstanceState::Paused, Behavior::Success);
    let error = fixture.client().rpc_reply(&request()).await.unwrap_err();
    assert_eq!(error.dispatch, DispatchState::NotSent);
    assert_eq!(error.error.code, ErrorCode::InvalidState);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
    fixture.finish().await;
    let mut fixture = Fixture::new(InstanceState::Running, Behavior::BadAck);
    let error = fixture.client().rpc_reply(&request()).await.unwrap_err();
    assert_eq!(error.dispatch, DispatchState::NotSent);
    assert!(fixture.observed_request().await.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn truncated_response_after_payload_is_uncertain_and_not_retryable() {
    let mut fixture = Fixture::new(InstanceState::Running, Behavior::Truncated);
    let error = fixture.client().rpc_reply(&request()).await.unwrap_err();
    assert_eq!(error.dispatch, DispatchState::Uncertain);
    assert!(!error.error.retryable);
    let observed = fixture.observed_request().await;
    assert_scoped_request(&observed, fixture.peer);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
    fixture.finish().await;
}

#[tokio::test]
async fn one_deadline_distinguishes_handshake_from_dispatched_payload() {
    for (behavior, expected) in [
        (Behavior::BeforeAckDeadline, DispatchState::NotSent),
        (Behavior::AfterPayloadDeadline, DispatchState::Uncertain),
    ] {
        let mut fixture = Fixture::new(InstanceState::Running, behavior);
        let error = fixture.client().rpc_reply(&request()).await.unwrap_err();
        assert_eq!(error.dispatch, expected);
        assert_eq!(error.error.code, ErrorCode::DeadlineExceeded);
        if expected == DispatchState::Uncertain {
            assert!(!error.error.retryable);
        }
        let observed = fixture.observed_request().await;
        assert_eq!(observed.is_empty(), expected == DispatchState::NotSent);
        if expected == DispatchState::Uncertain {
            assert_scoped_request(&observed, fixture.peer);
        }
        assert_eq!(fixture.connections.load(Ordering::SeqCst), 1);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn a_transfer_for_another_physical_vmm_is_refused_before_guest_dispatch() {
    let fixture = Fixture::new(InstanceState::Running, Behavior::Success);
    let transfer = GuestAuthorityTransfer {
        source_generation: fixture.peer.instance,
        target_generation: Uuid::new_v4(),
        barrier: Uuid::new_v4(),
        restoration: Uuid::new_v4(),
    };
    let error = fixture
        .client()
        .transfer_authority(&transfer)
        .await
        .unwrap_err();
    assert_eq!(error.dispatch, DispatchState::NotSent);
    assert_eq!(error.error.code, ErrorCode::InvalidRequest);
    assert_eq!(fixture.connections.load(Ordering::SeqCst), 0);
    fixture.finish().await;
}
