//! Actual Unix sockets and peer credentials with a controlled HTTP fixture.
//! These are transport contracts, not Firecracker/KVM runtime acceptance.
#![cfg(target_os = "linux")]

use std::{path::PathBuf, sync::Arc, time::Duration};

use goldenhoop_firecracker::{DispatchState, api::*, models::*};
use goldenhoop_protocol::ErrorCode;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Mutex,
    task::JoinHandle,
};
use uuid::Uuid;

#[derive(Clone, Copy)]
enum Reply {
    Success,
    Rejected,
    Eof,
    IdentityEof,
    IdentityStall,
    MutationStall,
    WrongIdentity,
    WrongVersion,
    WrongState,
    WrongSuccess,
    Oversized,
    ChunkedOversized,
    InvalidNoContent,
}

struct Fixture {
    directory: Option<tempfile::TempDir>,
    socket: PathBuf,
    peer: PeerIdentity,
    records: Arc<Mutex<Vec<(String, Value)>>>,
    task: Option<JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl Fixture {
    async fn new(reply: Reply) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let peer = PeerIdentity {
            pid: std::process::id(),
            // SAFETY: geteuid has no arguments or memory safety preconditions.
            uid: unsafe { libc::geteuid() },
            instance: Uuid::new_v4(),
        };
        let records = Arc::new(Mutex::new(Vec::new()));
        let captured = records.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let _ = serve(stream, peer.instance, reply, &captured).await;
            }
        });
        Self {
            directory: Some(directory),
            socket,
            peer,
            records,
            task: Some(task),
        }
    }

    fn client(&self) -> ApiClient {
        ApiClient::new(self.socket.clone(), self.peer, Duration::from_secs(2)).unwrap()
    }

    async fn finish(mut self) {
        let task = self.task.take().unwrap();
        task.abort();
        let _ = task.await;
        let path = self.directory.as_ref().unwrap().path().to_owned();
        self.directory.take().unwrap().close().unwrap();
        assert!(!path.exists());
    }
}

async fn serve(
    stream: UnixStream,
    instance: Uuid,
    reply: Reply,
    records: &Mutex<Vec<(String, Value)>>,
) -> std::io::Result<()> {
    let mut stream = BufReader::new(stream);
    loop {
        let mut first = String::new();
        if stream.read_line(&mut first).await? == 0 {
            return Ok(());
        }
        let parts: Vec<_> = first.split_whitespace().collect();
        assert_eq!(parts.len(), 3);
        let route = format!("{} {}", parts[0], parts[1]);
        let identity = route == "GET /";
        let mut length = 0;
        loop {
            let mut line = String::new();
            stream.read_line(&mut line).await?;
            if line == "\r\n" {
                break;
            }
            if let Some((key, value)) = line.split_once(':')
                && key.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse::<usize>().unwrap();
            }
        }
        assert!(length <= MAX_API_BYTES);
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        records.lock().await.push((
            route,
            if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        ));
        if (identity && matches!(reply, Reply::IdentityEof))
            || (!identity && matches!(reply, Reply::Eof))
        {
            return Ok(());
        }
        if (identity && matches!(reply, Reply::IdentityStall))
            || (!identity && matches!(reply, Reply::MutationStall))
        {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        let response = if identity {
            let body = json!({
                "id":if matches!(reply, Reply::WrongIdentity) { Uuid::new_v4() } else { instance },
                "app_name":"Firecracker",
                "state":if matches!(reply, Reply::WrongState) { "Invented state" } else { "Not started" },
                "vmm_version":if matches!(reply, Reply::WrongVersion) { "future" } else { SUPPORTED_VMM_VERSION }
            }).to_string();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        } else {
            match reply {
                Reply::Rejected => {
                    let body =
                        r#"{"fault_message":"private-host-path-and-secret-must-not-escape"}"#;
                    format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                }
                Reply::WrongSuccess => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".into(),
                Reply::Oversized => format!(
                    "HTTP/1.1 500 Failure\r\nContent-Length: {}\r\n\r\n",
                    MAX_API_BYTES + 1
                ),
                Reply::ChunkedOversized => {
                    let chunk = "x".repeat(MAX_API_BYTES + 1);
                    format!(
                        "HTTP/1.1 500 Failure\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                        chunk.len(),
                        chunk
                    )
                }
                Reply::InvalidNoContent => {
                    "HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx".into()
                }
                _ => "HTTP/1.1 204 No Content\r\n\r\n".into(),
            }
        };
        stream.get_mut().write_all(response.as_bytes()).await?;
    }
}

#[tokio::test]
async fn all_bound_operations_use_real_peer_credentials_and_identity_before_mutation() {
    let fixture = Fixture::new(Reply::Success).await;
    let client = fixture.client();
    assert_eq!(
        client.instance_info().await.unwrap().state,
        InstanceState::NotStarted
    );
    client
        .configure_machine(&MachineConfiguration::new(1, 1024).unwrap())
        .await
        .unwrap();
    client
        .configure_boot(&BootSource::new("/kernel".into(), "console=ttyS0".into()).unwrap())
        .await
        .unwrap();
    client
        .configure_root(&RootDrive::new("/root.ext4".into(), false).unwrap())
        .await
        .unwrap();
    client
        .configure_vsock(&Vsock::new(3, "/vsock".into()).unwrap())
        .await
        .unwrap();
    client.start().await.unwrap();
    client.pause().await.unwrap();
    client.resume().await.unwrap();
    client
        .create_snapshot(&SnapshotCreate::full("/state".into(), "/memory".into()).unwrap())
        .await
        .unwrap();
    client
        .load_snapshot(&SnapshotLoad::paused("/state".into(), "/memory".into()).unwrap())
        .await
        .unwrap();
    let records = fixture.records.lock().await.clone();
    assert_eq!(records.len(), 19);
    assert_eq!(records[1].0, "GET /");
    assert_eq!(records[2].0, "PUT /machine-config");
    assert_eq!(records[6].0, "PUT /drives/rootfs");
    assert_eq!(
        records[10],
        (
            "PUT /actions".into(),
            json!({"action_type":"InstanceStart"})
        )
    );
    assert_eq!(records[12], ("PATCH /vm".into(), json!({"state":"Paused"})));
    assert_eq!(
        records[14],
        ("PATCH /vm".into(), json!({"state":"Resumed"}))
    );
    assert_eq!(records[18].1["resume_vm"], false);
    fixture.finish().await;
}

#[tokio::test]
async fn foreign_uid_pid_symlinks_and_invalid_endpoint_never_send_http() {
    let fixture = Fixture::new(Reply::Success).await;
    for peer in [
        PeerIdentity {
            pid: fixture.peer.pid + 1,
            ..fixture.peer
        },
        PeerIdentity {
            uid: fixture.peer.uid + 1,
            ..fixture.peer
        },
    ] {
        let error = ApiClient::new(fixture.socket.clone(), peer, Duration::from_secs(1))
            .unwrap()
            .start()
            .await
            .unwrap_err();
        assert_eq!(error.dispatch, DispatchState::NotSent);
    }
    let link = fixture.directory.as_ref().unwrap().path().join("link.sock");
    std::os::unix::fs::symlink(&fixture.socket, &link).unwrap();
    assert_eq!(
        ApiClient::new(link, fixture.peer, Duration::from_secs(1))
            .unwrap()
            .start()
            .await
            .unwrap_err()
            .dispatch,
        DispatchState::NotSent
    );
    assert!(
        ApiClient::new(
            PathBuf::from("relative"),
            fixture.peer,
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(
        ApiClient::new(
            fixture.socket.clone(),
            PeerIdentity {
                pid: 0,
                ..fixture.peer
            },
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(fixture.records.lock().await.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn wrong_instance_version_or_state_cannot_authorize_an_operation() {
    for reply in [
        Reply::WrongIdentity,
        Reply::WrongVersion,
        Reply::WrongState,
        Reply::IdentityEof,
    ] {
        let fixture = Fixture::new(reply).await;
        let error = fixture.client().start().await.unwrap_err();
        assert_eq!(error.dispatch, DispatchState::NotSent);
        assert_eq!(fixture.records.lock().await.len(), 1);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn explicit_refusal_is_redacted_and_never_retried() {
    let fixture = Fixture::new(Reply::Rejected).await;
    let error = fixture.client().start().await.unwrap_err();
    assert_eq!(error.dispatch, DispatchState::Rejected);
    assert_eq!(error.error.code, ErrorCode::InvalidRequest);
    assert!(!error.to_string().contains("private-host-path-and-secret"));
    assert_eq!(fixture.records.lock().await.len(), 2);
    fixture.finish().await;
}

#[tokio::test]
async fn eof_wrong_ack_and_both_body_limits_remain_uncertain() {
    for reply in [
        Reply::Eof,
        Reply::WrongSuccess,
        Reply::Oversized,
        Reply::ChunkedOversized,
        Reply::InvalidNoContent,
    ] {
        let fixture = Fixture::new(reply).await;
        let error = fixture.client().start().await.unwrap_err();
        assert_eq!(error.dispatch, DispatchState::Uncertain);
        assert!(!error.error.retryable);
        assert_eq!(fixture.records.lock().await.len(), 2);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn one_deadline_preserves_whether_the_actual_mutation_was_dispatched() {
    for (reply, dispatch) in [
        (Reply::IdentityStall, DispatchState::NotSent),
        (Reply::MutationStall, DispatchState::Uncertain),
    ] {
        let fixture = Fixture::new(reply).await;
        let client = ApiClient::new(
            fixture.socket.clone(),
            fixture.peer,
            Duration::from_millis(250),
        )
        .unwrap();
        let started = tokio::time::Instant::now();
        let error = client.start().await.unwrap_err();
        assert_eq!(error.dispatch, dispatch);
        assert_eq!(error.error.code, ErrorCode::DeadlineExceeded);
        assert!(started.elapsed() < Duration::from_secs(2));
        fixture.finish().await;
    }
}
