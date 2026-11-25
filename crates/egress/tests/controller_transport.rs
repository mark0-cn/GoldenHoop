use goldenhoop_egress::controller::{CallError, Client, Envelope, MAX_FRAME, Reply, Request};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    time::Instant,
};

async fn frame(server: &mut BufReader<tokio::io::DuplexStream>) -> Value {
    let mut bytes = Vec::new();
    assert!(server.read_until(b'\n', &mut bytes).await.unwrap() > 0);
    assert_eq!(bytes.last(), Some(&b'\n'));
    serde_json::from_slice::<Envelope>(&bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[tokio::test]
async fn fragmented_acknowledgements_preserve_identity_remote_error_and_null_result() {
    let (local, remote) = tokio::io::duplex(4096);
    let (reader, writer) = tokio::io::split(local);
    let mut client = Client::new(reader, writer);
    let server = tokio::spawn(async move {
        let mut remote = BufReader::new(remote);
        for id in 1..=3 {
            let request = frame(&mut remote).await;
            assert_eq!(request, json!({"id":id,"command":{"operation":"inspect"}}));
            let reply = match id {
                1 => json!({"id":id,"result":{"revision":7}}),
                2 => json!({"id":id,"error":ApiError::new(ErrorCode::Conflict,"revision differs")}),
                _ => json!({"id":id,"result":null}),
            };
            let mut bytes = serde_json::to_vec(&reply).unwrap();
            bytes.push(b'\n');
            let middle = bytes.len() / 2;
            remote.write_all(&bytes[..middle]).await.unwrap();
            tokio::task::yield_now().await;
            remote.write_all(&bytes[middle..]).await.unwrap();
        }
    });
    assert!(
        matches!(client.call(Request::Inspect {},deadline()).await.unwrap(),Reply::Result(value) if value==json!({"revision":7}))
    );
    assert!(!client.is_uncertain());
    assert!(
        matches!(client.call(Request::Inspect {},deadline()).await.unwrap(),Reply::Error(error) if error.code==ErrorCode::Conflict)
    );
    assert!(!client.is_uncertain());
    assert!(matches!(
        client.call(Request::Inspect {}, deadline()).await.unwrap(),
        Reply::Result(Value::Null)
    ));
    assert!(!client.is_uncertain());
    server.await.unwrap();
}

#[tokio::test]
async fn malformed_mismatched_truncated_and_oversized_replies_fence_the_channel() {
    let mut cases = vec![
        (
            b"{\"id\":1,\"result\":true}\n{\"id\":2,\"result\":true}\n".to_vec(),
            CallError::InvalidReply,
        ),
        (
            b"{\"id\":2,\"result\":true}\n".to_vec(),
            CallError::InvalidReply,
        ),
        (
            b"{\"id\":1,\"result\":true,\"extra\":0}\n".to_vec(),
            CallError::InvalidReply,
        ),
        (
            b"{\"id\":2,\"id\":1,\"result\":true}\n".to_vec(),
            CallError::InvalidReply,
        ),
        (
            b"{\"id\":1,\"result\":true,\"error\":{}}\n".to_vec(),
            CallError::InvalidReply,
        ),
        (
            b"{\"id\":1,\"result\":true}".to_vec(),
            CallError::InvalidReply,
        ),
        (vec![0xff, b'\n'], CallError::InvalidReply),
        (Vec::new(), CallError::EndOfStream),
    ];
    cases.push((vec![b' '; MAX_FRAME as usize + 1], CallError::ReplyTooLarge));
    for (reply, expected) in cases {
        let (local, remote) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(local);
        let mut client = Client::new(reader, writer);
        let server = tokio::spawn(async move {
            let mut remote = BufReader::new(remote);
            assert_eq!(frame(&mut remote).await["id"], 1);
            remote.write_all(&reply).await.unwrap();
        });
        assert_eq!(
            client
                .call(Request::Install {}, deadline())
                .await
                .unwrap_err(),
            expected
        );
        assert!(client.is_uncertain());
        assert_eq!(
            client
                .call(
                    Request::Renew {
                        expected_revision: 1
                    },
                    deadline()
                )
                .await
                .unwrap_err(),
            CallError::UncertainChannel
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn deadline_after_dispatch_withholds_further_renewals() {
    let (local, remote) = tokio::io::duplex(4096);
    let (reader, writer) = tokio::io::split(local);
    let mut client = Client::new(reader, writer);
    let mut remote = BufReader::new(remote);
    let (result, request) = tokio::join!(
        client.call(
            Request::Install {},
            Instant::now() + Duration::from_millis(150)
        ),
        frame(&mut remote)
    );
    assert_eq!(request["command"]["operation"], "install");
    assert_eq!(result.unwrap_err(), CallError::Deadline);
    assert!(client.is_uncertain());
    assert_eq!(
        client
            .call(
                Request::Renew {
                    expected_revision: 1
                },
                deadline()
            )
            .await
            .unwrap_err(),
        CallError::UncertainChannel
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), remote.read_u8())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn cancelling_an_accepted_call_does_not_replay_it_or_renew_its_lease() {
    let (local, remote) = tokio::io::duplex(4096);
    let (reader, writer) = tokio::io::split(local);
    let mut client = Client::new(reader, writer);
    let mut remote = BufReader::new(remote);
    {
        let call = client.call(Request::Install {}, deadline());
        tokio::pin!(call);
        tokio::select! {
            result=&mut call=>panic!("controller has not replied: {result:?}"),
            request=frame(&mut remote)=>assert_eq!(request["command"]["operation"],"install"),
        }
    }
    assert!(client.is_uncertain());
    assert_eq!(
        client
            .call(
                Request::Renew {
                    expected_revision: 1
                },
                deadline()
            )
            .await
            .unwrap_err(),
        CallError::UncertainChannel
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), remote.read_u8())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn cancelling_a_partial_write_also_fences_the_channel() {
    let (local, mut remote) = tokio::io::duplex(16);
    let (reader, writer) = tokio::io::split(local);
    let mut client = Client::new(reader, writer);
    {
        let call = client.call(
            Request::Resolve {
                wire: vec![0; 4096],
                tcp: false,
            },
            deadline(),
        );
        tokio::pin!(call);
        tokio::select! {
            result=&mut call=>panic!("request exceeds duplex capacity: {result:?}"),
            byte=remote.read_u8()=>assert_eq!(byte.unwrap(),b'{'),
        }
    }
    assert!(client.is_uncertain());
    assert_eq!(
        client
            .call(Request::Inspect {}, deadline())
            .await
            .unwrap_err(),
        CallError::UncertainChannel
    );
}

#[tokio::test]
async fn local_rejection_writes_nothing_and_preserves_the_first_sequence() {
    let (local, remote) = tokio::io::duplex(4096);
    let (reader, writer) = tokio::io::split(local);
    let mut client = Client::new(reader, writer);
    assert_eq!(
        client
            .call(
                Request::DnsSource {
                    name: "a".repeat(MAX_FRAME as usize),
                    aaaa: false
                },
                deadline()
            )
            .await
            .unwrap_err(),
        CallError::InvalidRequest
    );
    assert!(!client.is_uncertain());
    assert_eq!(
        client
            .call(Request::Install {}, Instant::now())
            .await
            .unwrap_err(),
        CallError::ExpiredDeadline
    );
    assert!(!client.is_uncertain());
    let server = tokio::spawn(async move {
        let mut remote = BufReader::new(remote);
        assert_eq!(
            frame(&mut remote).await,
            json!({"id":1,"command":{"operation":"inspect"}})
        );
        remote
            .write_all(b"{\"id\":1,\"result\":true}\n")
            .await
            .unwrap();
    });
    assert!(matches!(
        client.call(Request::Inspect {}, deadline()).await.unwrap(),
        Reply::Result(Value::Bool(true))
    ));
    server.await.unwrap();
}

#[test]
fn shared_commands_keep_dns_defaults_and_refuse_unexpected_control_fields() {
    assert!(matches!(
        serde_json::from_value::<Envelope>(
            json!({"id":0,"command":{"operation":"resolve","wire":[1]}})
        )
        .unwrap()
        .command,
        Request::Resolve { tcp: false, .. }
    ));
    assert!(matches!(
        serde_json::from_value::<Envelope>(
            json!({"id":0,"command":{"operation":"dns_source","name":"example.test"}})
        )
        .unwrap()
        .command,
        Request::DnsSource { aaaa: false, .. }
    ));
    assert!(
        serde_json::from_value::<Envelope>(
            json!({"id":1,"command":{"operation":"inspect","expected_revision":2}})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<Envelope>(
            json!({"id":1,"command":{"operation":"install","expected_revision":2}})
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<Envelope>(
            json!({"id":1,"command":{"operation":"inspect"},"extra":0})
        )
        .is_err()
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_controller_stdio_refuses_unopened_operations_and_exits_after_eof() {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_goldenhoop-egress"))
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut client = Client::new(child.stdout.take().unwrap(), child.stdin.take().unwrap());
    let identity = goldenhoop_egress::NetworkIdentity {
        installation_id: uuid::Uuid::new_v4(),
        sandbox_id: uuid::Uuid::new_v4(),
        generation: uuid::Uuid::new_v4(),
        profile: "local-runc-dev".into(),
    };
    let expired = goldenhoop_egress::native::NativeBridgePlan {
        allocation: goldenhoop_egress::Allocation {
            installation_id: identity.installation_id,
            sandbox_id: identity.sandbox_id,
            generation: identity.generation,
            bridge: identity.bridge_name(),
            ifindex: 72,
        },
        identity,
        provisioning_token: uuid::Uuid::new_v4(),
        expires_at: chrono::Utc::now() - chrono::Duration::seconds(1),
    };
    for (request, expected) in [
        (Request::Inspect {}, ErrorCode::InvalidState),
        (
            Request::Renew {
                expected_revision: 7,
            },
            ErrorCode::InvalidState,
        ),
        (
            Request::BindNative { plan: expired },
            ErrorCode::DeadlineExceeded,
        ),
    ] {
        assert!(
            matches!(client.call(request,deadline()).await.unwrap(),Reply::Error(error) if error.code==expected)
        );
        assert!(!client.is_uncertain());
    }
    drop(client);
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn actual_collection_only_binary_refuses_enforcement_before_any_allocation() {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_goldenhoop-egress"))
        .arg("--collection-only")
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut client = Client::new(child.stdout.take().unwrap(), child.stdin.take().unwrap());
    for command in [
        Request::Install {},
        Request::Apply {
            expected_revision: 0,
            config: Default::default(),
        },
        Request::Renew {
            expected_revision: 0,
        },
        Request::Quarantine {
            expected_revision: 0,
        },
        Request::EnableEthernet {
            expected_revision: 0,
        },
    ] {
        assert!(
            matches!(client.call(command,deadline()).await.unwrap(),Reply::Error(error) if error.code==ErrorCode::Forbidden)
        );
        assert!(!client.is_uncertain());
    }
    assert!(
        matches!(client.call(Request::Inspect {},deadline()).await.unwrap(),Reply::Error(error) if error.code==ErrorCode::InvalidState)
    );
    drop(client);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}
