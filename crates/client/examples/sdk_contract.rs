//! Actual API contract. The outer harness owns the server/installation.
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{FutureExt, StreamExt};
use goldenhoop_client::*;
use uuid::Uuid;
#[path = "sdk_contract/contexts.rs"]
mod contexts;

fn append_session_output(bytes: &mut Vec<u8>, event: &ExecutionEvent) {
    if event.kind == EventKind::Stdout {
        bytes.extend(
            STANDARD
                .decode(event.data["data"].as_str().unwrap())
                .unwrap(),
        );
    }
}
async fn socket_output(
    socket: &mut SessionSocket,
    bytes: &mut Vec<u8>,
    marker: &[u8],
) -> Result<()> {
    while !bytes.windows(marker.len()).any(|value| value == marker) {
        match socket.recv().await? {
            Some(SessionSocketServerMessage::Event(event)) => append_session_output(bytes, &event),
            Some(SessionSocketServerMessage::Control(receipt))
                if matches!(
                    receipt.state,
                    SessionControlState::Unknown | SessionControlState::Rejected
                ) =>
            {
                return Err(Error::Api(receipt.error.unwrap()));
            }
            None => return Err(Error::Protocol("session ended before expected output")),
            _ => {}
        }
    }
    Ok(())
}

async fn interactive_sessions(client: &Client, sandbox: Uuid) -> Result<()> {
    let pipe = client
        .create_session(sandbox, &SessionSpec::shell(), &Uuid::new_v4().to_string())
        .await?;
    let pipe_id = pipe.execution.id;
    let write = SessionControl {
        sequence: 1,
        action: SessionAction::Write {
            data_base64: STANDARD.encode(b"v=rust; printf '%s' \"$v\"\n"),
        },
    };
    client.session_control(pipe_id, &write).await?;
    assert_eq!(
        client
            .wait_session_control(pipe_id, 1, Duration::from_secs(20))
            .await?
            .state,
        SessionControlState::Applied
    );
    client
        .session_control(
            pipe_id,
            &SessionControl {
                sequence: 2,
                action: SessionAction::CloseInput,
            },
        )
        .await?;
    let mut events = client.events(pipe_id, None).await?;
    let mut output = Vec::new();
    let mut completed = false;
    while let Some(event) = events.next().await {
        let event = event?;
        append_session_output(&mut output, &event);
        if event.kind == EventKind::Completed {
            let execution: Execution = serde_json::from_value(event.data).unwrap();
            assert_eq!(execution.state, ExecutionState::Succeeded);
            assert_eq!(execution.cleanup, CleanupState::Complete);
            completed = true;
        }
    }
    assert!(completed);
    assert_eq!(output, b"rust");

    let code = "import os,sys,tty,termios; assert all(os.isatty(fd) for fd in (0,1,2)); tty.setraw(0); print('READY',flush=True); n=0\nfor data in sys.stdin.buffer:\n if data==b'quit\\n': break\n n+=1; print('COUNT:%d:%s'%(n,data.hex()),flush=True)\nprint('FINAL:%d:%d:%d'%(n,*termios.tcgetwinsize(0)),flush=True)";
    let mut spec = SessionSpec {
        command: CommandSpec::new(["python3", "-c", code]),
        terminal: Some(TerminalSize {
            rows: 24,
            columns: 80,
        }),
    };
    spec.command.timeout_seconds = 30;
    let key = Uuid::new_v4().to_string();
    let created = client.create_session(sandbox, &spec, &key).await?;
    let id = created.execution.id;
    assert_eq!(
        client
            .create_session(sandbox, &spec, &key)
            .await?
            .execution
            .id,
        id
    );
    let mut socket = client.session_socket(id, 0).await?;
    let mut output = Vec::new();
    socket_output(&mut socket, &mut output, b"READY\n").await?;
    let input = SessionControl {
        sequence: 1,
        action: SessionAction::Write {
            data_base64: STANDARD.encode(b"\x00\xff\n"),
        },
    };
    socket.control(&input).await?;
    socket_output(&mut socket, &mut output, b"COUNT:1:00ff0a\n").await?;
    let cursor = socket.cursor();
    socket.close().await?;
    assert_eq!(
        client.session(id).await?.execution.state,
        ExecutionState::Running
    );
    let mut socket = client.session_socket(id, cursor).await?;
    socket.control(&input).await?;
    socket
        .control(&SessionControl {
            sequence: 2,
            action: SessionAction::Resize {
                size: TerminalSize {
                    rows: 40,
                    columns: 100,
                },
            },
        })
        .await?;
    socket
        .control(&SessionControl {
            sequence: 3,
            action: SessionAction::Write {
                data_base64: STANDARD.encode(b"quit\n"),
            },
        })
        .await?;
    let mut completion = None;
    while let Some(message) = socket.recv().await? {
        if let SessionSocketServerMessage::Event(event) = message {
            append_session_output(&mut output, &event);
            if event.kind == EventKind::Completed {
                completion = Some(serde_json::from_value::<Execution>(event.data).unwrap());
            }
        }
    }
    assert_eq!(completion.unwrap().state, ExecutionState::Succeeded);
    assert!(
        output
            .windows(b"FINAL:1:40:100\n".len())
            .any(|bytes| bytes == b"FINAL:1:40:100\n")
    );
    assert_eq!(
        client.session_control_status(id, 1).await?.state,
        SessionControlState::Applied
    );
    assert!(
        client
            .list_sessions(Some(sandbox), None, 100)
            .await?
            .items
            .iter()
            .any(|session| session.execution.id == id)
    );
    Ok(())
}

async fn exercise(client: &Client, id: Uuid) -> Result<Uuid> {
    assert!(
        client
            .diagnostics(id)
            .await?
            .runtime
            .unwrap()
            .usage
            .is_some()
    );
    assert!(
        client
            .list(None, 100)
            .await?
            .items
            .iter()
            .any(|v| v.id == id)
    );
    let binary = [0, 255, 128, b'\n', b'x'];
    client.write_file(id, "rust.bin", &binary).await?;
    assert_eq!(client.read_file(id, "rust.bin", 100).await?, binary);
    assert!(client.list_files(id, ".").await?.iter().any(|v| {
        std::path::Path::new(&v.path).file_name() == Some(std::ffi::OsStr::new("rust.bin"))
    }));
    assert!(matches!(
        client.read_file(id, "../etc/passwd", 100).await,
        Err(Error::Api(_))
    ));

    let result = client
        .run(
            id,
            &CommandSpec::new(["printf", "%s", "$HOME; echo not-a-shell"]),
        )
        .await?;
    assert_eq!(result.execution.state, ExecutionState::Succeeded);
    assert_eq!(result.stdout, b"$HOME; echo not-a-shell");
    let result = client
        .run(
            id,
            &CommandSpec::new([
                "python3",
                "-c",
                "import os;os.write(1,b'\\x00\\xff');os.write(2,b'err');raise SystemExit(23)",
            ]),
        )
        .await?;
    assert_eq!(result.execution.exit_code, Some(23));
    assert_eq!(result.execution.state, ExecutionState::Failed);
    assert_eq!(result.stdout, [0, 255]);
    assert_eq!(result.stderr, b"err");

    let once = CommandSpec::new([
        "python3",
        "-c",
        "with open('once','ab') as f:f.write(b'1')\nprint('once')",
    ]);
    let key = Uuid::new_v4().to_string();
    let first = client.run_with_key(id, &once, &key).await?;
    let repeated = client.run_with_key(id, &once, &key).await?;
    assert_eq!(first.execution.id, repeated.execution.id);
    assert_eq!(client.read_file(id, "once", 100).await?, b"1");

    let mut slow = CommandSpec::new(["python3", "-c", "import time;time.sleep(30)"]);
    slow.timeout_seconds = 1;
    assert_eq!(
        client.run(id, &slow).await?.execution.state,
        ExecutionState::TimedOut
    );
    slow.timeout_seconds = 30;
    let execution = client.start(id, &slow, &Uuid::new_v4().to_string()).await?;
    client.cancel(execution.id).await?;
    assert_eq!(
        client
            .wait_execution(execution.id, Duration::from_secs(10))
            .await?
            .state,
        ExecutionState::Cancelled
    );

    let script = CommandSpec::new([
        "python3",
        "-c",
        "import time;print('a',flush=True);time.sleep(0.5);print('b',flush=True)",
    ]);
    let execution = client
        .start(id, &script, &Uuid::new_v4().to_string())
        .await?;
    let mut events = client.events(execution.id, None).await?;
    let cursor = loop {
        let event = events
            .next()
            .await
            .ok_or(Error::Protocol("missing first output"))??;
        if event.kind == EventKind::Stdout {
            break event.sequence;
        }
    };
    drop(events);
    let mut resumed = client.events(execution.id, Some(cursor)).await?;
    let mut completed = false;
    let mut last = cursor;
    while let Some(event) = resumed.next().await {
        let event = event?;
        assert_eq!(event.sequence, last + 1);
        last = event.sequence;
        if event.kind == EventKind::Completed {
            completed = true;
            break;
        }
    }
    assert!(completed);
    for action in ["pause", "resume"] {
        let key = Uuid::new_v4().to_string();
        let operation = if action == "pause" {
            client.pause(id, &key).await?
        } else {
            client.resume(id, &key).await?
        };
        client
            .wait_operation(operation.id, Duration::from_secs(10))
            .await?;
    }
    client.remove_file(id, "rust.bin").await?;
    assert!(
        matches!(client.read_file(id,"rust.bin",100).await,Err(Error::Api(error)) if error.code==ErrorCode::NotFound)
    );
    interactive_sessions(client, id).await?;
    let artifact = client
        .capture_artifact(
            id,
            &CreateArtifact {
                path: "once".into(),
                name: "rust-sdk.bin".into(),
            },
        )
        .await?;
    Ok(artifact.id)
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(
        &std::env::var("GOLDENHOOP_ENDPOINT")?,
        &std::env::var("GOLDENHOOP_API_TOKEN")?,
    )?;
    let profile = std::env::var("GOLDENHOOP_TEST_PROFILE")?;
    assert!(
        client
            .profiles()
            .await?
            .iter()
            .any(|p| p.id == profile && p.availability == Availability::Available)
    );
    let request = CreateSandbox::new(profile.clone(), std::env::var("GOLDENHOOP_TEST_IMAGE")?);
    let mut lease = client.lease(&request).await?;
    let id = lease.id();
    let result = std::panic::AssertUnwindSafe(tokio::time::timeout(
        Duration::from_secs(60),
        exercise(&client, id),
    ))
    .catch_unwind()
    .await;
    // Cleanup runs before propagating either an operation failure or timeout.
    lease.close().await?;
    lease.close().await?;
    assert_eq!(client.sandbox(id).await?.cleanup, CleanupState::Complete);
    assert!(client.diagnostics(id).await?.runtime.is_none());
    let artifact_id = match result {
        Ok(result) => result??,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    let verification = std::panic::AssertUnwindSafe(async {
        assert_eq!(client.artifact_bytes(artifact_id).await?, b"1");
        assert!(
            client
                .list_artifacts(Some(id), None, 100)
                .await?
                .items
                .iter()
                .any(|artifact| artifact.id == artifact_id)
        );
        Ok::<_, Error>(())
    })
    .catch_unwind()
    .await;
    let deleted = client
        .delete_artifact(artifact_id, &Uuid::new_v4().to_string())
        .await?;
    client
        .wait_operation(deleted.id, Duration::from_secs(60))
        .await?;
    assert_eq!(
        client.artifact(artifact_id).await?.cleanup,
        CleanupState::Complete
    );
    match verification {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    let code_contexts = if let Ok(image) = std::env::var("GOLDENHOOP_TEST_KERNEL_IMAGE") {
        Some(contexts::run(&client, &profile, &image).await?)
    } else {
        None
    };
    println!(
        "{}",
        serde_json::json!({"client":"rust","result":"passed","sandbox_id":id,"cleanup":"complete",
        "cases":["profiles","lease","binary_files","traversal_refusal","literal_argv","nonzero_binary_output","idempotency","timeout","cancel","sse_resume","pause_resume","confirmed_cleanup","retained_artifact_and_confirmed_delete"],"code_contexts":code_contexts})
    );
    Ok(())
}
