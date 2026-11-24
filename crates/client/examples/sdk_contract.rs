//! Actual API contract. The outer harness owns the server/installation.
use std::time::Duration;

use futures_util::{FutureExt, StreamExt};
use goldenhoop_client::*;
use uuid::Uuid;

async fn exercise(client: &Client, id: Uuid) -> Result<()> {
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
    Ok(())
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
    let request = CreateSandbox::new(profile, std::env::var("GOLDENHOOP_TEST_IMAGE")?);
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
    match result {
        Ok(result) => result??,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    println!(
        "{}",
        serde_json::json!({"client":"rust","result":"passed","sandbox_id":id,"cleanup":"complete",
        "cases":["profiles","lease","binary_files","traversal_refusal","literal_argv","nonzero_binary_output","idempotency","timeout","cancel","sse_resume","pause_resume","confirmed_cleanup"]})
    );
    Ok(())
}
