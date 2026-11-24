use futures_util::{FutureExt, StreamExt};
use goldenhoop_client::*;
use std::time::Duration;
use uuid::Uuid;

async fn exercise(client: &Client, sandbox: Uuid) -> Result<()> {
    let key = Uuid::new_v4().to_string();
    let context = client
        .create_code_context(sandbox, &CodeContextSpec::default(), &key)
        .await?;
    assert_eq!(
        client
            .create_code_context(sandbox, &CodeContextSpec::default(), &key)
            .await?
            .id,
        context.id
    );
    let id = context.id;
    client
        .wait_code_context_ready(id, Duration::from_secs(30))
        .await?;
    let output = client
        .run_code(
            id,
            &CodeRunSpec::new(
                "import os\nassert 20000<=os.getuid()<20004 and os.getgid()==1000\nvalue=40",
            ),
        )
        .await?;
    assert_eq!(output.run.state, CodeRunState::KernelSucceeded);
    let mut spec = CodeRunSpec::new(
        "value+=1\nopen('/workspace/rust-code-once','a').write('1')\nprint(value)\nvalue",
    );
    spec.timeout_seconds = 15;
    let key = Uuid::new_v4().to_string();
    let output = client.run_code_with_key(id, &spec, &key).await?;
    let replay = client.run_code_with_key(id, &spec, &key).await?;
    assert_eq!(output.run.id, replay.run.id);
    assert_eq!(output.run.events_after, replay.run.events_after);
    assert_eq!(replay.stdout, "41\n");
    assert_eq!(client.read_file(sandbox, "rust-code-once", 16).await?, b"1");
    let output = client
        .run_code(id, &CodeRunSpec::new("print(value+1)\nvalue+1"))
        .await?;
    assert_eq!(output.stdout, "42\n");
    assert!(
        output
            .results
            .iter()
            .any(|value| value["data"]["text/plain"] == "42")
    );
    let output = client
        .run_code(
            id,
            &CodeRunSpec::new("raise ValueError('expected Rust SDK exception')"),
        )
        .await?;
    assert_eq!(output.run.state, CodeRunState::KernelFailed);
    assert!(
        output
            .errors
            .iter()
            .any(|value| value["ename"] == "ValueError")
    );
    assert_eq!(
        client.code_context(id).await?.state,
        CodeContextState::Ready
    );
    let second = client
        .create_code_context(
            sandbox,
            &CodeContextSpec::default(),
            &Uuid::new_v4().to_string(),
        )
        .await?
        .id;
    client
        .wait_code_context_ready(second, Duration::from_secs(30))
        .await?;
    assert_eq!(
        client
            .run_code(second, &CodeRunSpec::new("print('value' in globals())"))
            .await?
            .stdout,
        "False\n"
    );
    client
        .close_code_context(second, &Uuid::new_v4().to_string())
        .await?;
    client
        .wait_code_context_closed(second, Duration::from_secs(30))
        .await?;
    let accepted=client.start_code(id,&CodeRunSpec::new("import time\nprint('first',flush=True)\ntime.sleep(.3)\nprint('second',flush=True)"),&Uuid::new_v4().to_string()).await?;
    let mut stream = client
        .code_context_events(id, accepted.events_after)
        .await?;
    let cursor = loop {
        let event = stream
            .next()
            .await
            .ok_or(Error::Protocol("missing code stdout"))??;
        if event.run_id == Some(accepted.id) && event.kind == CodeContextEventKind::Stdout {
            break event.sequence;
        }
    };
    drop(stream);
    let mut stream = client.code_context_events(id, cursor).await?;
    let mut last = cursor;
    loop {
        let event = stream
            .next()
            .await
            .ok_or(Error::Protocol("missing code result after resume"))??;
        assert_eq!(event.sequence, last + 1);
        last = event.sequence;
        if event.run_id == Some(accepted.id) && event.kind == CodeContextEventKind::RunCompleted {
            assert_eq!(event.data["state"], "kernel_succeeded");
            break;
        }
    }
    drop(stream);
    let active = client
        .start_code(
            id,
            &CodeRunSpec::new("print('armed',flush=True)\ntime.sleep(60)"),
            &Uuid::new_v4().to_string(),
        )
        .await?;
    let mut stream = client.code_context_events(id, active.events_after).await?;
    loop {
        let event = stream
            .next()
            .await
            .ok_or(Error::Protocol("missing active code marker"))??;
        if event.run_id == Some(active.id) && event.kind == CodeContextEventKind::Stdout {
            break;
        }
    }
    drop(stream);
    let queued = client
        .start_code(
            id,
            &CodeRunSpec::new("open('/workspace/rust-must-not-run','w').write('bad')"),
            &Uuid::new_v4().to_string(),
        )
        .await?;
    client.cancel_code_run(active.id).await?;
    client
        .wait_code_context_closed(id, Duration::from_secs(30))
        .await?;
    assert_eq!(
        client.code_run(active.id).await?.state,
        CodeRunState::Cancelled
    );
    assert_eq!(
        client.code_run(queued.id).await?.state,
        CodeRunState::Cancelled
    );
    assert!(
        matches!(client.read_file(sandbox,"rust-must-not-run",16).await,Err(Error::Api(error)) if error.code==ErrorCode::NotFound)
    );
    let mut history = client.code_context_events(id, active.events_after).await?;
    let mut closed = false;
    while let Some(event) = history.next().await {
        if event?.kind == CodeContextEventKind::Closed {
            closed = true;
        }
    }
    assert!(closed);
    let timeout = client
        .create_code_context(
            sandbox,
            &CodeContextSpec::default(),
            &Uuid::new_v4().to_string(),
        )
        .await?
        .id;
    client
        .wait_code_context_ready(timeout, Duration::from_secs(30))
        .await?;
    let mut spec = CodeRunSpec::new("import time;time.sleep(60)");
    spec.timeout_seconds = 1;
    assert_eq!(
        client.run_code(timeout, &spec).await?.run.state,
        CodeRunState::TimedOut
    );
    client
        .wait_code_context_closed(timeout, Duration::from_secs(30))
        .await?;
    let failed = client
        .create_code_context(
            sandbox,
            &CodeContextSpec::default(),
            &Uuid::new_v4().to_string(),
        )
        .await?
        .id;
    client
        .wait_code_context_ready(failed, Duration::from_secs(30))
        .await?;
    let unknown = client
        .run_code(failed, &CodeRunSpec::new("import os;os._exit(7)"))
        .await;
    let run = match unknown {
        Err(Error::CodeObservation(id, _)) => client.code_run(id).await?,
        _ => {
            return Err(Error::Protocol(
                "kernel crash was not an uncertain observation",
            ));
        }
    };
    assert_eq!(run.state, CodeRunState::Unknown);
    assert!(run.finished_at.is_some());
    assert_eq!(
        client
            .wait_code_context_closed(failed, Duration::from_secs(30))
            .await?
            .state,
        CodeContextState::Failed
    );
    assert!(
        client
            .list_code_contexts(Some(sandbox), None, 100)
            .await?
            .items
            .iter()
            .any(|context| context.id == id)
    );
    assert!(
        client
            .list_code_runs(id, None, 100)
            .await?
            .items
            .iter()
            .any(|run| run.id == active.id)
    );
    Ok(())
}

pub async fn run(
    client: &Client,
    profile: &str,
    image: &str,
) -> std::result::Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut request = CreateSandbox::new(profile, image);
    request.ttl_seconds = 360;
    request
        .required_capabilities
        .extend([Capability::CodeContexts, Capability::Artifacts]);
    let mut lease = client.lease(&request).await?;
    let sandbox = lease.id();
    let result =
        std::panic::AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(240), async {
            exercise(client, sandbox).await?;
            super::languages::exercise(client, sandbox, profile).await
        }))
        .catch_unwind()
        .await;
    lease.close().await?;
    assert_eq!(
        client.sandbox(sandbox).await?.cleanup,
        CleanupState::Complete
    );
    let languages = match result {
        Ok(value) => value??,
        Err(error) => std::panic::resume_unwind(error),
    };
    Ok(
        serde_json::json!({"sandbox_id":sandbox,"result":"passed","cleanup":"complete","languages":languages,"cases":["retained_state","idempotent_result_replay","rich_result","kernel_exception","independent_context","sse_resume","cancel_queued_code","timeout_collection","unknown_crash","durable_history","all_advertised_languages"]}),
    )
}
