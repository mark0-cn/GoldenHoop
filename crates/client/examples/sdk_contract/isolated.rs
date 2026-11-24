use super::*;

async fn exercise(client: &Client, parent: Uuid, kernel: bool) -> Result<()> {
    let request = CreateIsolatedSession::default();
    let key = Uuid::new_v4().to_string();
    let value = client
        .create_isolated_session(parent, &request, &key)
        .await?;
    let child = value.sandbox.id;
    client
        .wait_operation(value.operation.id, Duration::from_secs(30))
        .await?;
    assert_eq!(
        client
            .create_isolated_session(parent, &request, &key)
            .await?
            .sandbox
            .id,
        child
    );
    let scope = client.sandbox_scope(child).await?;
    assert_eq!(scope.parent_id, Some(parent));
    assert_eq!(scope.root_id, parent);
    assert_eq!(scope.depth, 1);
    assert_eq!(
        client.isolated_sessions(parent, None, 1).await?.items[0].id,
        child
    );
    assert_eq!(
        client.sandbox_scope(parent).await?.allocated_to_children,
        ResourceLimits::default()
    );
    client.write_file(parent, "private", b"parent").await?;
    assert!(
        matches!(client.read_file(child,"private",16).await,Err(Error::Api(error)) if error.code==ErrorCode::NotFound)
    );
    client.write_file(child, "private", b"child").await?;
    let command = CommandSpec::new([
        "python3",
        "-c",
        "open('/workspace/once','a').write('1');print('child')",
    ]);
    let command_key = Uuid::new_v4().to_string();
    let first = client.run_with_key(child, &command, &command_key).await?;
    let replay = client.run_with_key(child, &command, &command_key).await?;
    assert_eq!(replay.execution.id, first.execution.id);
    assert_eq!(replay.stdout, b"child\n");
    assert_eq!(client.read_file(child, "once", 16).await?, b"1");
    assert_eq!(client.read_file(parent, "private", 16).await?, b"parent");
    if kernel {
        let context = client
            .create_code_context(
                child,
                &CodeContextSpec::default(),
                &Uuid::new_v4().to_string(),
            )
            .await?;
        client
            .wait_code_context_ready(context.id, Duration::from_secs(30))
            .await?;
        client
            .run_code(context.id, &CodeRunSpec::new("child_value=40"))
            .await?;
        let output = client
            .run_code(context.id, &CodeRunSpec::new("print(child_value+2)"))
            .await?;
        assert_eq!(output.stdout, "42\n");
        client
            .close_code_context(context.id, &Uuid::new_v4().to_string())
            .await?;
        client
            .wait_code_context_closed(context.id, Duration::from_secs(30))
            .await?;
    }
    let mut extra = client
        .isolated_lease(
            parent,
            &CreateIsolatedSession {
                feature_limit: Some(
                    [Capability::Commands, Capability::Files]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
        )
        .await?;
    extra.close().await?;
    extra.close().await?;
    assert_eq!(
        client.sandbox(extra.id()).await?.cleanup,
        CleanupState::Complete
    );
    let operation = client.terminate(child, &Uuid::new_v4().to_string()).await?;
    client
        .wait_operation(operation.id, Duration::from_secs(30))
        .await?;
    assert_eq!(client.sandbox(parent).await?.state, SandboxState::Running);
    assert_eq!(
        client.sandbox_scope(parent).await?.allocated_to_children,
        ResourceLimits {
            cpu_millis: 0,
            memory_bytes: 0,
            pids: 0
        }
    );
    Ok(())
}

pub async fn run(
    client: &Client,
    profile: &str,
    image: &str,
    kernel: bool,
) -> std::result::Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut request = CreateSandbox::new(profile, image);
    request.ttl_seconds = 300;
    request.child_budget = Some(ResourceLimits {
        cpu_millis: 2000,
        memory_bytes: 2 * 1024 * 1024 * 1024,
        pids: 512,
    });
    request
        .required_capabilities
        .insert(Capability::IsolatedSessions);
    let mut parent = client.lease(&request).await?;
    let result = std::panic::AssertUnwindSafe(tokio::time::timeout(
        Duration::from_secs(100),
        exercise(client, parent.id(), kernel),
    ))
    .catch_unwind()
    .await;
    parent.close().await?;
    assert_eq!(
        client.sandbox(parent.id()).await?.cleanup,
        CleanupState::Complete
    );
    match result {
        Ok(value) => value??,
        Err(error) => std::panic::resume_unwind(error),
    };
    Ok(
        serde_json::json!({"result":"passed","cleanup":"complete","parent_id":parent.id(),"code_context":kernel,
        "cases":["create_replay","scope_and_pages","workspace_isolation","command_replay_once","narrowed_child_lease","independent_child_delete","confirmed_tree_cleanup"]}),
    )
}
