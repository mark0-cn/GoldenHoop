//! Run only against a disposable/test installation. All resources are label-owned.
use std::{collections::BTreeMap, panic::AssertUnwindSafe, path::Path, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use futures_util::FutureExt;
use goldenhoop_docker::*;
use goldenhoop_protocol::*;
use goldenhoop_runtime::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn source_hashes(
    root: &Path,
    directory: &Path,
    hashes: &mut BTreeMap<String, String>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            source_hashes(root, &path, hashes)?;
        } else if matches!(
            path.extension().and_then(|v| v.to_str()),
            Some("rs" | "toml")
        ) {
            hashes.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                format!("{:x}", Sha256::digest(std::fs::read(&path)?)),
            );
        }
    }
    Ok(())
}

async fn execution(
    driver: &DockerDriver,
    handle: &RuntimeHandle,
    argv: &[&str],
) -> Result<Vec<ExecutionEvent>, Box<dyn std::error::Error>> {
    let id = Uuid::new_v4();
    driver
        .rpc(
            handle,
            &AgentRequest::Start {
                id,
                command: CommandSpec {
                    argv: argv.iter().map(|value| (*value).into()).collect(),
                    cwd: "/workspace".into(),
                    env: BTreeMap::new(),
                    timeout_seconds: 5,
                    max_output_bytes: 4096,
                },
            },
        )
        .await?;
    let mut events = Vec::new();
    let mut after = 0;
    for _ in 0..100 {
        if let AgentResponse::Events(packet) = driver
            .rpc(handle, &AgentRequest::Events { id, after })
            .await?
        {
            after = packet.last().map_or(after, |event| event.sequence);
            events.extend(packet);
        }
        if let AgentResponse::Execution(record) =
            driver.rpc(handle, &AgentRequest::Inspect { id }).await?
            && record.state.is_terminal()
        {
            assert_eq!(record.state, ExecutionState::Succeeded, "{record:?}");
            assert_eq!(record.cleanup, CleanupState::Complete);
            if let AgentResponse::Events(packet) = driver
                .rpc(handle, &AgentRequest::Events { id, after })
                .await?
            {
                events.extend(packet);
            }
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.kind == EventKind::Completed)
                    .count(),
                1
            );
            return Ok(events);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("execution result not observed".into())
}

fn sandbox(request: &CreateSandbox) -> Sandbox {
    let now = Utc::now();
    Sandbox {
        id: Uuid::new_v4(),
        profile: request.profile.clone(),
        image: request.image.clone(),
        state: SandboxState::Starting,
        cleanup: CleanupState::Pending,
        created_at: now,
        expires_at: now + chrono::Duration::seconds(request.ttl_seconds as i64),
        observed_at: None,
        resources: request.resources.clone(),
        metadata: Default::default(),
        reason: None,
    }
}

async fn contract(
    driver: &DockerDriver,
    config: &DockerConfig,
    workload_image: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let denied = DockerDriver::connect(DockerConfig {
        profile: DockerProfile::RuncDevelopment,
        allow_runc_development: false,
        ..config.clone()
    })
    .await?;
    assert_eq!(denied.probe().await.availability, Availability::Unavailable);
    let profile = driver.probe().await;
    assert_eq!(profile.availability, Availability::Available, "{profile:?}");
    let request: CreateSandbox = serde_json::from_value(serde_json::json!({
        "profile":config.profile.id(),"image":workload_image,"ttl_seconds":60,
        "resources":{"cpu_millis":1000,"memory_bytes":268435456,"pids":128}
    }))?;
    let record = sandbox(&request);
    let handle = driver.create(&record, &request).await?;
    let engine = bollard::Docker::connect_with_socket_defaults()?;
    let effective = engine
        .inspect_container(&handle.backend_ref, None)
        .await?
        .config
        .unwrap();
    assert_eq!(effective.healthcheck.unwrap().test.unwrap(), vec!["NONE"]);
    assert!(
        !effective
            .env
            .unwrap_or_default()
            .iter()
            .any(|value| value.starts_with("LD_PRELOAD=") && value != "LD_PRELOAD=")
    );
    let image = engine.inspect_image(workload_image).await?;
    if image.config.and_then(|config| config.healthcheck).is_some() {
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            driver
                .rpc(
                    &handle,
                    &AgentRequest::ReadFile {
                        path: "healthcheck-ran".into(),
                        max_bytes: 64
                    }
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
    }
    assert_eq!(driver.inspect(&handle).await?.state, ObservedState::Running);
    assert_eq!(
        driver.create(&record, &request).await?.backend_ref,
        handle.backend_ref
    );
    let data = STANDARD.encode([0_u8, 255, 10]);
    driver
        .rpc(
            &handle,
            &AgentRequest::WriteFile {
                path: "binary".into(),
                data_base64: data.clone(),
            },
        )
        .await?;
    assert!(
        matches!(driver.rpc(&handle, &AgentRequest::ReadFile {path:"binary".into(),max_bytes:64}).await?, AgentResponse::File { data_base64 } if data_base64 == data)
    );
    let events = execution(
        driver,
        &handle,
        &["printf", "%s", "$(touch /workspace/injected)"],
    )
    .await?;
    let actual = events
        .iter()
        .filter(|event| event.kind == EventKind::Stdout)
        .flat_map(|event| {
            STANDARD
                .decode(event.data["data"].as_str().unwrap())
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, b"$(touch /workspace/injected)");

    // Reconnect from a fresh worker using persisted labels and serialized handles.
    let restarted = DockerDriver::connect(config.clone()).await?;
    let handle: RuntimeHandle = serde_json::from_slice(&serde_json::to_vec(&handle)?)?;
    assert!(
        restarted
            .discover()
            .await?
            .iter()
            .any(|found| found.backend_ref == handle.backend_ref)
    );
    restarted.rpc(&handle, &AgentRequest::Ping).await?;

    // A different installation cannot delete this container, even with its Docker ID.
    let stranger = DockerDriver::connect(DockerConfig {
        installation_id: Uuid::new_v4(),
        ..config.clone()
    })
    .await?;
    assert_eq!(
        stranger.remove(&handle).await.unwrap_err().code,
        ErrorCode::Forbidden
    );
    assert_eq!(driver.inspect(&handle).await?.state, ObservedState::Running);
    driver.pause(&handle).await?;
    assert_eq!(
        driver.create(&record, &request).await?.backend_ref,
        handle.backend_ref
    );
    driver.resume(&handle).await?;
    let mut changed = request.clone();
    changed.image = config.agent_image.clone();
    let mut changed_record = record.clone();
    changed_record.image = changed.image.clone();
    assert_eq!(
        driver
            .create(&changed_record, &changed)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    driver.remove(&handle).await?;
    driver.remove(&handle).await?;
    assert_eq!(driver.inspect(&handle).await?.state, ObservedState::Missing);

    let mut short_request = request.clone();
    short_request.ttl_seconds = 3;
    let expiring = sandbox(&short_request);
    let expired_handle = driver.create(&expiring, &short_request).await?;
    driver.pause(&expired_handle).await?;
    // The independent worker can reap while the sandbox is paused and no API is alive.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(restarted.reap_expired().await?, vec![expiring.id]);
    assert_eq!(
        driver.inspect(&expired_handle).await?.state,
        ObservedState::Missing
    );
    Ok(
        serde_json::json!({"suite":"docker-driver-contract", "profile":profile,"result":"passed",
        "cases":["explicit_runc_opt_in","actual_runtime_smoke","static_agent_in_foreign_image","image_healthcheck_disabled","image_environment_cleared","literal_execution_and_terminal_events","binary_files","idempotent_create","worker_restart_discovery","ownership_refusal","pause_resume","create_conflict","confirmed_repeat_delete","paused_absolute_expiry"]}),
    )
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = DockerConfig {
        installation_id: Uuid::new_v4(),
        agent_image: std::env::var("GOLDENHOOP_AGENT_IMAGE")
            .unwrap_or_else(|_| "goldenhoop-agent:test".into()),
        profile: if std::env::var("GOLDENHOOP_TEST_RUNTIME").as_deref() == Ok("runsc") {
            DockerProfile::Gvisor
        } else {
            DockerProfile::RuncDevelopment
        },
        allow_runc_development: true,
    };
    let driver = DockerDriver::connect(config.clone()).await?;
    let workload_image = std::env::var("GOLDENHOOP_WORKLOAD_IMAGE")
        .unwrap_or_else(|_| "debian:bookworm-slim".into());
    let result = AssertUnwindSafe(contract(&driver, &config, &workload_image))
        .catch_unwind()
        .await;
    // Cleanup also follows failed checks; only this fresh installation is in scope.
    for handle in driver.discover().await? {
        driver.remove(&handle).await?;
    }
    assert!(driver.discover().await?.is_empty());
    driver.remove_agent_bundle().await?;
    let mut evidence = match result {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut hashes = BTreeMap::new();
    source_hashes(root, &root.join("crates"), &mut hashes)?;
    for name in ["Cargo.toml", "Cargo.lock", "images/agent/Dockerfile"] {
        hashes.insert(
            name.into(),
            format!("{:x}", Sha256::digest(std::fs::read(root.join(name))?)),
        );
    }
    evidence["source_files_sha256"] = serde_json::json!(hashes);
    let docker = bollard::Docker::connect_with_socket_defaults()?;
    evidence["docker"] = serde_json::to_value(docker.version().await?)?;
    evidence["agent_image_id"] =
        serde_json::json!(docker.inspect_image(&config.agent_image).await?.id);
    evidence["workload_image_id"] =
        serde_json::json!(docker.inspect_image(&workload_image).await?.id);
    evidence["workload_image"] = serde_json::json!(workload_image);
    evidence["installation_id"] = serde_json::json!(config.installation_id);
    evidence["timestamp"] = serde_json::json!(Utc::now());
    evidence["cleanup"] = serde_json::json!("complete");
    let rendered = serde_json::to_string_pretty(&evidence)?;
    println!("{rendered}");
    if let Ok(path) = std::env::var("GOLDENHOOP_EVIDENCE") {
        let path = Path::new(&path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, format!("{rendered}\n"))?;
    }
    Ok(())
}
