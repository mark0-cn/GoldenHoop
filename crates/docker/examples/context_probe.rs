//! Actual optional-capability gate, using a fresh installation and owned resources.
use futures_util::FutureExt;
use goldenhoop_docker::{DockerConfig, DockerDriver, DockerProfile};
use goldenhoop_protocol::*;
use goldenhoop_runtime::RuntimeDriver;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, panic::AssertUnwindSafe, path::Path};
use uuid::Uuid;

async fn contract(
    driver: &DockerDriver,
    agent: &str,
    kernel: &str,
    cases: &mut Vec<Value>,
) -> Result<(), ApiError> {
    let base = driver.probe().await;
    assert!(base.code_languages.is_empty());
    if base.availability != Availability::Available
        || base.capabilities.contains(&Capability::CodeContexts)
    {
        return Err(ApiError::new(
            ErrorCode::BackendUnavailable,
            "mandatory probe did not establish the expected baseline",
        ));
    }
    cases.push(json!({"case":"default_does_not_advertise_unprobed_kernels","result":"passed","profile":base}));
    let missing = format!("goldenhoop-missing-kernel-{}:test", Uuid::new_v4().simple());
    assert!(driver.probe_code_contexts(&missing).await.is_err());
    assert!(
        !driver
            .profile_snapshot()
            .await
            .capabilities
            .contains(&Capability::CodeContexts)
    );
    assert!(driver.discover().await?.is_empty());
    cases.push(
        json!({"case":"missing_cached_image_refused_without_pull_or_fallback","result":"passed"}),
    );
    assert!(driver.probe_code_contexts(agent).await.is_err());
    assert!(
        !driver
            .profile_snapshot()
            .await
            .capabilities
            .contains(&Capability::CodeContexts)
    );
    assert!(driver.discover().await?.is_empty());
    cases.push(
        json!({"case":"missing_kernel_dependencies_refused_and_collected","result":"passed"}),
    );
    let enabled = driver.probe_code_contexts(kernel).await?;
    assert_eq!(enabled.availability, Availability::Available);
    assert!(enabled.capabilities.contains(&Capability::CodeContexts));
    assert_eq!(
        enabled.code_languages,
        [CodeLanguage::Python].into_iter().collect()
    );
    assert!(driver.discover().await?.is_empty());
    cases.push(json!({"case":"actual_uid_state_replay_output_exception_and_collection","result":"passed","profile":enabled}));
    assert!(driver.probe_code_contexts(agent).await.is_err());
    let withdrawn = driver.profile_snapshot().await;
    assert!(withdrawn.code_languages.is_empty());
    assert!(!withdrawn.capabilities.contains(&Capability::CodeContexts));
    assert!(withdrawn.capabilities.contains(&Capability::Commands));
    assert!(driver.discover().await?.is_empty());
    cases.push(json!({"case":"failed_reprobe_withdraws_optional_capability","result":"passed","profile":withdrawn}));
    Ok(())
}
fn hashes(root: &Path, at: &Path, out: &mut BTreeMap<String, String>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(at)? {
        let path = entry?.path();
        if path.is_dir() {
            hashes(root, &path, out)?;
        } else if path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| matches!(value, "rs" | "toml" | "sql"))
        {
            out.insert(
                path.strip_prefix(root)
                    .expect("source inside checkout")
                    .to_string_lossy()
                    .replace('\\', "/"),
                format!("{:x}", Sha256::digest(std::fs::read(path)?)),
            );
        }
    }
    Ok(())
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let agent =
        std::env::var("GOLDENHOOP_AGENT_IMAGE").unwrap_or_else(|_| "goldenhoop-agent:test".into());
    let kernel = std::env::var("GOLDENHOOP_KERNEL_IMAGE")
        .unwrap_or_else(|_| "goldenhoop-kernel-fixture:test".into());
    let config = DockerConfig {
        installation_id: Uuid::new_v4(),
        agent_image: agent.clone(),
        profile: if std::env::var("GOLDENHOOP_TEST_RUNTIME").as_deref() == Ok("runsc") {
            DockerProfile::Gvisor
        } else {
            DockerProfile::RuncDevelopment
        },
        allow_runc_development: true,
    };
    let driver = DockerDriver::connect(config.clone()).await?;
    let mut cases = Vec::new();
    let result = AssertUnwindSafe(contract(&driver, &agent, &kernel, &mut cases))
        .catch_unwind()
        .await;
    let mut failure = match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error.to_string()),
        Err(_) => Some("contract assertion panicked; inspect the test log".into()),
    };
    let cleanup = async {
        for handle in driver.discover().await? {
            driver.remove(&handle).await?;
        }
        if !driver.discover().await?.is_empty() {
            return Err(ApiError::new(
                ErrorCode::BackendUnavailable,
                "owned probe containers remain",
            ));
        }
        driver.remove_agent_bundle().await
    }
    .await;
    let clean = cleanup.is_ok();
    if let Err(error) = cleanup {
        failure = Some(format!("cleanup failed: {error}"));
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut source = BTreeMap::new();
    hashes(root, &root.join("crates"), &mut source)?;
    for name in [
        "Cargo.toml",
        "Cargo.lock",
        "images/agent/Dockerfile",
        "images/kernel/Dockerfile",
    ] {
        source.insert(
            name.into(),
            format!("{:x}", Sha256::digest(std::fs::read(root.join(name))?)),
        );
    }
    let docker = bollard::Docker::connect_with_socket_defaults()?;
    let evidence = json!({"suite":"driver-code-context-probe","timestamp":chrono::Utc::now(),"installation_id":config.installation_id,"runtime":config.profile.id(),
        "result":if failure.is_none(){"passed"}else{"failed"},"cleanup":if clean{"complete"}else{"unknown"},"error":failure,"cases":cases,
        "source_files_sha256":source,"docker":docker.version().await.ok(),"agent_image_id":docker.inspect_image(&agent).await.ok().and_then(|image|image.id),
        "kernel_image_id":docker.inspect_image(&kernel).await.ok().and_then(|image|image.id)});
    if let Ok(path) = std::env::var("GOLDENHOOP_EVIDENCE") {
        let path = Path::new(&path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            path,
            format!("{}\n", serde_json::to_string_pretty(&evidence)?),
        )?;
    }
    println!(
        "{}",
        json!({"suite":evidence["suite"],"result":evidence["result"],"cleanup":evidence["cleanup"],"cases":cases.len(),"error":failure})
    );
    if let Some(failure) = failure {
        return Err(failure.into());
    }
    Ok(())
}
