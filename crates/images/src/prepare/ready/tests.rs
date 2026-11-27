use super::*;
use std::{
    io::{Read, Seek},
    os::unix::fs::{PermissionsExt, symlink},
};

fn fixture() -> (tempfile::TempDir, BlobStore, ImageJob, BuilderInventory) {
    let directory = tempfile::tempdir().unwrap();
    let installation = Uuid::new_v4();
    let blobs = BlobStore::local(&directory.path().join("blobs"), installation).unwrap();
    let content = Content {
        sha256: "a".repeat(64),
        size_bytes: 512,
    };
    let inventory = BuilderInventory {
        format: 1,
        builder_version: env!("CARGO_PKG_VERSION").into(),
        agent: content.clone(),
        init: content.clone(),
        mke2fs: content.clone(),
        e2fsck: content.clone(),
    };
    let id = Uuid::new_v4();
    let generation = Uuid::new_v4();
    let request = ImagePrepareRequest {
        id,
        generation,
        source_image: format!("sha256:{}", "b".repeat(64)),
        builder_image: format!("sha256:{}", "c".repeat(64)),
        runtime: BuilderRuntime::Runsc,
        disk_bytes: 64 * 1024 * 1024,
    };
    let source = ExportRequest {
        id: Uuid::new_v4(),
        generation: Uuid::new_v4(),
        source_image: request.source_image.clone(),
    };
    let archive = blobs
        .large_reference(source.id, content.sha256.clone(), content.size_bytes)
        .unwrap();
    let conversion = PrepareRequest {
        generation,
        archive: content.clone(),
        agent: content.clone(),
        init: content.clone(),
        disk_bytes: request.disk_bytes,
    };
    let manifest = PreparedImage {
        format: 1,
        generation,
        archive: content.clone(),
        agent: content.clone(),
        init: content.clone(),
        disk: Content {
            sha256: "d".repeat(64),
            size_bytes: request.disk_bytes,
        },
        mke2fs: content.clone(),
        e2fsck: content,
        created_at: "2026-11-27T00:00:00Z".parse().unwrap(),
        builder_version: inventory.builder_version.clone(),
    };
    let disk = blobs
        .large_reference(id, manifest.disk.sha256.clone(), manifest.disk.size_bytes)
        .unwrap();
    let payload = State {
        format: 1,
        phase: Phase::Ready,
        source,
        archive: Some(archive),
        inventory: Some(inventory.clone()),
        request: Some(conversion),
        nonce: Uuid::new_v4(),
        seeder_id: Some("e".repeat(64)),
        builder_id: Some("f".repeat(64)),
        host: Some(HostObservation {
            pid: 123,
            start_ticks: 1,
            boot_id: Uuid::new_v4(),
            process_cgroup: "/fixture".into(),
            owned_cgroup: "/fixture".into(),
            limits: BuilderLimits {
                memory_max: 1024 * 1024 * 1024,
                swap_max: 0,
                pids_max: 64,
                cpu_quota: 100000,
                cpu_period: 100000,
            },
        }),
        converter_observation: None,
        manifest: Some(manifest),
        disk: Some(disk),
        error: None,
        coordination: None,
        recovery_observation: None,
        producer: None,
    };
    let job = ImageJob {
        id,
        installation_id: installation,
        generation,
        request_sha256: "0".repeat(64),
        request: json!({"format":1,"role":ROLE,"request":request,"storage_binding":blobs.binding()}),
        payload: serde_json::to_value(payload).unwrap(),
        revision: 9,
        created_at: "2026-11-27T00:00:00Z".parse().unwrap(),
    };
    (directory, blobs, job, inventory)
}
#[test]
fn only_ready_exact_request_inventory_generation_and_storage_are_consumable() {
    // Synthetic metadata validates admission only, not actual converter execution.
    let (_directory, blobs, job, inventory) = fixture();
    ready_state(&job, &blobs, &inventory, false).unwrap();
    for phase in [
        "reserved",
        "disk_stored",
        "providers_collected",
        "source_collecting",
        "failed_collected",
        "collecting",
        "collected",
    ] {
        let mut changed = job.clone();
        changed.payload["phase"] = json!(phase);
        assert!(
            ready_state(&changed, &blobs, &inventory, false).is_err(),
            "{phase}"
        );
    }
    for (field, value) in [
        ("format", json!(2)),
        ("role", json!("source-export")),
        ("storage_binding", json!("foreign")),
        ("extra", json!(true)),
    ] {
        let mut changed = job.clone();
        changed.request[field] = value;
        assert!(
            ready_state(&changed, &blobs, &inventory, false).is_err(),
            "{field}"
        );
    }
    let mut changed = job.clone();
    changed.installation_id = Uuid::new_v4();
    assert!(ready_state(&changed, &blobs, &inventory, false).is_err());
    let mut changed = job.clone();
    changed.request["request"]["id"] = json!(Uuid::new_v4());
    assert!(ready_state(&changed, &blobs, &inventory, false).is_err());
    let mut changed = job.clone();
    changed.request["request"]["generation"] = json!(Uuid::new_v4());
    assert!(ready_state(&changed, &blobs, &inventory, false).is_err());
    let mut changed = job.clone();
    changed.payload["disk"]["sha256"] = json!("b".repeat(64));
    assert!(ready_state(&changed, &blobs, &inventory, false).is_err());
    let mut changed = job.clone();
    changed.payload["error"] = serde_json::to_value(conflict()).unwrap();
    assert!(ready_state(&changed, &blobs, &inventory, false).is_err());
    for asset in ["agent", "init", "mke2fs", "e2fsck"] {
        let mut changed = serde_json::to_value(&inventory).unwrap();
        changed[asset]["sha256"] = json!("e".repeat(64));
        let changed: BuilderInventory = serde_json::from_value(changed).unwrap();
        assert!(
            ready_state(&job, &blobs, &changed, false).is_err(),
            "{asset}"
        );
    }
    let mut development = job;
    development.request["request"]["runtime"] = json!("runc_development");
    assert_eq!(
        ready_state(&development, &blobs, &inventory, false)
            .unwrap_err()
            .code,
        ErrorCode::UnsupportedCapability
    );
    ready_state(&development, &blobs, &inventory, true).unwrap();
}

#[test]
fn manifest_name_binds_all_content_and_public_metadata_omits_private_fields() {
    let (_directory, blobs, job, inventory) = fixture();
    let (_, info) = ready_state(&job, &blobs, &inventory, false).unwrap();
    let encoded = serde_json::to_value(&info).unwrap();
    assert_eq!(encoded.as_object().unwrap().len(), 2);
    let raw = serde_json::to_string(&encoded).unwrap();
    for private in [
        "storage_binding",
        "host_observation",
        "owned_cgroup",
        "producer",
        "installation_id",
        "/fixture",
    ] {
        assert!(!raw.contains(private), "{private}");
    }
    let manifest = serde_json::to_value(&info.manifest).unwrap();
    for field in ["archive", "agent", "init", "disk", "mke2fs", "e2fsck"] {
        let mut changed = manifest.clone();
        changed[field]["sha256"] = json!("e".repeat(64));
        let changed: PreparedImage = serde_json::from_value(changed).unwrap();
        assert_ne!(
            PreparedImageReference::for_manifest(job.id, &changed).unwrap(),
            info.reference
        );
    }
    let reordered = serde_json::to_string_pretty(&manifest).unwrap();
    let reordered: PreparedImage = serde_json::from_str(&reordered).unwrap();
    assert_eq!(
        PreparedImageReference::for_manifest(job.id, &reordered).unwrap(),
        info.reference
    );
}

fn root_staging() -> Option<tempfile::TempDir> {
    if unsafe { libc::geteuid() } != 0 {
        assert_ne!(std::env::var("GH_IMAGE_REQUIRE_UID0").as_deref(), Ok("1"));
        return None;
    }
    Some(
        tempfile::Builder::new()
            .prefix("goldenhoop-materialize-")
            .tempdir_in("/var/lib")
            .unwrap(),
    )
}

#[tokio::test]
async fn actual_anonymous_copy_survives_source_collection_and_closes_without_a_path() {
    let Some(directory) = root_staging() else {
        return;
    };
    let blobs = BlobStore::local(&directory.path().join("blobs"), Uuid::new_v4()).unwrap();
    let staging = directory.path().join("staging");
    std::fs::create_dir(&staging).unwrap();
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
    let payload = vec![0x6b; goldenhoop_artifacts::LARGE_CHUNK_BYTES + 31];
    let reference = blobs
        .large_reference(
            Uuid::new_v4(),
            format!("{:x}", Sha256::digest(&payload)),
            payload.len() as u64,
        )
        .unwrap();
    blobs
        .put_large(&reference, payload.as_slice())
        .await
        .unwrap();
    let mut file = download(&blobs, &reference, &staging).await.unwrap();
    assert_eq!(file.metadata().unwrap().nlink(), 0);
    assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o600);
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    blobs.collect_large(&reference).await.unwrap();
    let mut actual = Vec::new();
    file.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, payload);
    file.rewind().unwrap();
    assert!(
        blobs
            .download_large(&reference, tokio::io::sink())
            .await
            .is_err()
    );
    let fd = file.as_raw_fd();
    drop(file);
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    directory.close().unwrap();
}

#[tokio::test]
async fn actual_corrupt_partial_copy_and_untrusted_staging_never_publish_a_named_file() {
    let Some(directory) = root_staging() else {
        return;
    };
    let blobs = BlobStore::local(&directory.path().join("blobs"), Uuid::new_v4()).unwrap();
    let staging = directory.path().join("staging");
    std::fs::create_dir(&staging).unwrap();
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
    let payload = vec![0x53; goldenhoop_artifacts::LARGE_CHUNK_BYTES + 31];
    let reference = blobs
        .large_reference(
            Uuid::new_v4(),
            format!("{:x}", Sha256::digest(&payload)),
            payload.len() as u64,
        )
        .unwrap();
    blobs
        .put_large(&reference, payload.as_slice())
        .await
        .unwrap();
    let chunk = blobs.local_root().unwrap().join(format!(
        "goldenhoop/{}/large/{}/{}/chunk-00000001",
        reference.installation_id, reference.id, reference.generation
    ));
    std::fs::write(&chunk, b"wrong").unwrap();
    assert!(download(&blobs, &reference, &staging).await.is_err());
    // Wait for any already-dispatched Tokio filesystem work to finish. Failure
    // never exposes its descriptor; no named staging entry exists at any point.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let held = std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
                .any(|path| path.starts_with(&staging));
            if !held {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(anonymous_file(&staging).is_err());
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
    let alias = directory.path().join("alias");
    symlink(&staging, &alias).unwrap();
    assert!(anonymous_file(&alias).is_err());
    assert!(anonymous_file(Path::new("relative")).is_err());
    blobs.collect_large(&reference).await.unwrap();
    directory.close().unwrap();
}
