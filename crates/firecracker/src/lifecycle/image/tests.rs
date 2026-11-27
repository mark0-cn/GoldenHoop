use super::*;
use goldenhoop_image_builder::{Content, PreparedImage};

fn fixture() -> (DriverConfig, ReadyImageInfo) {
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
    let manifest = PreparedImage {
        format: 1,
        generation: Uuid::new_v4(),
        archive: content.clone(),
        agent: content.clone(),
        init: content.clone(),
        disk: Content {
            sha256: "b".repeat(64),
            size_bytes: 64 * MIB,
        },
        mke2fs: content.clone(),
        e2fsck: content,
        created_at: "2026-11-27T00:00:00Z".parse().unwrap(),
        builder_version: inventory.builder_version.clone(),
    };
    let reference = PreparedImageReference::for_manifest(Uuid::new_v4(), &manifest).unwrap();
    let artifact = Artifact {
        path: "/operator/input".into(),
        sha256: "c".repeat(64),
        size: 64 * MIB,
    };
    let cfg = DriverConfig {
        installation_id: Uuid::new_v4(),
        data_root: "/var/lib/ghi".into(),
        artifacts: BootInput {
            firecracker: artifact.clone(),
            jailer: artifact.clone(),
            kernel: artifact.clone(),
            rootfs: artifact.clone(),
        },
        supervisor: artifact,
        image: format!("sha256:{}", "c".repeat(64)),
        prepared_images: Some(PreparedImagePolicy {
            inventory,
            max_disk_bytes: 64 * MIB,
            disk_budget_bytes: 128 * MIB,
            staging_root: "/var/lib/ghi/input".into(),
            staging_bytes: 64 * MIB,
            allow_runc_development: false,
        }),
        max_resources: ResourceLimits {
            cpu_millis: 1000,
            memory_bytes: 256 * MIB,
            pids: 32,
        },
        capacity: HostCapacity::default(),
        max_ttl_seconds: 300,
    };
    (
        cfg,
        ReadyImageInfo {
            reference,
            manifest,
        },
    )
}

#[test]
fn selected_images_pin_the_guest_contract_but_allow_different_exact_disks() {
    let (cfg, info) = fixture();
    cfg.validate().unwrap();
    let policy = cfg.prepared_images.as_ref().unwrap();
    policy.validate_info(&info).unwrap();
    let mut other = info.clone();
    other.manifest.disk.sha256 = "d".repeat(64);
    other.reference =
        PreparedImageReference::for_manifest(Uuid::new_v4(), &other.manifest).unwrap();
    policy.validate_info(&other).unwrap();
    let first = cfg.selected_artifacts(Uuid::new_v4(), &info).unwrap();
    let second = cfg.selected_artifacts(Uuid::new_v4(), &other).unwrap();
    assert_eq!(first.firecracker, cfg.artifacts.firecracker);
    assert_eq!(second.kernel, cfg.artifacts.kernel);
    assert_ne!(first.rootfs.sha256, second.rootfs.sha256);
    assert_ne!(first.rootfs.path, second.rootfs.path);
    let mut changed = info.clone();
    changed.manifest.agent.sha256 = "d".repeat(64);
    changed.reference =
        PreparedImageReference::for_manifest(changed.reference.id, &changed.manifest).unwrap();
    assert!(policy.validate_info(&changed).is_err());
    let mut changed = info.clone();
    changed.reference.manifest_sha256 = "e".repeat(64);
    assert!(policy.validate_info(&changed).is_err());
    let mut changed = info;
    changed.manifest.disk.size_bytes = 128 * MIB;
    changed.reference =
        PreparedImageReference::for_manifest(changed.reference.id, &changed.manifest).unwrap();
    assert!(policy.validate_info(&changed).is_err());
}

#[test]
fn recovery_binds_the_selected_manifest_and_owned_destination_without_an_image_job() {
    // Synthetic metadata admission only; actual boot/restart requires the KVM gate.
    let (cfg, info) = fixture();
    let generation = Uuid::new_v4();
    let id = Uuid::new_v4();
    let record = VmJournal {
        format: 1,
        owner: VmOwner {
            installation_id: cfg.installation_id,
            sandbox_id: id,
            generation,
            request_sha256: "f".repeat(64),
            expires_at: Utc::now() + chrono::Duration::seconds(120),
            host_boot_id: Uuid::new_v4().to_string(),
            boot_deadline_ns: 1,
        },
        artifacts: cfg.selected_artifacts(generation, &info).unwrap(),
        selected_image: Some(info),
        profile_probe_context_sha256: None,
        resources: cfg.max_resources.clone(),
        supervisor: None,
        supervisor_cgroup_identity: None,
        vm_cgroup_identity: None,
        vm_root: None,
        root_collection_started: false,
        supervisor_artifact: cfg.supervisor.clone(),
        original_cgroup: "/sys/fs/cgroup".into(),
        process: None,
        phase: "reserved".into(),
        ever_ready: false,
        error: None,
        console_tail: String::new(),
        supervisor_stderr_tail: String::new(),
        supervisor_cgroup_events: Default::default(),
    };
    record.validate(&cfg, id).unwrap();
    let bytes = serde_json::to_vec(&record).unwrap();
    let restored: VmJournal = serde_json::from_slice(&bytes).unwrap();
    restored.validate(&cfg, id).unwrap();
    let mut changed = record.clone();
    changed.artifacts.rootfs.path = cfg.paths(Uuid::new_v4()).unwrap().jail.join("rootfs.ext4");
    assert!(changed.validate(&cfg, id).is_err());
    let mut changed = record.clone();
    changed.artifacts.kernel.sha256 = "a".repeat(64);
    assert!(changed.validate(&cfg, id).is_err());
    let mut unconfirmed_probe = record.clone();
    unconfirmed_probe.profile_probe_context_sha256 = Some("a".repeat(64));
    assert!(unconfirmed_probe.validate(&cfg, id).is_err());
    unconfirmed_probe.phase = "collected".into();
    assert!(unconfirmed_probe.validate(&cfg, id).is_err());
    unconfirmed_probe.ever_ready = true;
    assert!(
        unconfirmed_probe.validate(&cfg, id).is_err(),
        "missing original process cannot certify a full probe"
    );
    let mut legacy = record;
    legacy.selected_image = None;
    legacy.artifacts = cfg.artifacts.clone();
    legacy.validate(&cfg, id).unwrap();
    assert!(
        serde_json::to_value(&legacy)
            .unwrap()
            .get("selected_image")
            .is_none()
    );
    let mut legacy_cfg = cfg;
    legacy_cfg.prepared_images = None;
    assert!(
        serde_json::to_value(&legacy_cfg)
            .unwrap()
            .get("prepared_images")
            .is_none()
    );
}

#[test]
fn undersized_or_unbounded_declared_staging_and_disk_policies_are_refused() {
    let (cfg, _) = fixture();
    let mut changed = cfg.clone();
    changed.prepared_images.as_mut().unwrap().staging_bytes = 63 * MIB;
    assert!(changed.validate().is_err());
    let mut changed = cfg.clone();
    changed.prepared_images.as_mut().unwrap().disk_budget_bytes = 63 * MIB;
    assert!(changed.validate().is_err());
    let mut changed = cfg.clone();
    changed.prepared_images.as_mut().unwrap().staging_bytes = 4 * MAX_DISK_BYTES + MIB;
    assert!(changed.validate().is_err());
    let mut changed = cfg;
    changed.prepared_images.as_mut().unwrap().staging_root = "relative".into();
    assert!(changed.validate().is_err());
}
