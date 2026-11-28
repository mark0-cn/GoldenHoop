//! Projection only; synthetic manifests do not establish KVM capture acceptance.
use super::*;
use goldenhoop_runtime::MemoryCaptureState;

fn fixture() -> (DriverConfig, MemoryCaptureRequest, CheckpointManifest) {
    let manifest = crate::checkpoint::tests::fixture();
    let artifact = Artifact {
        path: "/operator/synthetic-artifact".into(),
        sha256: "a".repeat(64),
        size: 1,
    };
    let cfg = DriverConfig {
        installation_id: manifest.source.installation,
        data_root: "/operator/synthetic-native-data".into(),
        artifacts: BootInput {
            firecracker: artifact.clone(),
            jailer: artifact.clone(),
            kernel: artifact.clone(),
            rootfs: artifact.clone(),
        },
        supervisor: artifact,
        image: format!("sha256:{}", "a".repeat(64)),
        prepared_images: None,
        checkpoints: Some(crate::checkpoint::CheckpointStorePolicy {
            max_bytes: 512 * MIB,
            max_checkpoints: 2,
        }),
        max_resources: manifest.resources.clone(),
        capacity: HostCapacity {
            cpu_millis: 4000,
            memory_bytes: 2 * 1024 * MIB,
            max_vms: 2,
        },
        max_ttl_seconds: 300,
    };
    let now = Utc::now();
    let source = Sandbox {
        id: manifest.source.sandbox,
        profile: PROFILE.into(),
        image: cfg.image.clone(),
        state: SandboxState::Running,
        desired_state: DesiredState::Running,
        cleanup: CleanupState::Pending,
        created_at: now,
        expires_at: now + chrono::Duration::seconds(300),
        observed_at: Some(now),
        resources: manifest.resources.clone(),
        metadata: Default::default(),
        reason: None,
    };
    let handle = super::super::driver::native_handle(
        manifest.source.installation,
        manifest.source.sandbox,
        manifest.source.source_generation,
    );
    (
        cfg,
        MemoryCaptureRequest {
            id: manifest.source.capture,
            source,
            handle,
            created_at: now,
        },
        manifest,
    )
}
fn ready(manifest: &CheckpointManifest) -> serde_json::Value {
    serde_json::json!({"capture":manifest.source.capture,"phase":"ready","capture_outcome":"ready","reserved_bytes":512*MIB,"manifest":manifest,"reference":manifest.reference().unwrap(),"content_verified":true,"error":null,"restoration":{"private_path":"/operator/private-restoration"}})
}

#[test]
fn verified_ready_projection_binds_full_manifest_and_omits_private_native_data() {
    let (cfg, request, manifest) = fixture();
    let observed = project(&cfg, &request, ready(&manifest)).unwrap();
    assert_eq!(observed.id, request.id);
    assert_eq!(observed.source.backend_ref, request.handle.backend_ref);
    let MemoryCaptureState::Ready {
        manifest: public,
        reference,
    } = observed.state
    else {
        panic!("not Ready")
    };
    assert_eq!(public.objects.len(), 3);
    assert_eq!(public.source_sandbox_id, request.source.id);
    assert_eq!(public.created_at, request.created_at);
    let json = serde_json::to_string(&public).unwrap();
    assert!(
        !json.contains("private_path")
            && !json.contains("source_generation")
            && !json.contains("request_sha256")
    );
    assert_eq!(
        serde_json::from_value::<CheckpointReference>(reference).unwrap(),
        manifest.reference().unwrap()
    );
    assert!(
        !super::super::driver::profile(&cfg)
            .capabilities
            .contains(&Capability::MemorySnapshot)
    );
}

#[test]
fn valid_but_foreign_generation_and_contradictory_ready_observations_are_refused() {
    let (cfg, request, manifest) = fixture();
    for variant in 0..7 {
        let mut changed = manifest.clone();
        match variant {
            0 => {
                changed.source.source_generation = Uuid::new_v4();
                changed.barrier.generation = changed.source.source_generation;
            }
            1 => changed.source.sandbox = Uuid::new_v4(),
            2 => {
                changed.resources.memory_bytes *= 2;
                changed.memory.size_bytes = changed.resources.memory_bytes;
            }
            _ => {}
        }
        let mut value = ready(&changed);
        match variant {
            3 => value["capture"] = serde_json::json!(Uuid::new_v4()),
            4 => value["content_verified"] = false.into(),
            5 => value["reserved_bytes"] = 0.into(),
            6 => value["reference"]["manifest_sha256"] = "0".repeat(64).into(),
            _ => {}
        }
        assert!(project(&cfg, &request, value).is_err(), "variant {variant}");
    }
}

#[test]
fn pending_failure_and_positive_collection_remain_distinct_and_disabled_preflight_is_effect_free() {
    let (mut cfg, request, _) = fixture();
    let mut pending = serde_json::json!({"capture":request.id,"phase":"capturing","capture_outcome":"pending","reserved_bytes":512*MIB,"content_verified":false,"reference":null,"manifest":null,"error":null});
    assert!(matches!(
        project(&cfg, &request, pending.clone()).unwrap().state,
        MemoryCaptureState::Pending
    ));
    pending["reserved_bytes"] = 0.into();
    assert!(project(&cfg, &request, pending).is_err());
    let failure = serde_json::json!({"capture":request.id,"phase":"failed","capture_outcome":"unconfirmed","reserved_bytes":512*MIB,"content_verified":false,"error":"/operator/private/failure"});
    let MemoryCaptureState::Failed(error) = project(&cfg, &request, failure).unwrap().state else {
        panic!("failure became collection")
    };
    assert!(!error.message.contains("/operator"));
    let mut collected = serde_json::json!({"capture":request.id,"phase":"collected","capture_outcome":"unconfirmed","reserved_bytes":0,"objects_absent":true,"error":null});
    assert!(matches!(
        project(&cfg, &request, collected.clone()).unwrap().state,
        MemoryCaptureState::Collected
    ));
    collected["objects_absent"] = false.into();
    assert!(!matches!(
        project(&cfg, &request, collected).unwrap().state,
        MemoryCaptureState::Collected
    ));
    cfg.checkpoints = None;
    assert_eq!(
        validate(&cfg, &request).unwrap_err().code,
        ErrorCode::UnsupportedCapability
    );
}

fn refused(manifest: &CheckpointManifest) -> serde_json::Value {
    serde_json::json!({"capture":manifest.source.capture,"phase":"refused","capture_outcome":"not_started",
        "reserved_bytes":0,"objects_absent":true,"content_verified":false,"manifest":null,"reference":null,"error":null,
        "refusal":{"format":1,"store":Uuid::new_v4(),"source":manifest.source,"reason":ApiError::new(ErrorCode::QuotaExceeded,"/operator/private/diagnostic")}})
}

#[test]
fn source_bound_durable_refusal_projects_independently_of_failure_and_sanitizes_public_error() {
    let (cfg, request, manifest) = fixture();
    let value = refused(&manifest);
    let observed = project(&cfg, &request, value.clone()).unwrap();
    let MemoryCaptureState::Refused { reason, receipt } = observed.state else {
        panic!("not a durable refusal")
    };
    assert_eq!(reason.code, ErrorCode::QuotaExceeded);
    assert!(!reason.message.contains("/operator"));
    assert_eq!(receipt, value["refusal"]);
    assert_eq!(observed.source.backend_ref, request.handle.backend_ref);
}

#[test]
fn missing_foreign_and_contradictory_refusal_receipts_never_release_source() {
    let (cfg, request, manifest) = fixture();
    for variant in 0..20 {
        let mut value = refused(&manifest);
        match variant {
            0 => value["refusal"] = serde_json::Value::Null,
            1 => value["refusal"]["format"] = 2.into(),
            2 => value["refusal"]["store"] = serde_json::json!(Uuid::nil()),
            3 => value["refusal"]["source"]["installation"] = serde_json::json!(Uuid::new_v4()),
            4 => value["refusal"]["source"]["sandbox"] = serde_json::json!(Uuid::new_v4()),
            5 => {
                value["refusal"]["source"]["source_generation"] = serde_json::json!(Uuid::new_v4())
            }
            6 => value["refusal"]["source"]["capture"] = serde_json::json!(Uuid::new_v4()),
            7 => value["refusal"]["source"]["request_sha256"] = "not-a-digest".into(),
            8 => value["reserved_bytes"] = 1.into(),
            9 => value["objects_absent"] = false.into(),
            10 => value["content_verified"] = true.into(),
            11 => value["reference"] = serde_json::to_value(manifest.reference().unwrap()).unwrap(),
            12 => value["manifest"] = serde_json::to_value(&manifest).unwrap(),
            13 => value["error"] = "failed capture".into(),
            14 => value["capture_outcome"] = "failed".into(),
            15 => value["phase"] = "failed".into(),
            16 => value["refusal"]["source"]["source_generation"] = serde_json::json!(Uuid::nil()),
            17 => value["refusal"]["reason"]["message"] = "x".repeat(513).into(),
            18 => {
                value.as_object_mut().unwrap().remove("objects_absent");
            }
            19 => value["refusal"]["source"]["request_sha256"] = "A".repeat(64).into(),
            _ => unreachable!(),
        }
        assert!(project(&cfg, &request, value).is_err(), "variant {variant}");
    }
}
