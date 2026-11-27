use super::*;

pub(crate) fn fixture() -> CheckpointManifest {
    let source = CaptureIdentity {
        installation: Uuid::new_v4(),
        sandbox: Uuid::new_v4(),
        source_generation: Uuid::new_v4(),
        capture: Uuid::new_v4(),
        request_sha256: "a".repeat(64),
    };
    let object = |size_bytes| CheckpointContent {
        id: Uuid::new_v4(),
        sha256: "b".repeat(64),
        size_bytes,
    };
    CheckpointManifest {
        format: 1,
        barrier: GuestBarrierInfo {
            protocol: GUEST_CONTROL_VERSION,
            generation: source.source_generation,
            barrier: Uuid::new_v4(),
            phase: GuestBarrierPhase::Quiesced,
            workload_frozen: true,
            rootfs_synced: true,
        },
        source,
        runtime: CheckpointRuntime {
            firecracker_version: "1.18.0".into(),
            firecracker_sha256: "c".repeat(64),
            jailer_sha256: "d".repeat(64),
            kernel_sha256: "e".repeat(64),
            architecture: "x86_64".into(),
            host_compatibility_sha256: "f".repeat(64),
        },
        resources: ResourceLimits {
            cpu_millis: 1000,
            memory_bytes: 128 * MIB,
            pids: 32,
        },
        state: object(1024),
        memory: object(128 * MIB),
        disk: object(64 * MIB),
    }
}

#[test]
fn trusted_reference_binds_every_role_source_barrier_and_exact_runtime() {
    let manifest = fixture();
    let reference = manifest.reference().unwrap();
    let budget = 192 * MIB + 1024;
    assert_eq!(
        manifest
            .admit(&reference, &manifest.runtime, budget)
            .unwrap(),
        budget
    );
    for edit in 0..8 {
        let mut changed = manifest.clone();
        match edit {
            0 => changed.source.source_generation = Uuid::new_v4(),
            1 => changed.source.capture = Uuid::new_v4(),
            2 => changed.barrier.barrier = Uuid::new_v4(),
            3 => changed.memory.sha256 = "0".repeat(64),
            4 => changed.disk.id = Uuid::new_v4(),
            5 => changed.resources.cpu_millis = 2000,
            6 => changed.runtime.host_compatibility_sha256 = "0".repeat(64),
            _ => changed.source.request_sha256 = "0".repeat(64),
        }
        assert!(
            changed
                .admit(&reference, &manifest.runtime, budget)
                .is_err()
        );
    }
    assert!(
        manifest
            .admit(&reference, &manifest.runtime, budget - 1)
            .is_err()
    );
    let mut runtime = manifest.runtime.clone();
    runtime.firecracker_sha256 = "0".repeat(64);
    assert!(manifest.admit(&reference, &runtime, budget).is_err());
}

#[test]
fn malformed_or_incomplete_capture_cannot_mint_a_content_reference() {
    for edit in 0..13 {
        let mut value = fixture();
        match edit {
            0 => value.source.installation = Uuid::nil(),
            1 => value.barrier.phase = GuestBarrierPhase::Resumed,
            2 => value.barrier.rootfs_synced = false,
            3 => value.barrier.workload_frozen = false,
            4 => value.barrier.protocol = 2,
            5 => value.state.size_bytes = MAX_CHECKPOINT_STATE_BYTES + 1,
            6 => value.memory.size_bytes += 1,
            7 => value.disk.size_bytes = u64::MAX,
            8 => value.disk.id = value.state.id,
            9 => value.state.sha256 = "A".repeat(64),
            10 => value.runtime.architecture = "aarch64".into(),
            11 => value.resources.memory_bytes = u64::MAX,
            _ => value.memory.id = Uuid::nil(),
        }
        assert!(value.reference().is_err(), "malformed variant {edit}");
    }
}

#[test]
fn manifest_decoding_is_strict_and_reference_is_stable_through_roundtrip() {
    let value = fixture();
    let reference = value.reference().unwrap();
    let mut json = serde_json::to_value(&value).unwrap();
    let decoded: CheckpointManifest = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(decoded.reference().unwrap(), reference);
    json["memory"]["host_path"] = serde_json::json!("/arbitrary");
    assert!(serde_json::from_value::<CheckpointManifest>(json).is_err());
}
