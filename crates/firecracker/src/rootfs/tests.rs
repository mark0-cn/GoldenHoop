use super::*;
use crate::control::{GuestFilesystemState, GuestRootFilesystem};

pub(crate) fn fixture() -> RootfsManifest {
    let source = CaptureIdentity {
        installation: Uuid::new_v4(),
        sandbox: Uuid::new_v4(),
        source_generation: Uuid::new_v4(),
        capture: Uuid::new_v4(),
        request_sha256: "a".repeat(64),
    };
    let asset = RootfsArtifact {
        sha256: "b".repeat(64),
        size_bytes: 512,
    };
    let intent = RootfsCaptureIntent {
        source: source.clone(),
        boot: RootfsBoot {
            firecracker_version: "1.18.0".into(),
            firecracker_sha256: "c".repeat(64),
            jailer_sha256: "d".repeat(64),
            kernel: asset.clone(),
            architecture: "x86_64".into(),
            guest_control_version: GUEST_CONTROL_VERSION,
            agent: asset.clone(),
            init: asset.clone(),
            guest_config: asset,
            control_port: 52,
            workload_pids: 256,
        },
        origin: RootfsOrigin::Configured {
            disk: RootfsArtifact {
                sha256: "e".repeat(64),
                size_bytes: 64 * MIB,
            },
        },
        barrier: Uuid::new_v4(),
        inspection_generation: Uuid::new_v4(),
        inspector_inventory_sha256: "f".repeat(64),
        disk_id: Uuid::new_v4(),
        disk_bytes: 64 * MIB,
    };
    let barrier = GuestRootfsBarrierInfo {
        protocol: GUEST_CONTROL_VERSION,
        format: 1,
        generation: source.source_generation,
        barrier: intent.barrier,
        phase: GuestBarrierPhase::Quiesced,
        workload_frozen: true,
        filesystem: GuestFilesystemState::Frozen,
        root: Some(GuestRootFilesystem {
            device: 254,
            inode: 2,
            mount_id: 17,
        }),
        thaw_started: false,
    };
    RootfsManifest {
        format: 1,
        filesystem: RootfsFilesystem::Ext4,
        intent,
        barrier,
        disk: RootfsArtifact {
            sha256: "0".repeat(64),
            size_bytes: 64 * MIB,
        },
    }
}
#[test]
fn manifest_pins_original_capture_boot_inspector_and_independent_disk() {
    let good = fixture();
    let reference = good.reference().unwrap();
    good.admit(&reference, &good.intent.boot, good.intent.disk_bytes)
        .unwrap();
    assert!(
        good.admit(&reference, &good.intent.boot, good.intent.disk_bytes - 1)
            .is_err()
    );
    let mut changed = good.clone();
    changed.intent.source.source_generation = Uuid::new_v4();
    assert!(changed.reference().is_err());
    let mut changed = good.clone();
    changed.intent.inspector_inventory_sha256 = "1".repeat(64);
    assert!(
        changed
            .admit(&reference, &good.intent.boot, good.intent.disk_bytes)
            .is_err()
    );
    let mut changed = good.clone();
    changed.intent.disk_id = Uuid::new_v4();
    assert!(
        changed
            .admit(&reference, &good.intent.boot, good.intent.disk_bytes)
            .is_err()
    );
    let mut changed = good.clone();
    changed.disk.sha256 = "2".repeat(64);
    assert!(
        changed
            .admit(&reference, &good.intent.boot, good.intent.disk_bytes)
            .is_err()
    );
    let mut changed = good.intent.boot.clone();
    changed.init.sha256 = "3".repeat(64);
    assert!(
        good.admit(&reference, &changed, good.intent.disk_bytes)
            .is_err()
    );
    let mut changed = good.clone();
    changed.intent.origin = RootfsOrigin::Prepared {
        image: Uuid::nil(),
        generation: Uuid::new_v4(),
        manifest_sha256: "a".repeat(64),
        disk: good.disk.clone(),
    };
    assert!(changed.reference().is_err());
}
#[test]
fn manifest_refuses_uncertain_or_thawed_barriers_and_memory_wire_substitution() {
    let good = fixture();
    for state in [
        GuestFilesystemState::Unknown,
        GuestFilesystemState::NotDispatched,
        GuestFilesystemState::Thawed,
    ] {
        let mut bad = good.clone();
        bad.barrier.filesystem = state;
        assert!(bad.reference().is_err());
    }
    let mut bad = good.clone();
    bad.barrier.thaw_started = true;
    assert!(bad.reference().is_err());
    let mut bad = good.clone();
    bad.barrier.root = None;
    assert!(bad.reference().is_err());
    let mut wire = serde_json::to_value(&good).unwrap();
    for field in ["memory", "state", "host_path", "retained_execution"] {
        wire[field] = serde_json::json!({});
        assert!(serde_json::from_value::<RootfsManifest>(wire.clone()).is_err());
        wire.as_object_mut().unwrap().remove(field);
    }
    assert!(serde_json::from_value::<crate::checkpoint::CheckpointManifest>(wire).is_err());
    let memory = crate::checkpoint::tests::fixture();
    assert!(
        serde_json::from_value::<RootfsManifest>(serde_json::to_value(memory).unwrap()).is_err()
    );
}
