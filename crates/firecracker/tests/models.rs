use goldenhoop_firecracker::{kvm::KvmState, models::*};
use serde_json::json;

#[test]
fn pinned_wire_shapes_keep_full_snapshots_and_paused_restore_explicit() {
    assert_eq!(
        serde_json::to_value(MachineConfiguration::new(1, 1024).unwrap()).unwrap(),
        json!({"vcpu_count":1,"mem_size_mib":1024,"smt":false,"track_dirty_pages":false})
    );
    assert_eq!(
        serde_json::to_value(SnapshotCreate::full("/state".into(), "/memory".into()).unwrap())
            .unwrap(),
        json!({"snapshot_type":"Full","snapshot_path":"/state","mem_file_path":"/memory"})
    );
    assert_eq!(
        serde_json::to_value(SnapshotLoad::paused("/state".into(), "/memory".into()).unwrap())
            .unwrap(),
        json!({"snapshot_path":"/state","mem_backend":{"backend_type":"File","backend_path":"/memory"},"resume_vm":false,"track_dirty_pages":false})
    );
    let root = serde_json::to_value(RootDrive::new("/root.ext4".into(), false).unwrap()).unwrap();
    assert_eq!(root["drive_id"], "rootfs");
    assert_eq!(root["is_root_device"], true);
    assert_eq!(root["is_read_only"], false);
    assert_eq!(root["cache_type"], "Writeback");
}

#[test]
fn jailed_paths_refuse_ambiguous_or_non_file_targets_before_any_dispatch() {
    for path in [
        "",
        "/",
        "relative",
        "/../file",
        "/a/./file",
        "/a//file",
        "/a/",
        "/a\\b",
        "/a\0b",
        "/a\nb",
    ] {
        assert!(RootDrive::new(path.into(), false).is_err(), "{path:?}");
        assert!(
            BootSource::new(path.into(), String::new()).is_err(),
            "{path:?}"
        );
        assert!(Vsock::new(3, path.into()).is_err(), "{path:?}");
        assert!(
            SnapshotCreate::full(path.into(), "/memory".into()).is_err(),
            "{path:?}"
        );
        assert!(
            SnapshotLoad::paused("/state".into(), path.into()).is_err(),
            "{path:?}"
        );
    }
    assert!(BootSource::new("/kernel".into(), "console=ttyS0\ninit=/bad".into()).is_err());
    assert!(BootSource::new("/kernel".into(), "x".repeat(4097)).is_err());
    assert!(SnapshotCreate::full("/same".into(), "/same".into()).is_err());
    assert!(SnapshotLoad::paused("/same".into(), "/same".into()).is_err());
}

#[test]
fn reserved_cids_zero_resources_and_unknown_states_are_refused() {
    for cid in [0, 1, 2, u32::MAX] {
        assert!(Vsock::new(cid, "/vsock".into()).is_err());
    }
    assert!(Vsock::new(3, "/vsock".into()).is_ok());
    assert!(MachineConfiguration::new(0, 1024).is_err());
    assert!(MachineConfiguration::new(1, 0).is_err());
    for state in ["Not started", "Running", "Paused"] {
        assert!(
            serde_json::from_value::<InstanceInfo>(
                json!({"id":"test","app_name":"Firecracker","vmm_version":"1.18.0","state":state})
            )
            .is_ok()
        );
    }
    assert!(
        serde_json::from_value::<InstanceInfo>(
            json!({"id":"test","app_name":"Firecracker","vmm_version":"1.18.0","state":"Unknown"})
        )
        .is_err()
    );
}

#[test]
fn actual_host_probe_does_not_publish_runtime_capabilities() {
    let observation = goldenhoop_firecracker::kvm::probe_kvm();
    assert!(!observation.runtime_capabilities_verified);
    if observation.state == KvmState::Ready {
        assert_eq!(observation.operating_system, "linux");
        assert_eq!(observation.api_version, Some(12));
    }
    #[cfg(not(target_os = "linux"))]
    assert_eq!(observation.state, KvmState::UnsupportedHost);
}

#[test]
fn host_probe_cli_reports_actual_outcome_with_a_distinct_refusal_exit() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_goldenhoop-firecracker"))
        .arg("probe-kvm")
        .output()
        .unwrap();
    let observation: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(observation["runtime_capabilities_verified"], false);
    assert_eq!(
        output.status.code(),
        Some(if observation["state"] == "ready" {
            0
        } else {
            2
        })
    );
    assert!(output.stderr.is_empty());
}
