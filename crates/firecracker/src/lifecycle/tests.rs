use super::*;

#[test]
fn tracked_actual_process_rejects_foreign_start_time_and_observes_reaped_exit() {
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = OwnedChild(
        std::process::Command::new("sleep")
            .arg("10")
            .spawn()
            .unwrap(),
    );
    let identity = process_identity(child.0.id()).unwrap();
    let fd = track_process(&identity).unwrap();
    assert!(!pidfd_exited(&fd).unwrap());
    let mut foreign = identity.clone();
    foreign.start_ticks += 1;
    assert!(track_process(&foreign).is_err());
    assert!(child.0.try_wait().unwrap().is_none());
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(pidfd_exited(&fd).unwrap());
    assert!(!Path::new("/proc").join(identity.pid.to_string()).exists());
}

#[test]
fn atomic_private_record_has_complete_bytes_and_no_pending_orphan_after_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("record.json");
    for phase in ["reserved", "running", "collected"] {
        let value = serde_json::json!({"generation":Uuid::new_v4(),"phase":phase});
        atomic_json(&path, &value).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap(),
            value
        );
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
    let path = directory.path().to_owned();
    directory.close().unwrap();
    assert!(!path.exists());
}

#[test]
fn oversized_unix_endpoints_are_rejected_before_directory_creation() {
    let artifact = Artifact {
        path: PathBuf::from("/operator-owned/artifact"),
        sha256: "a".repeat(64),
        size: 1,
    };
    let cfg = DriverConfig {
        installation_id: Uuid::new_v4(),
        data_root: PathBuf::from(format!("/var/lib/{}", "q".repeat(100))),
        artifacts: BootInput {
            firecracker: artifact.clone(),
            jailer: artifact.clone(),
            kernel: artifact.clone(),
            rootfs: artifact.clone(),
        },
        supervisor: artifact,
        image: format!("sha256:{}", "a".repeat(64)),
        max_resources: ResourceLimits {
            cpu_millis: 1000,
            memory_bytes: 256 * MIB,
            pids: 32,
        },
        capacity: HostCapacity::default(),
        max_ttl_seconds: 300,
    };
    assert!(cfg.validate().is_err());
    assert!(!cfg.data_root.exists());
}
