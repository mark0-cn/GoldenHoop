use super::*;
use crate::lifecycle::{self, HostCapacity, VmOwner, private_directory, read_json, root::Root};
use std::os::unix::fs::PermissionsExt;

struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn fixture() -> (tempfile::TempDir, DriverConfig, VmJournal) {
    let directory = tempfile::Builder::new()
        .prefix("ghr-")
        .tempdir_in("/var/lib")
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["vm", "records"] {
        private_directory(&directory.path().join(name)).unwrap();
    }
    let path = std::env::current_exe().unwrap();
    let (sha256, size) = digest(File::open(&path).unwrap()).unwrap();
    let artifact = Artifact { path, sha256, size };
    let resources = goldenhoop_protocol::ResourceLimits {
        cpu_millis: 1000,
        memory_bytes: 256 * MIB,
        pids: 32,
    };
    let cfg = DriverConfig {
        installation_id: Uuid::new_v4(),
        data_root: directory.path().to_owned(),
        artifacts: BootInput {
            firecracker: artifact.clone(),
            jailer: artifact.clone(),
            kernel: artifact.clone(),
            rootfs: artifact.clone(),
        },
        supervisor: artifact.clone(),
        image: format!("sha256:{}", artifact.sha256),
        max_resources: resources.clone(),
        capacity: HostCapacity::default(),
        max_ttl_seconds: 300,
    };
    cfg.validate().unwrap();
    let record = VmJournal {
        format: 1,
        owner: VmOwner {
            installation_id: cfg.installation_id,
            sandbox_id: Uuid::new_v4(),
            generation: Uuid::new_v4(),
            request_sha256: "a".repeat(64),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(120),
            host_boot_id: lifecycle::boot_id().unwrap(),
            boot_deadline_ns: lifecycle::boottime_ns().unwrap() + 120_000_000_000,
        },
        artifacts: cfg.artifacts.clone(),
        resources,
        supervisor: None,
        supervisor_cgroup_identity: None,
        vm_cgroup_identity: None,
        vm_root: None,
        root_collection_started: false,
        supervisor_artifact: artifact,
        original_cgroup: PathBuf::from("/sys/fs/cgroup"),
        process: None,
        phase: "reserved".into(),
        ever_ready: false,
        error: None,
        console_tail: String::new(),
        supervisor_stderr_tail: String::new(),
        supervisor_cgroup_events: Default::default(),
    };
    atomic_json(&directory.path().join("cfg.json"), &cfg).unwrap();
    atomic_json(&directory.path().join("seed.json"), &record).unwrap();
    (directory, cfg, record)
}

#[test]
fn owned_writer() {
    let Some(directory) = std::env::var_os("GH_ROOT_FIXTURE") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let cfg: DriverConfig = read_json(&directory.join("cfg.json")).unwrap();
    let mut record: VmJournal = read_json(&directory.join("seed.json")).unwrap();
    let path = cfg.paths(record.owner.generation).unwrap().root;
    let root = Root::create(&path, record.owner.generation).unwrap();
    record.supervisor = Some(root.receipt().producer.clone());
    record.vm_root = Some(root.receipt());
    record.phase = "preparing".into();
    atomic_json(&cfg.record_path(record.owner.sandbox_id), &record).unwrap();
    if std::env::var("GH_ROOT_ROLE").as_deref() == Ok("allocate") {
        std::fs::write(directory.join("ready"), b"actual_root_acknowledged").unwrap();
        assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
        return;
    }
    atomic_json(
        &path.join("intent.json"),
        &serde_json::json!({"generation":record.owner.generation,"owner":record.owner}),
    )
    .unwrap();
    std::fs::create_dir(path.join("payload")).unwrap();
    std::fs::write(path.join("payload/file"), b"owned").unwrap();
    let mut machine = Machine::persistent(&cfg, record).unwrap();
    machine.root_handle = Some(root);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(machine.collect(&mut GuestReport::empty(machine.generation)))
        .unwrap();
}

async fn crash_case(role: &str) {
    if unsafe { libc::geteuid() } != 0 {
        assert!(
            std::env::var_os("GH_ROOT_REQUIRE_UID0").is_none(),
            "root gate is not UID0"
        );
        return;
    }
    let (directory, cfg, seed) = fixture();
    let root = cfg.paths(seed.owner.generation).unwrap().root;
    let mut child = OwnedChild(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "machine::root_tests::owned_writer",
                "--test-threads=1",
            ])
            .env("GH_ROOT_FIXTURE", directory.path())
            .env("GH_ROOT_ROLE", role)
            .env("GH_ROOT_READY", directory.path().join("ready"))
            .env("GH_ROOT_REMOVAL_BARRIER", &root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let until = std::time::Instant::now() + Duration::from_secs(30);
    while !directory.path().join("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "owned writer exited before real cut"
        );
        assert!(
            std::time::Instant::now() < until,
            "owned writer cut not reached"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let record: VmJournal = read_json(&cfg.record_path(seed.owner.sandbox_id)).unwrap();
    assert_eq!(
        record.supervisor.as_ref().unwrap(),
        &lifecycle::process_identity(child.0.id()).unwrap()
    );
    assert!(record.vm_root.is_some() && root.exists() && !root.join("intent.json").exists());
    assert_eq!(record.root_collection_started, role == "delete");
    let before = std::fs::symlink_metadata(&root).unwrap();
    assert!(
        Machine::recover(&cfg, record.clone()).is_err(),
        "missing marker cannot advertise a live VM"
    );
    assert!(
        Machine::recover_for_collection(&cfg, record.clone()).is_err(),
        "live producer must retain authority"
    );
    child.0.kill().unwrap();
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PID,
                child.0.id(),
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOWAIT,
            )
        },
        0
    );
    assert!(
        Machine::recover_for_collection(&cfg, record.clone()).is_err(),
        "zombie is not writer absence"
    );
    child.0.wait().unwrap();
    assert!(!Path::new("/proc").join(child.0.id().to_string()).exists());
    let mut recovered = Machine::recover_for_collection(&cfg, record).unwrap();
    let after = std::fs::symlink_metadata(&root).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    let mut report = GuestReport::empty(recovered.generation);
    recovered.collect(&mut report).await.unwrap();
    assert!(report.root_absent && report.cgroup_absent && report.vmm_reaped && !root.exists());
    let final_record: VmJournal = read_json(&cfg.record_path(seed.owner.sandbox_id)).unwrap();
    assert_eq!(final_record.phase, "vm_collected");
    assert!(final_record.root_collection_started);
    drop(recovered);
    let path = directory.path().to_owned();
    directory.close().unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn actual_sigkill_after_root_ack_before_marker_recovers_same_inode() {
    crash_case("allocate").await;
}

#[tokio::test]
async fn actual_sigkill_after_marker_unlink_resumes_partial_root_collection() {
    crash_case("delete").await;
}
