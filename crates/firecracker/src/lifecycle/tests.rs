use super::*;
use std::os::unix::fs::PermissionsExt;

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
    assert!(!reaper::process_absent(&identity).unwrap());
    let mut foreign = identity.clone();
    foreign.start_ticks += 1;
    assert!(track_process(&foreign).is_err());
    assert!(reaper::process_absent(&foreign).unwrap());
    assert!(child.0.try_wait().unwrap().is_none());
    child.0.kill().unwrap();
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PID,
                identity.pid,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOWAIT,
            )
        },
        0
    );
    assert!(
        !reaper::process_absent(&identity).unwrap(),
        "a zombie is not absence"
    );
    child.0.wait().unwrap();
    assert!(reaper::process_absent(&identity).unwrap());
    assert!(pidfd_exited(&fd).unwrap());
    assert!(!Path::new("/proc").join(identity.pid.to_string()).exists());
}

#[test]
fn atomic_private_record_has_complete_bytes_and_no_pending_orphan_after_replacement() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
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
        // The permanent target mutex is retained while this store exists.
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 2);
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
        checkpoints: None,
        prepared_images: None,
        rootfs: None,
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

#[test]
fn orphan_reaping_requires_the_actual_parent() {
    use std::io::{BufRead, Write};
    const ROLE: &str = "GH_TEST_OWNED_REAPER_ROLE";
    if std::env::var(ROLE).as_deref() == Ok("reaper") {
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let output = std::process::Command::new("sh")
            .args(["-c", "sleep 0.1 >/dev/null 2>&1 & printf '%s\\n' \"$!\""])
            .output()
            .unwrap();
        assert!(output.status.success());
        let pid: u32 = std::str::from_utf8(&output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        println!("\nGH_REAPER_CHILD={pid}");
        std::io::stdout().flush().unwrap();
        let mut command = String::new();
        std::io::stdin().read_line(&mut command).unwrap();
        assert_eq!(command.trim(), "reap");
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, &mut status, 0) },
            pid as i32
        );
        assert!(!Path::new("/proc").join(pid.to_string()).exists());
        return;
    }
    struct Fixture(std::process::Child);
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(input) = self.0.stdin.as_mut() {
                let _ = input.write_all(b"reap\n");
            }
            let _ = self.0.wait();
        }
    }
    let mut fixture = Fixture(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lifecycle::tests::orphan_reaping_requires_the_actual_parent",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env(ROLE, "reaper")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let fixture_pid = fixture.0.id();
    let mut output = std::io::BufReader::new(fixture.0.stdout.take().unwrap());
    let pid = loop {
        let mut line = String::new();
        assert!(output.read_line(&mut line).unwrap() > 0);
        if let Some(value) = line.trim().strip_prefix("GH_REAPER_CHILD=") {
            break value.parse::<u32>().unwrap();
        }
    };
    let proc = Path::new("/proc").join(pid.to_string());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(proc.join("stat")).unwrap();
        let parts: Vec<_> = text
            .rsplit_once(')')
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        if parts[0] == "Z" {
            assert_eq!(parts[1].parse::<u32>().unwrap(), fixture_pid);
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(descriptor >= 0);
    let fd = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
    let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                fd.as_raw_fd() as libc::id_t,
                &mut information,
                libc::WEXITED | libc::WNOHANG,
            )
        },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert!(proc.exists(), "an exited nonchild is not a reaped process");
    fixture
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"reap\n")
        .unwrap();
    assert!(fixture.0.wait().unwrap().success());
    assert!(!proc.exists());
    assert!(!Path::new("/proc").join(fixture_pid.to_string()).exists());
}

#[test]
fn descriptor_wait_rejects_wrong_start_identity_and_reaps_only_the_owned_child() {
    struct Child(Option<std::process::Child>);
    impl Drop for Child {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let mut child = Child(Some(
        std::process::Command::new("sleep")
            .arg("10")
            .spawn()
            .unwrap(),
    ));
    let identity = process_identity(child.0.as_ref().unwrap().id()).unwrap();
    let mut wrong = identity.clone();
    wrong.start_ticks += 1;
    assert!(super::reaper::recorded(&wrong).is_err());
    assert!(child.0.as_mut().unwrap().try_wait().unwrap().is_none());
    let target = super::reaper::recorded(&identity).unwrap().unwrap();
    assert!(!target.collected().unwrap());
    child.0.as_mut().unwrap().kill().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if target.collected().unwrap() {
            child.0.take();
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!Path::new("/proc").join(identity.pid.to_string()).exists());
}
