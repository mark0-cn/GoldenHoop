use super::*;
use std::{
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    process::{Command, Stdio},
};

const CHILD: &str = "lifecycle::metadata::atomic::tests::metadata_writer_child";
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn directory() -> tempfile::TempDir {
    let result = tempfile::Builder::new()
        .prefix("ghmeta-")
        .tempdir_in(if unsafe { libc::geteuid() } == 0 {
            "/var/lib"
        } else {
            "/tmp"
        })
        .unwrap();
    std::fs::set_permissions(result.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    result
}
fn start(root: &Path, target: &str, bytes: &[u8], stage: &str) -> Child {
    let mut child = Child(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD, "--nocapture"])
            .env("GH_METADATA_TEST_ROOT", root)
            .env("GH_METADATA_TEST_TARGET", target)
            .env(
                "GH_METADATA_TEST_VALUE",
                std::str::from_utf8(bytes).unwrap(),
            )
            .env("GH_METADATA_TEST_STAGE", stage)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !root.join("child-ready").exists() {
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut message = String::new();
            if let Some(mut output) = child.0.stderr.take() {
                output.read_to_string(&mut message).unwrap();
            }
            panic!("metadata child exited before barrier: {status}: {message}");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "metadata child barrier deadline"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    child
}
fn kill(child: &mut Child) {
    let original = process_identity(child.0.id()).unwrap();
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(super::super::super::reaper::process_absent(&original).unwrap());
}
fn pending(root: &Path) -> Vec<String> {
    pending_names(&Parent::open(root).unwrap()).unwrap()
}
fn close(directory: tempfile::TempDir) {
    let path = directory.path().to_owned();
    directory.close().unwrap();
    assert!(!path.exists());
}
fn regular(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn metadata_writer_child() {
    let Some(root) = std::env::var_os("GH_METADATA_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let target = std::env::var("GH_METADATA_TEST_TARGET").unwrap();
    let value = std::env::var("GH_METADATA_TEST_VALUE").unwrap();
    let barrier = std::env::var("GH_METADATA_TEST_STAGE").unwrap();
    write_observed(&root.join(target), value.as_bytes(), true, |stage| {
        if stage == barrier {
            regular(&root.join("child-ready"), stage.as_bytes());
            let deadline = std::time::Instant::now() + Duration::from_secs(40);
            while std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("fixture parent did not collect its stopped writer");
        }
    })
    .unwrap();
    panic!("metadata writer did not stop at its requested barrier");
}

#[test]
fn actual_sigkill_at_each_publication_boundary_recovers_the_original_inode_without_replay() {
    for existing in [false, true] {
        for stage in ["anonymous_synced", "pending_synced", "published_synced"] {
            let directory = directory();
            let root = directory.path();
            let target = root.join("record.json");
            if existing {
                write(&target, br#"{"version":"old"}"#, true).unwrap();
            }
            let before = if existing {
                Some(std::fs::read(&target).unwrap())
            } else {
                None
            };
            let mut child = start(root, "record.json", br#"{"version":"new"}"#, stage);
            let original_pending = pending(root);
            let expected_inode = if stage == "pending_synced" {
                assert_eq!(original_pending.len(), 1);
                let inode =
                    Inode::of(&std::fs::symlink_metadata(root.join(&original_pending[0])).unwrap());
                let live = recover(root, &[], true, |_, _| Ok(())).unwrap();
                assert_eq!(live.unconfirmed, ["record.json"]);
                assert_eq!(pending(root), original_pending);
                assert_eq!(std::fs::read(&target).ok(), before);
                // A different target remains writable while this writer still
                // holds its actual descriptor-bound kernel mutex.
                write(&root.join("other.json"), b"{}", true).unwrap();
                Some(inode)
            } else {
                None
            };
            kill(&mut child);
            let observed = recover(root, &[], false, |_, _| Ok(())).unwrap();
            assert!(observed.unconfirmed.is_empty() && pending(root).is_empty());
            if stage == "anonymous_synced" {
                assert!(observed.completed.is_empty());
                assert_eq!(std::fs::read(&target).ok(), before);
            } else {
                assert_eq!(std::fs::read(&target).unwrap(), br#"{"version":"new"}"#);
                if let Some(inode) = expected_inode {
                    assert_eq!(observed.completed, ["record.json"]);
                    assert_eq!(
                        Inode::of(&std::fs::symlink_metadata(&target).unwrap()),
                        inode
                    );
                }
            }
            assert!(
                recover(root, &[], false, |_, _| Ok(()))
                    .unwrap()
                    .completed
                    .is_empty()
            );
            close(directory);
        }
    }
}

#[test]
fn changed_target_pending_mutex_parent_or_content_is_preserved_without_publication() {
    for change in [
        "target",
        "pending",
        "mutex",
        "content",
        "symlink",
        "hardlink",
        "copied_parent",
    ] {
        let directory = directory();
        let root = directory.path();
        let target = root.join("record.json");
        write(&target, br#"{"version":"old"}"#, true).unwrap();
        let mut child = start(
            root,
            "record.json",
            br#"{"version":"new"}"#,
            "pending_synced",
        );
        kill(&mut child);
        let name = pending(root).pop().unwrap();
        let temporary = root.join(&name);
        let old_target = std::fs::read(&target).unwrap();
        let mut extra = None;
        match change {
            "target" => {
                std::fs::rename(&target, root.join("saved-target")).unwrap();
                regular(&target, &old_target); // identical bytes still differ in inode
            }
            "pending" => {
                std::fs::rename(&temporary, root.join("saved-pending")).unwrap();
                regular(&temporary, br#"{"foreign":true}"#);
            }
            "mutex" => {
                let path = root.join(mutex_name("record.json"));
                let bytes = std::fs::read(&path).unwrap();
                std::fs::rename(&path, root.join("saved-mutex")).unwrap();
                regular(&path, &bytes);
            }
            "content" => {
                std::fs::write(&temporary, br#"{"tampered":true}"#).unwrap();
            }
            "symlink" => {
                std::fs::rename(&temporary, root.join("saved-pending")).unwrap();
                std::os::unix::fs::symlink(&target, &temporary).unwrap();
            }
            "hardlink" => {
                std::fs::hard_link(&temporary, root.join("extra-link")).unwrap();
            }
            "copied_parent" => {
                let copied = self::directory();
                for entry in std::fs::read_dir(root).unwrap() {
                    let entry = entry.unwrap();
                    let destination = copied.path().join(entry.file_name());
                    std::fs::copy(entry.path(), &destination).unwrap();
                    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                // Preserve the actual receipt as a controlled copied-context
                // fault, without claiming a genuine process namespace reuse.
                let parent = Parent::open(root).unwrap();
                let (file, _) = raw_receipt(&parent, &name).unwrap().unwrap();
                let mut bytes = [0u8; RECEIPT_LIMIT];
                let n = unsafe {
                    libc::fgetxattr(
                        file.as_raw_fd(),
                        ATTRIBUTE.as_ptr().cast(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                    )
                };
                assert!(n > 0);
                let dest = File::open(copied.path().join(&name)).unwrap();
                assert_eq!(
                    unsafe {
                        libc::fsetxattr(
                            dest.as_raw_fd(),
                            ATTRIBUTE.as_ptr().cast(),
                            bytes.as_ptr().cast(),
                            n as usize,
                            libc::XATTR_CREATE,
                        )
                    },
                    0
                );
                assert!(recover(copied.path(), &[], false, |_, _| Ok(())).is_err());
                assert_eq!(
                    std::fs::read(copied.path().join("record.json")).unwrap(),
                    old_target
                );
                assert!(copied.path().join(&name).exists());
                extra = Some(copied);
            }
            _ => unreachable!(),
        }
        if change != "copied_parent" {
            assert!(
                recover(root, &[], false, |_, _| Ok(())).is_err(),
                "{change}"
            );
            assert_eq!(std::fs::read(&target).unwrap(), old_target);
            assert!(std::fs::symlink_metadata(&temporary).is_ok());
        }
        if let Some(copied) = extra {
            close(copied);
        }
        close(directory);
    }
}

#[test]
fn root_claim_recovers_killed_lock_or_marker_publication_only_for_its_durable_installation() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    for target in ["installation.lock", "installation.json"] {
        let directory = directory();
        let root = directory.path();
        let installation = Uuid::new_v4();
        if target == "installation.json" {
            drop(super::super::claim_installation(root, installation).unwrap());
            std::fs::remove_file(root.join(target)).unwrap();
        }
        let value = if target == "installation.lock" {
            serde_json::json!({"format":1,"installation_id":installation,"data_root":root})
        } else {
            serde_json::json!({"format":1,"installation_id":installation})
        };
        let mut child = start(
            root,
            target,
            &serde_json::to_vec(&value).unwrap(),
            "pending_synced",
        );
        kill(&mut child);
        assert_eq!(
            std::fs::read(root.join("child-ready")).unwrap(),
            b"pending_synced"
        );
        std::fs::remove_file(root.join("child-ready")).unwrap();
        let name = pending(root).pop().unwrap();
        let inode = Inode::of(&std::fs::symlink_metadata(root.join(&name)).unwrap());
        assert!(super::super::claim_installation(root, Uuid::new_v4()).is_err());
        assert_eq!(pending(root), [name]);
        let claim = super::super::claim_installation(root, installation).unwrap();
        assert_eq!(
            Inode::of(&std::fs::symlink_metadata(root.join(target)).unwrap()),
            inode
        );
        assert!(root.join("installation.json").exists() && pending(root).is_empty());
        assert!(super::super::claim_installation(root, installation).is_err());
        drop(claim);
        close(directory);
    }
}

#[test]
fn new_publication_never_overwrites_a_conflict_or_collects_a_substituted_pending() {
    let directory = directory();
    let root = directory.path();
    let target = root.join("record.json");
    write(&target, b"{}", false).unwrap();
    let initial = std::fs::read(&target).unwrap();
    assert!(write(&target, br#"{"replace":true}"#, false).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), initial);
    let result = write_observed(&target, br#"{"new":true}"#, true, |stage| {
        if stage == "pending_synced" {
            let name = pending(root).pop().unwrap();
            let path = root.join(name);
            std::fs::rename(&path, root.join("actual-owned-pending")).unwrap();
            regular(&path, br#"{"foreign":true}"#);
        }
    });
    assert!(result.is_err());
    assert_eq!(std::fs::read(&target).unwrap(), initial);
    let name = pending(root).pop().unwrap();
    assert_eq!(
        std::fs::read(root.join(name)).unwrap(),
        br#"{"foreign":true}"#
    );
    close(directory);
}
