use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

fn mounts() -> Result<Vec<(u64, PathBuf)>> {
    std::fs::read_to_string("/proc/self/mountinfo")?
        .lines()
        .map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 6 {
                return Err(invalid("mount observation incomplete").into());
            }
            Ok((fields[0].parse()?, PathBuf::from(fields[4])))
        })
        .collect()
}

struct OwnedMount {
    target: PathBuf,
    id: Option<u64>,
}
impl OwnedMount {
    fn collect(&mut self) -> Result<()> {
        let Some(id) = self.id else {
            return Ok(());
        };
        let before = mounts()?;
        if !before.iter().any(|(value, _)| *value == id) {
            self.id = None;
            return Ok(());
        }
        if !before
            .iter()
            .any(|(value, path)| *value == id && path == &self.target)
        {
            return Err(invalid("owned mount moved or was replaced").into());
        }
        let target = CString::new(self.target.as_os_str().as_bytes())?;
        if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if mounts()?.iter().any(|(value, _)| *value == id) {
            return Err(invalid("owned mount remains").into());
        }
        self.id = None;
        Ok(())
    }
}
impl Drop for OwnedMount {
    fn drop(&mut self) {
        let _ = self.collect();
    }
}

#[test]
#[ignore = "requires root and actual bind mounts; dedicated release gate only"]
fn actual_bind_mount_refusal_and_original_root_collection() {
    let fixture = tempfile::Builder::new()
        .prefix("ghr-")
        .tempdir_in("/var/lib")
        .unwrap();
    std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = fixture.path().join("root");
    let source = fixture.path().join("source");
    let target = path.join("mount");
    let mut mount = OwnedMount {
        target: target.clone(),
        id: None,
    };
    let mut root = None;
    let mut cases = Vec::new();
    let mut observed = serde_json::json!({"fixture":fixture.path(),"root":path});
    let result = (|| -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(invalid("actual root mount gate requires UID0").into());
        }
        root = Some(Root::create(&path, Uuid::new_v4())?);
        let root = root
            .as_ref()
            .ok_or_else(|| invalid("root receipt unobserved"))?;
        observed["receipt"] = serde_json::to_value(root.receipt())?;
        std::fs::create_dir(&source)?;
        std::fs::write(source.join("sentinel"), b"must remain")?;
        std::fs::create_dir(&target)?;
        let csource = CString::new(source.as_os_str().as_bytes())?;
        let ctarget = CString::new(target.as_os_str().as_bytes())?;
        if unsafe {
            libc::mount(
                csource.as_ptr(),
                ctarget.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        mount.id = mounts()?
            .iter()
            .find(|(_, path)| path == &target)
            .map(|(id, _)| *id);
        if mount.id.is_none() {
            return Err(invalid("created bind mount identity unobserved").into());
        }
        observed["mount_id"] = serde_json::json!(mount.id);
        if root.remove_all().is_ok() || std::fs::read(source.join("sentinel"))? != b"must remain" {
            return Err(invalid("mounted source was not preserved").into());
        }
        root.verify()?;
        cases.push("actual_bind_mount_crossing_refused_and_source_sentinel_preserved");
        mount.collect()?;
        root.remove_all()?;
        if !absent(&path)? || std::fs::read(source.join("sentinel"))? != b"must remain" {
            return Err(
                invalid("original root collection or source preservation unconfirmed").into(),
            );
        }
        cases.push("actual_unmounted_original_root_inode_collected");
        Ok(())
    })();
    let cleanup = (|| -> Result<()> {
        mount.collect()?;
        // No unknown mount may be hidden by recursive fixture collection.
        if mounts()?
            .iter()
            .any(|(_, path)| path.starts_with(fixture.path()))
        {
            return Err(invalid("fixture retains an unconfirmed mount").into());
        }
        if let Some(root) = &root
            && !absent(&path)?
        {
            root.remove_all()?;
        }
        Ok(())
    })();
    drop(root);
    let fixture_path = fixture.path().to_owned();
    let cleanup = match cleanup {
        Ok(()) => fixture.close().map_err(Into::into),
        Err(error) => {
            let _retained = fixture.keep();
            Err(error)
        }
    };
    let gone = absent(&fixture_path).unwrap_or(false);
    observed["fixture_absent"] = serde_json::json!(gone);
    let report = serde_json::json!({"suite":"actual VM root bind-mount refusal","result":if result.is_ok()&&cleanup.is_ok()&&gone {"passed"}else{"failed"},
        "cleanup":if cleanup.is_ok()&&gone {"complete"}else{"unknown"},"cases":cases,"observations":observed,
        "error":result.as_ref().err().map(ToString::to_string),"cleanup_error":cleanup.as_ref().err().map(ToString::to_string),
        "scope":"actual root descriptor/mount refusal and exact inode collection; no KVM or production-manager cut claim"});
    println!("GH_ROOT_FILESYSTEM_CONTRACT={report}");
    assert!(result.is_ok() && cleanup.is_ok() && gone, "{report}");
}

pub(super) fn barrier(path: &Path, name: &OsStr) {
    if name == OsStr::new("intent.json")
        && std::env::var_os("GH_ROOT_REMOVAL_BARRIER").is_some_and(|v| Path::new(&v) == path)
    {
        let ready = std::env::var_os("GH_ROOT_READY").expect("owned root barrier ready path");
        std::fs::write(ready, b"actual_marker_unlinked").expect("root barrier observation");
        assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
    }
}

#[test]
fn actual_root_receipt_refuses_replacement_links_copied_header_birth_and_context() {
    if unsafe { libc::geteuid() } != 0 {
        assert!(
            std::env::var_os("GH_ROOT_REQUIRE_UID0").is_none(),
            "root gate is not UID0"
        );
        return;
    }
    let fixture = tempfile::Builder::new()
        .prefix("ghr-")
        .tempdir_in("/var/lib")
        .unwrap();
    std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = fixture.path().join("root");
    let generation = Uuid::new_v4();
    let root = Root::create(&path, generation).unwrap();
    let receipt = root.receipt();
    std::fs::write(path.join("owned"), b"original").unwrap();
    assert!(Root::recorded(&path, None, generation, Some(&receipt.producer)).is_err());
    assert!(
        Root::recorded(
            &path,
            Some(&receipt),
            Uuid::new_v4(),
            Some(&receipt.producer)
        )
        .is_err()
    );
    for field in ["birth_nanoseconds", "pid_namespace_inode"] {
        let mut changed = serde_json::to_value(&receipt).unwrap();
        changed[field] = serde_json::json!(changed[field].as_u64().unwrap() + 1);
        let changed = serde_json::from_value(changed).unwrap();
        assert!(
            Root::recorded(&path, Some(&changed), generation, Some(&receipt.producer)).is_err()
        );
    }
    let retained = fixture.path().join("retained");
    std::fs::rename(&path, &retained).unwrap();
    let replacement = Root::create(&path, Uuid::new_v4()).unwrap();
    std::fs::write(path.join("owned"), b"replacement").unwrap();
    // Even a copied complete xattr does not transfer the original inode/birth.
    let bytes = serde_json::to_vec(&receipt).unwrap();
    assert_eq!(
        unsafe {
            libc::fsetxattr(
                replacement.directory.as_raw_fd(),
                ATTRIBUTE.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
            )
        },
        0
    );
    assert!(root.remove_all().is_err());
    assert!(Root::recorded(&path, Some(&receipt), generation, Some(&receipt.producer)).is_err());
    assert_eq!(std::fs::read(retained.join("owned")).unwrap(), b"original");
    assert_eq!(std::fs::read(path.join("owned")).unwrap(), b"replacement");
    drop(replacement);
    // This is a fixture-created replacement, not production recovery authority.
    std::fs::remove_dir_all(&path).unwrap();
    let foreign = fixture.path().join("foreign");
    std::fs::create_dir(&foreign).unwrap();
    std::fs::write(foreign.join("sentinel"), b"preserved").unwrap();
    symlink(&foreign, &path).unwrap();
    assert!(root.remove_all().is_err());
    assert!(Root::recorded(&path, Some(&receipt), generation, Some(&receipt.producer)).is_err());
    assert!(!absent(&path).unwrap());
    assert_eq!(
        std::fs::read(foreign.join("sentinel")).unwrap(),
        b"preserved"
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&retained, &path).unwrap();
    // Symlinks inside the owned root are unlinked, never followed.
    symlink(&foreign, path.join("link")).unwrap();
    root.remove_all().unwrap();
    assert!(absent(&path).unwrap());
    assert_eq!(
        std::fs::read(foreign.join("sentinel")).unwrap(),
        b"preserved"
    );
    drop(root);
    let path = fixture.path().to_owned();
    fixture.close().unwrap();
    assert!(!path.exists());
}
