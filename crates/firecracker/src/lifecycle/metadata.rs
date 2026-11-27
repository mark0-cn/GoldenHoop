//! Native metadata ownership. A missing marker is not permission to adopt an
//! occupied directory; an unacknowledged file create is not cleanup authority.
use super::*;
use std::io::{Seek, SeekFrom};

fn collect_temporary(path: &Path, owned: &File) -> io::Result<()> {
    let expected = owned.metadata()?;
    match std::fs::symlink_metadata(path) {
        Ok(actual)
            if actual.is_file()
                && actual.dev() == expected.dev()
                && actual.ino() == expected.ino() =>
        {
            std::fs::remove_file(path)
        }
        Ok(_) => Err(invalid(
            "atomic metadata temporary identity changed; collection unconfirmed",
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
fn publish(path: &Path, bytes: &[u8], temporary: &Path, replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("missing metadata parent"))?;
    if temporary.parent() != Some(parent) {
        return Err(invalid("metadata temporary leaves its parent").into());
    }
    let mut owned = None;
    let result = (|| -> io::Result<()> {
        // Retain the actual created descriptor. A collision or substituted
        // path must never authorize removing somebody else's file.
        owned = Some(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(temporary)?,
        );
        let file = owned
            .as_mut()
            .ok_or_else(|| invalid("metadata creation not observed"))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if replace {
            std::fs::rename(temporary, path)?;
        } else {
            let source = std::ffi::CString::new(temporary.as_os_str().as_encoded_bytes())
                .map_err(io::Error::other)?;
            let target = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
                .map_err(io::Error::other)?;
            if unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    libc::AT_FDCWD,
                    source.as_ptr(),
                    libc::AT_FDCWD,
                    target.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        File::open(parent)?.sync_all()
    })();
    if result.is_err()
        && let Some(file) = &owned
    {
        collect_temporary(temporary, file)?;
    }
    Ok(result?)
}
fn json(path: &Path, value: &impl Serialize, replace: bool) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 65536 {
        return Err(invalid("private metadata exceeds limit").into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("missing metadata parent"))?;
    let temporary = parent.join(format!(".{}.pending", Uuid::new_v4()));
    publish(path, &bytes, &temporary, replace)
}
pub(crate) fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    json(path, value, true)
}

fn marker(root: &Path, installation: Uuid) -> Result<bool> {
    let path = root.join("installation.json");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let actual: serde_json::Value = read_json(&path)?;
            if actual != serde_json::json!({"format":1,"installation_id":installation}) {
                return Err(invalid("native installation identity mismatch").into());
            }
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn unmarked_inventory(root: &Path) -> Result<()> {
    for entry in std::fs::read_dir(root)? {
        if entry?.file_name() != "installation.lock" {
            return Err(invalid("unmarked native root is occupied; refusing adoption").into());
        }
    }
    Ok(())
}
pub(super) fn claim_installation(root: &Path, installation: Uuid) -> Result<File> {
    if unsafe { libc::geteuid() } != 0 || installation.is_nil() {
        return Err(invalid("native root claim requires root and a non-nil installation").into());
    }
    private_directory(root)?;
    if !marker(root, installation)? {
        unmarked_inventory(root)?;
    }
    let path = root.join("installation.lock");
    let open = |create_new: bool| {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(create_new)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
    };
    let (mut lock, created) = match open(true) {
        Ok(file) => (file, true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (open(false)?, false),
        Err(e) => return Err(e.into()),
    };
    let actual = lock.metadata()?;
    if !actual.is_file()
        || actual.uid() != 0
        || actual.mode() & 0o777 != 0o600
        || actual.nlink() != 1
        || actual.len() > 4096
    {
        return Err(invalid("native installation lock ownership mismatch").into());
    }
    fs2::FileExt::try_lock_exclusive(&lock)
        .map_err(|_| invalid("native installation already has an owner"))?;
    let marked = marker(root, installation)?;
    if !marked {
        unmarked_inventory(root)?;
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut lock).take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(invalid("native root claim exceeds limit").into());
    }
    let expected = serde_json::json!({"format":1,"installation_id":installation,"data_root":root});
    if bytes.is_empty() {
        // A valid legacy marker authorizes upgrading its empty lock in place.
        // An existing unmarked/empty lock has no installation identity.
        if !created && !marked {
            return Err(invalid("unmarked native lock has no durable owner").into());
        }
        lock.seek(SeekFrom::Start(0))?;
        lock.write_all(&serde_json::to_vec(&expected)?)?;
        lock.sync_all()?;
        File::open(root)?.sync_all()?;
    } else if serde_json::from_slice::<serde_json::Value>(&bytes)? != expected {
        return Err(invalid("native durable root claim differs").into());
    }
    if !marked {
        // A persisted matching claim can resume a crash before marker creation.
        // Occupied/ambiguous roots and partial claims remain quarantined.
        json(
            &root.join("installation.json"),
            &serde_json::json!({"format":1,"installation_id":installation}),
            false,
        )?;
    }
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_colliding_temporary_and_a_substituted_inode_cannot_be_collected() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("record.json");
        let temporary = directory.path().join(".collision.pending");
        std::fs::write(&temporary, b"foreign").unwrap();
        assert!(publish(&target, b"{}", &temporary, true).is_err());
        assert_eq!(std::fs::read(&temporary).unwrap(), b"foreign");
        assert!(!target.exists());
        let owned = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&target)
            .unwrap();
        let original = directory.path().join("original");
        std::fs::rename(&target, &original).unwrap();
        std::fs::write(&target, b"replacement").unwrap();
        assert!(collect_temporary(&target, &owned).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"replacement");
        let path = directory.path().to_owned();
        directory.close().unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn initial_marker_never_overwrites_and_failed_rename_collects_only_its_created_file() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("installation.json");
        std::fs::write(&target, b"original").unwrap();
        let temporary = directory.path().join(".owned.pending");
        assert!(publish(&target, b"replacement", &temporary, false).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
        assert!(!temporary.exists());
        let blocked = directory.path().join("directory");
        std::fs::create_dir(&blocked).unwrap();
        assert!(publish(&blocked, b"{}", &temporary, true).is_err());
        assert!(blocked.is_dir());
        assert!(!temporary.exists());
        let path = directory.path().to_owned();
        directory.close().unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn native_root_claim_preserves_foreign_roots_and_recovers_only_its_durable_identity() {
        let installation = Uuid::new_v4();
        if unsafe { libc::geteuid() } != 0 {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("native");
            assert!(claim_installation(&root, installation).is_err());
            assert!(!root.exists());
            return;
        }
        let directory = tempfile::Builder::new()
            .prefix("goldenhoop-root-claim-")
            .tempdir_in("/var/lib")
            .unwrap();
        let root = directory.path().join("native");
        let lock = claim_installation(&root, installation).unwrap();
        assert!(claim_installation(&root, installation).is_err());
        drop(lock);
        assert!(claim_installation(&root, Uuid::new_v4()).is_err());
        std::fs::remove_file(root.join("installation.json")).unwrap();
        let recovered = claim_installation(&root, installation).unwrap();
        assert!(root.join("installation.json").exists());
        drop(recovered);
        let occupied = directory.path().join("occupied");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&occupied)
            .unwrap();
        std::fs::write(occupied.join("foreign"), b"preserve").unwrap();
        assert!(claim_installation(&occupied, installation).is_err());
        assert!(!occupied.join("installation.lock").exists());
        assert_eq!(
            std::fs::read(occupied.join("foreign")).unwrap(),
            b"preserve"
        );
        let ambiguous = directory.path().join("ambiguous");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&ambiguous)
            .unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(ambiguous.join("installation.lock"))
            .unwrap();
        assert!(claim_installation(&ambiguous, installation).is_err());
        assert!(!ambiguous.join("installation.json").exists());
        let legacy = directory.path().join("legacy");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&legacy)
            .unwrap();
        atomic_json(
            &legacy.join("installation.json"),
            &serde_json::json!({"format":1,"installation_id":installation}),
        )
        .unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(legacy.join("installation.lock"))
            .unwrap();
        let migrated = claim_installation(&legacy, installation).unwrap();
        assert!(migrated.metadata().unwrap().len() > 0);
        drop(migrated);
        let path = directory.path().to_owned();
        directory.close().unwrap();
        assert!(!path.exists());
    }
}
