//! Native metadata ownership. A missing marker is not permission to adopt an
//! occupied directory; an unacknowledged file create is not cleanup authority.
use super::*;
use std::io::{Seek, SeekFrom};

mod atomic;
pub(super) use atomic::Recovery;
pub(super) fn recover_entries(
    root: &Path,
    targets: &[&str],
    allow_unconfirmed: bool,
    verify: impl Fn(&str, &[u8]) -> Result<()>,
) -> Result<Recovery> {
    atomic::recover(root, targets, allow_unconfirmed, verify)
}
fn json(path: &Path, value: &impl Serialize, replace: bool) -> Result<()> {
    atomic::write(path, &serde_json::to_vec(value)?, replace)
}
pub(crate) fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    json(path, value, true)
}
pub(super) fn initial_json(path: &Path, value: &impl Serialize) -> Result<()> {
    json(path, value, false)
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
pub(super) fn claim_installation(root: &Path, installation: Uuid) -> Result<File> {
    if unsafe { libc::geteuid() } != 0 || installation.is_nil() {
        return Err(invalid("native root claim requires root and a non-nil installation").into());
    }
    private_directory(root)?;
    let expected = serde_json::json!({"format":1,"installation_id":installation,"data_root":root});
    if !marker(root, installation)? {
        atomic::unmarked_inventory(root, installation)?;
    }
    recover_entries(root, &["installation.lock"], false, |name, bytes| {
        atomic::claim_bytes(root, installation, name, bytes)
    })?;
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
    // Publish a complete lock claim from an unnamed inode. A crash cannot leave
    // a newly created empty/partial installation lock with no durable identity.
    let (mut lock, created) = match open(false) {
        Ok(file) => (file, false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => match initial_json(&path, &expected) {
            Ok(()) => (open(false)?, true),
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::AlreadyExists) =>
            {
                (open(false)?, false)
            }
            Err(error) => return Err(error),
        },
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
        atomic::unmarked_inventory(root, installation)?;
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut lock).take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(invalid("native root claim exceeds limit").into());
    }
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
    recover_entries(root, &["installation.json"], false, |name, bytes| {
        atomic::claim_bytes(root, installation, name, bytes)
    })?;
    let marked = marker(root, installation)?;
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
