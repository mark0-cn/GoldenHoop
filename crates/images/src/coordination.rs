//! Permanent inode locks fence local image dispatchers, including after a
//! process dies. A lock is coordination metadata, never a cleanup capability.
use goldenhoop_artifacts::BlobStore;
use goldenhoop_protocol::{ApiError, ErrorCode};
use goldenhoop_store::Store;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

fn conflict(message: &str) -> ApiError {
    ApiError::new(ErrorCode::Conflict, message)
}
pub(crate) fn recovery_storage(blobs: &BlobStore) -> Result<(), ApiError> {
    use std::os::unix::ffi::OsStrExt;
    let unsupported = || {
        ApiError::new(
            ErrorCode::UnsupportedCapability,
            "image recovery requires local kernel filesystem storage; remote writer settlement is unconfirmed",
        )
    };
    let root = blobs.local_root().ok_or_else(unsupported)?;
    let path = std::ffi::CString::new(root.as_os_str().as_bytes()).map_err(|_| unsupported())?;
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: both pointers remain live and the result is read only on success.
    if unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(unsupported());
    }
    let kind = unsafe { stat.assume_init() }.f_type;
    // ext*, XFS, Btrfs, tmpfs and kernel overlayfs. In particular, a path-style
    // NFS/CIFS/FUSE store is not fenced by the producer's process exit.
    if ![0xef53, 0x58465342, 0x9123683e, 0x01021994, 0x794c7630].contains(&kind) {
        return Err(unsupported());
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Stamp {
    format: u32,
    engine_id: String,
    boot_id: Uuid,
    database_device: u64,
    database_inode: u64,
    lock_device: u64,
    lock_inode: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Producer {
    pid: u32,
    start_ticks: u64,
    pid_namespace: u64,
}
fn start_ticks(pid: u32) -> Result<Option<u64>, ApiError> {
    let file = match File::open(format!("/proc/{pid}/stat")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(conflict("image producer observation is unavailable")),
    };
    let mut text = String::new();
    file.take(4097)
        .read_to_string(&mut text)
        .map_err(|_| conflict("invalid image producer stat"))?;
    if text.len() > 4096 {
        return Err(conflict("invalid image producer stat"));
    }
    if !text.starts_with(&format!("{pid} (")) {
        return Err(conflict("image producer stat identity differs"));
    }
    let ticks = text
        .rsplit_once(") ")
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| conflict("invalid image producer stat"))?;
    // A zombie still has this identity. Only actual absence or a different
    // start time establishes that the recorded producer has gone.
    Ok(Some(ticks))
}
impl Producer {
    pub(crate) fn current() -> Result<Self, ApiError> {
        let pid = std::process::id();
        Ok(Self {
            pid,
            start_ticks: start_ticks(pid)?
                .ok_or_else(|| conflict("current image producer is absent"))?,
            pid_namespace: fs::metadata("/proc/self/ns/pid")
                .map_err(|_| conflict("PID namespace is unavailable"))?
                .ino(),
        })
    }
    pub(crate) fn require_gone(&self) -> Result<(), ApiError> {
        if self.pid == 0
            || self.pid > i32::MAX as u32
            || self.start_ticks == 0
            || self.pid_namespace == 0
        {
            return Err(conflict("recorded image producer identity is invalid"));
        }
        let current = fs::metadata("/proc/self/ns/pid")
            .map_err(|_| conflict("PID namespace is unavailable"))?
            .ino();
        if current != self.pid_namespace {
            return Err(conflict(
                "image producer PID namespace differs; death is unconfirmed",
            ));
        }
        if start_ticks(self.pid)? == Some(self.start_ticks) {
            return Err(conflict("recorded image producer is still present"));
        }
        Ok(())
    }
}
#[derive(Clone)]
#[cfg_attr(test, derive(Serialize, Deserialize))]
pub(crate) struct Coordinator {
    database: PathBuf,
    installation: Uuid,
    engine_id: String,
    boot_id: Uuid,
}
pub(crate) struct Lease {
    _file: File,
    pub(crate) stamp: Stamp,
}
impl Lease {
    pub(crate) fn check(
        &self,
        recorded: Option<&Stamp>,
        stable_legacy: bool,
    ) -> Result<(), ApiError> {
        match recorded {
            Some(value) if *value == self.stamp => Ok(()),
            None if stable_legacy => Ok(()),
            _ => Err(conflict(
                "image producer/provider/database identity differs or is unrecorded",
            )),
        }
    }
}
fn trusted_database(path: &Path) -> Result<fs::Metadata, ApiError> {
    if unsafe { libc::geteuid() } != 0
        || !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(conflict(
            "image coordination requires a trusted root database",
        ));
    }
    let mut ancestor = path.parent();
    while let Some(parent) = ancestor {
        let meta = fs::symlink_metadata(parent)
            .map_err(|_| conflict("image database ancestry is unavailable"))?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != 0
            || meta.mode() & 0o022 != 0
        {
            return Err(conflict("image database ancestry is not trusted"));
        }
        ancestor = parent.parent();
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| conflict("image database is unavailable"))?;
    let meta = file
        .metadata()
        .map_err(|_| conflict("image database metadata is unavailable"))?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
        return Err(conflict("image database ownership/type/link count differs"));
    }
    Ok(meta)
}
impl Coordinator {
    pub(crate) async fn connect(store: &Store, engine_id: String) -> Result<Self, ApiError> {
        let database = store.image_job_database_path().await?;
        let boot_id = Uuid::parse_str(
            fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| conflict("host boot identity is unavailable"))?
                .trim(),
        )
        .map_err(|_| conflict("host boot identity is invalid"))?;
        let result = Self {
            database,
            installation: store.installation_id(),
            engine_id,
            boot_id,
        };
        trusted_database(&result.database)?;
        if result.installation.is_nil()
            || result.boot_id.is_nil()
            || result.engine_id.is_empty()
            || result.engine_id.len() > 128
            || !result.engine_id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(conflict("image coordinator identity is invalid"));
        }
        Ok(result)
    }
    pub(crate) fn acquire(&self, id: Uuid) -> Result<Lease, ApiError> {
        self.acquire_mode(id, libc::LOCK_EX)
    }
    pub(crate) fn acquire_reader(&self, id: Uuid) -> Result<Lease, ApiError> {
        self.acquire_mode(id, libc::LOCK_SH)
    }
    fn acquire_mode(&self, id: Uuid, mode: libc::c_int) -> Result<Lease, ApiError> {
        if id.is_nil() {
            return Err(conflict("invalid image job lock identity"));
        }
        let database = trusted_database(&self.database)?;
        let parent = self
            .database
            .parent()
            .ok_or_else(|| conflict("image database has no parent"))?;
        let path = parent.join(format!(
            ".goldenhoop-image-{}-{}.lock",
            self.installation.simple(),
            id.simple()
        ));
        let open = || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
        };
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => {
                file.sync_all()
                    .map_err(|_| conflict("image lock sync failed"))?;
                File::open(parent)
                    .and_then(|file| file.sync_all())
                    .map_err(|_| conflict("image lock parent sync failed"))?;
                file
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                open().map_err(|_| conflict("image lock cannot be opened"))?
            }
            Err(_) => return Err(conflict("image lock cannot be created")),
        };
        let check = |meta: &fs::Metadata| {
            meta.is_file()
                && meta.uid() == 0
                && meta.mode() & 0o7777 == 0o600
                && meta.nlink() == 1
                && meta.len() == 0
        };
        let meta = file
            .metadata()
            .map_err(|_| conflict("image lock metadata is unavailable"))?;
        if !check(&meta) {
            return Err(conflict("image lock ownership/type/content differs"));
        }
        // SAFETY: flock uses this live descriptor and nonblocking integer flags.
        if unsafe { libc::flock(file.as_raw_fd(), mode | libc::LOCK_NB) } != 0 {
            return Err(conflict("image job has an active producer or collector"));
        }
        let actual =
            fs::symlink_metadata(&path).map_err(|_| conflict("image lock path disappeared"))?;
        if !check(&actual) || actual.dev() != meta.dev() || actual.ino() != meta.ino() {
            return Err(conflict("image lock path identity changed"));
        }
        Ok(Lease {
            stamp: Stamp {
                format: 1,
                engine_id: self.engine_id.clone(),
                boot_id: self.boot_id,
                database_device: database.dev(),
                database_inode: database.ino(),
                lock_device: meta.dev(),
                lock_inode: meta.ino(),
            },
            _file: file,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn actual_shared_readers_coexist_and_exclude_producers_until_both_release() {
        let Some((directory, coordinator)) = fixture() else {
            return;
        };
        let id = Uuid::new_v4();
        let release = |lease: Lease| {
            // Explicit fixture unlock avoids a parallel test fork temporarily
            // retaining this test's descriptions until its CLOEXEC completes.
            assert_eq!(
                unsafe { libc::flock(lease._file.as_raw_fd(), libc::LOCK_UN) },
                0
            );
            drop(lease);
        };
        let producer = coordinator.acquire(id).unwrap();
        assert!(coordinator.acquire_reader(id).is_err());
        let stamp = producer.stamp.clone();
        release(producer);
        let first = coordinator.acquire_reader(id).unwrap();
        let second = coordinator.acquire_reader(id).unwrap();
        first.check(Some(&stamp), false).unwrap();
        second.check(Some(&stamp), false).unwrap();
        assert!(coordinator.acquire(id).is_err());
        release(first);
        assert!(coordinator.acquire(id).is_err());
        release(second);
        release(coordinator.acquire(id).unwrap());
        directory.close().unwrap();
    }

    fn fixture() -> Option<(tempfile::TempDir, Coordinator)> {
        if unsafe { libc::geteuid() } != 0 {
            assert!(trusted_database(Path::new("/var/lib/unavailable-image.db")).is_err());
            return None;
        }
        // /tmp is deliberately not trusted for dispatcher state.
        let directory = tempfile::Builder::new()
            .prefix("goldenhoop-image-lock-")
            .tempdir_in("/var/lib")
            .unwrap();
        let database = directory.path().join("image.db");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&database)
            .unwrap();
        let coordinator = Coordinator {
            database,
            installation: Uuid::new_v4(),
            engine_id: "test-engine".into(),
            boot_id: Uuid::new_v4(),
        };
        Some((directory, coordinator))
    }
    #[test]
    fn remote_storage_does_not_inherit_a_local_process_fence() {
        let remote = BlobStore::s3(
            goldenhoop_artifacts::S3Config {
                endpoint: "https://s3.invalid".into(),
                bucket: "fixture".into(),
                region: "test-1".into(),
                access_key_id: "fixture".into(),
                secret_access_key: "fixture".into(),
                session_token: None,
            },
            Uuid::new_v4(),
        )
        .unwrap();
        assert!(remote.local_root().is_none());
        assert_eq!(
            recovery_storage(&remote).unwrap_err().code,
            ErrorCode::UnsupportedCapability
        );
        let Some((directory, coordinator)) = fixture() else {
            return;
        };
        let local =
            BlobStore::local(&directory.path().join("blobs"), coordinator.installation).unwrap();
        recovery_storage(&local).unwrap();
        directory.close().unwrap();
    }
    #[test]
    fn lock_is_exclusive_and_binds_provider_database_and_permanent_inode() {
        let Some((directory, coordinator)) = fixture() else {
            return;
        };
        let id = Uuid::new_v4();
        let first = coordinator.acquire(id).unwrap();
        assert!(coordinator.acquire(id).is_err());
        let stamp = first.stamp.clone();
        assert!(first.check(None, false).is_err());
        assert!(first.check(None, true).is_ok());
        drop(first);
        let next = coordinator.acquire(id).unwrap();
        next.check(Some(&stamp), false).unwrap();
        let mut foreign = stamp.clone();
        foreign.engine_id = "another-engine".into();
        assert!(next.check(Some(&foreign), true).is_err());
        foreign = stamp;
        foreign.database_inode = foreign.database_inode.wrapping_add(1);
        assert!(next.check(Some(&foreign), true).is_err());
        drop(next);
        directory.close().unwrap();
    }
    #[test]
    fn aliased_database_and_populated_or_aliased_lock_are_refused() {
        let Some((directory, coordinator)) = fixture() else {
            return;
        };
        let alias = directory.path().join("alias.db");
        symlink(&coordinator.database, &alias).unwrap();
        assert!(trusted_database(&alias).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&coordinator.database, &alias).unwrap();
        assert!(coordinator.acquire(Uuid::new_v4()).is_err());
        fs::remove_file(&alias).unwrap();
        let id = Uuid::new_v4();
        let lease = coordinator.acquire(id).unwrap();
        let lock = directory.path().join(format!(
            ".goldenhoop-image-{}-{}.lock",
            coordinator.installation.simple(),
            id.simple()
        ));
        drop(lease);
        fs::write(&lock, b"unexpected content").unwrap();
        assert!(coordinator.acquire(id).is_err());
        fs::remove_file(&lock).unwrap();
        symlink(&coordinator.database, &lock).unwrap();
        assert!(coordinator.acquire(id).is_err());
        fs::remove_file(&lock).unwrap();
        let lease = coordinator.acquire(id).unwrap();
        let stamp = lease.stamp.clone();
        // Keep the old inode open so the replacement cannot reuse its identity.
        fs::remove_file(&lock).unwrap();
        let replacement = coordinator.acquire(id).unwrap();
        assert!(replacement.check(Some(&stamp), false).is_err());
        drop(replacement);
        drop(lease);
        fs::set_permissions(&coordinator.database, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(coordinator.acquire(id).is_err());
        directory.close().unwrap();
    }

    struct Child(Option<std::process::Child>);
    impl Drop for Child {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    #[test]
    fn actual_sigkill_releases_mutex_and_process_identity_requires_reaping() {
        const CHILD: &str = "GOLDENHOOP_IMAGE_LOCK_TEST_CHILD";
        if let Some(raw) = std::env::var_os(CHILD) {
            use std::io::Write;
            let (coordinator, id): (Coordinator, Uuid) =
                serde_json::from_str(raw.to_str().unwrap()).unwrap();
            let _lease = coordinator.acquire(id).unwrap();
            let ready = coordinator.database.with_extension("child-ready");
            let bytes = serde_json::to_vec(&Producer::current().unwrap()).unwrap();
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(ready)
                .unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
            loop {
                std::thread::park();
            }
        }
        let Some((directory, coordinator)) = fixture() else {
            return;
        };
        let id = Uuid::new_v4();
        let lease = coordinator.acquire(id).unwrap();
        let stamp = lease.stamp.clone();
        drop(lease);
        let mut child = Child(Some(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "coordination::tests::actual_sigkill_releases_mutex_and_process_identity_requires_reaping"])
            .env(CHILD, serde_json::to_string(&(coordinator.clone(), id)).unwrap())
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).spawn().unwrap()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut producer: Producer = loop {
            if let Ok(bytes) = fs::read(coordinator.database.with_extension("child-ready"))
                && let Ok(value) = serde_json::from_slice(&bytes)
            {
                break value;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child did not acquire its lock"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let pid = child.0.as_ref().unwrap().id();
        assert_eq!(producer.pid, pid);
        assert!(producer.require_gone().is_err());
        assert!(coordinator.acquire(id).is_err());
        child.0.as_mut().unwrap().kill().unwrap();
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid,
                    info.as_mut_ptr(),
                    libc::WEXITED | libc::WNOWAIT,
                )
            },
            0
        );
        assert!(producer.require_gone().is_err());
        use std::os::unix::process::ExitStatusExt;
        let status = child.0.as_mut().unwrap().wait().unwrap();
        child.0 = None;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        producer.require_gone().unwrap();
        let next = coordinator.acquire(id).unwrap();
        next.check(Some(&stamp), false).unwrap();
        producer.pid_namespace = producer.pid_namespace.wrapping_add(1);
        assert!(producer.require_gone().is_err());
        drop(next);
        directory.close().unwrap();
    }
}
