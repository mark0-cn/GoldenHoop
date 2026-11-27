use super::*;
use std::{
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::symlink,
};

struct Fixture {
    directory: tempfile::TempDir,
    manifest: CheckpointManifest,
    reference: CheckpointReference,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("ghc-content-")
            .tempdir_in("/var/lib")
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["source", "staging"] {
            let path = directory.path().join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut manifest = super::super::tests::fixture();
        for (name, content) in [
            ("state", &mut manifest.state),
            ("memory", &mut manifest.memory),
            ("disk", &mut manifest.disk),
        ] {
            let path = directory.path().join("source").join(name);
            let mut file = File::create(&path).unwrap();
            file.set_len(content.size_bytes).unwrap();
            file.write_all(name.as_bytes()).unwrap();
            file.seek(SeekFrom::Start(content.size_bytes - 4)).unwrap();
            file.write_all(b"tail").unwrap();
            file.sync_all().unwrap();
            drop(file);
            content.sha256 = crate::fileio::digest(File::open(path).unwrap()).unwrap().0;
        }
        let reference = manifest.reference().unwrap();
        Self {
            directory,
            manifest,
            reference,
        }
    }
    fn staging(&self) -> std::path::PathBuf {
        self.directory.path().join("staging")
    }
    fn inputs(&self) -> CheckpointFiles {
        let open = |name| File::open(self.directory.path().join("source").join(name)).unwrap();
        CheckpointFiles {
            state: open("state"),
            memory: open("memory"),
            disk: open("disk"),
        }
    }
    fn materialize(&self) -> io::Result<StagedCheckpoint> {
        StagedCheckpoint::materialize(
            self.manifest.clone(),
            &self.reference,
            &self.manifest.runtime,
            192 * MIB + 1024,
            self.inputs(),
            0,
            &self.staging(),
        )
    }
    fn assert_empty_staging(&self) {
        assert_eq!(std::fs::read_dir(self.staging()).unwrap().count(), 0);
        for fd in std::fs::read_dir("/proc/self/fd").unwrap().flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                let prefix = format!("{}/#", self.staging().display());
                assert!(
                    !link
                        .as_os_str()
                        .as_encoded_bytes()
                        .starts_with(prefix.as_bytes()),
                    "anonymous checkpoint fd leaked: {link:?}"
                );
            }
        }
    }
}

#[test]
fn anonymous_copies_survive_source_collection_and_close_without_named_leftovers() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    const CHILD: &str = "GOLDENHOOP_CHECKPOINT_CONTENT_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status=std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","checkpoint::staging::tests::anonymous_copies_survive_source_collection_and_close_without_named_leftovers","--nocapture","--test-threads=1"])
            .env(CHILD,"1").status().unwrap();
        assert!(status.success());
        return;
    }
    let fixture = Fixture::new();
    let staged = fixture.materialize().unwrap();
    assert_eq!(staged.manifest().reference().unwrap(), fixture.reference);
    let files = staged.files();
    let raw = [
        files.state.as_raw_fd(),
        files.memory.as_raw_fd(),
        files.disk.as_raw_fd(),
    ];
    for (name, input, content) in [
        ("state", &files.state, &fixture.manifest.state),
        ("memory", &files.memory, &fixture.manifest.memory),
        ("disk", &files.disk, &fixture.manifest.disk),
    ] {
        let source = fixture.directory.path().join("source").join(name);
        let original = source.metadata().unwrap();
        let copied = input.metadata().unwrap();
        assert_ne!(
            (original.dev(), original.ino()),
            (copied.dev(), copied.ino())
        );
        assert_eq!(copied.nlink(), 0);
        assert_eq!(copied.mode() & 0o7777, 0o400);
        assert_eq!(
            unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
        let mut attempt = input;
        assert!(attempt.write_all(b"corrupt").is_err());
        std::fs::remove_file(&source).unwrap();
        assert!(!source.exists());
        assert_eq!(
            crate::fileio::digest(input.try_clone().unwrap()).unwrap(),
            (content.sha256.clone(), content.size_bytes)
        );
    }
    assert_eq!(std::fs::read_dir(fixture.staging()).unwrap().count(), 0);
    drop(staged);
    for fd in raw {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }
    fixture.assert_empty_staging();
    let root = fixture.directory.path().to_owned();
    fixture.directory.close().unwrap();
    assert!(!root.exists());
}

#[test]
fn corruption_or_truncation_collects_all_partial_anonymous_copies() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let fixture = Fixture::new();
    let path = fixture.directory.path().join("source/memory");
    let mut changed = OpenOptions::new().write(true).open(&path).unwrap();
    changed.write_all(b"wrong!").unwrap();
    changed.sync_all().unwrap();
    assert!(fixture.materialize().is_err());
    fixture.assert_empty_staging();
    changed
        .set_len(fixture.manifest.memory.size_bytes - 1)
        .unwrap();
    changed.sync_all().unwrap();
    drop(changed);
    assert!(fixture.materialize().is_err());
    fixture.assert_empty_staging();
    let root = fixture.directory.path().to_owned();
    fixture.directory.close().unwrap();
    assert!(!root.exists());
}

#[test]
fn untrusted_paths_foreign_inputs_and_unreserved_bytes_allocate_no_named_outputs() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let fixture = Fixture::new();
    let staged = fixture.staging();
    let link = fixture.directory.path().join("alias");
    symlink(&staged, &link).unwrap();
    for (path, uid, budget) in [
        (&link, 0, u64::MAX),
        (&staged, 1, u64::MAX),
        (&staged, 0, 192 * MIB + 1023),
    ] {
        assert!(
            StagedCheckpoint::materialize(
                fixture.manifest.clone(),
                &fixture.reference,
                &fixture.manifest.runtime,
                budget,
                fixture.inputs(),
                uid,
                path
            )
            .is_err()
        );
        fixture.assert_empty_staging();
    }
    let mut disk = File::open(fixture.directory.path().join("source/disk")).unwrap();
    let mut bytes = [0; 4];
    disk.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"disk");
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(fixture.materialize().is_err());
    fixture.assert_empty_staging();
    let root = fixture.directory.path().to_owned();
    fixture.directory.close().unwrap();
    assert!(!root.exists());
}
