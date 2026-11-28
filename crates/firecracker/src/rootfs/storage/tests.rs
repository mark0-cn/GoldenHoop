//! Actual local files/processes with synthetic guest/inspector receipts. These
//! tests do not establish KVM pause, guest thaw or actual isolated inspection.
use super::*;
use goldenhoop_image_builder::{InspectedFile, RootfsInspectionReport};
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    process::{Child, Command},
    time::{Duration, Instant},
};

struct Fixture {
    directory: Option<tempfile::TempDir>,
    path: PathBuf,
    source: PathBuf,
    manifest: RootfsManifest,
    inventory: RootfsInspectionInventory,
    vmm: OwnedChild,
}
struct OwnedChild(Child);
impl std::ops::Deref for OwnedChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for OwnedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("goldenhoop-rootfs-store-")
            .tempdir_in("/var/lib")
            .unwrap();
        let path = directory.path().to_owned();
        let source = path.join("original.disk");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source)
            .unwrap();
        file.set_len(64 * MIB).unwrap();
        file.write_all(b"original start").unwrap();
        file.seek(std::io::SeekFrom::Start(32 * MIB + 17)).unwrap();
        file.write_all(b"captured middle").unwrap();
        file.seek(std::io::SeekFrom::Start(64 * MIB - 3)).unwrap();
        file.write_all(b"end").unwrap();
        file.sync_all().unwrap();
        let vmm = OwnedChild(Command::new("sleep").arg("300").spawn().unwrap());
        let mut manifest = crate::rootfs::tests::fixture();
        manifest.intent.boot.firecracker_sha256 = lifecycle::process_identity(vmm.id())
            .unwrap()
            .executable_sha256;
        file.rewind().unwrap();
        let (sha256, size_bytes) = crate::fileio::digest_exact(file, 64 * MIB).unwrap();
        manifest.disk = RootfsArtifact { sha256, size_bytes };
        let inventory = RootfsInspectionInventory {
            format: 1,
            builder_version: env!("CARGO_PKG_VERSION").into(),
            agent: content(&manifest.intent.boot.agent),
            init: content(&manifest.intent.boot.init),
            e2fsck: Content {
                sha256: "e".repeat(64),
                size_bytes: 512,
            },
            debugfs: Content {
                sha256: "f".repeat(64),
                size_bytes: 512,
            },
        };
        manifest.intent.inspector_inventory_sha256 = inspector_fingerprint(&inventory).unwrap();
        Self {
            directory: Some(directory),
            path,
            source,
            manifest,
            inventory,
            vmm,
        }
    }
    fn store(&self) -> RootfsStore {
        RootfsStore::open_or_initialize(
            &self.path.join("store"),
            self.manifest.intent.source.installation,
            RootfsStorePolicy {
                max_bytes: 64 * MIB,
                max_captures: 1,
            },
        )
        .unwrap()
    }
    fn session(&self, store: &RootfsStore) -> RootfsCaptureSession {
        let mut session = store
            .reserve(self.manifest.intent.clone(), self.vmm.id())
            .unwrap();
        session.begin().unwrap();
        session
    }
    fn resumed(&self) -> GuestRootfsBarrierInfo {
        let mut resumed = self.manifest.barrier.clone();
        resumed.phase = GuestBarrierPhase::Resumed;
        resumed.workload_frozen = false;
        resumed.filesystem = crate::control::GuestFilesystemState::Thawed;
        resumed.thaw_started = true;
        resumed
    }
    fn report(&self, manifest: &RootfsManifest) -> RootfsInspectionReport {
        let file = |path: &str, inode, mode, artifact: &RootfsArtifact| InspectedFile {
            path: path.into(),
            inode,
            uid: 0,
            gid: 0,
            mode,
            links: 1,
            content: content(artifact),
        };
        let boot = &manifest.intent.boot;
        RootfsInspectionReport {
            passed: true,
            staging_absent: true,
            tools_collected: true,
            error: None,
            inspection: Some(RootfsInspection {
                format: 1,
                generation: manifest.intent.inspection_generation,
                disk: content(&manifest.disk),
                agent: file("/usr/local/bin/goldenhoop-agent", 18, 0o755, &boot.agent),
                init: file("/usr/sbin/goldenhoop-init", 19, 0o755, &boot.init),
                guest_config: file("/etc/goldenhoop/guest.json", 20, 0o644, &boot.guest_config),
                guest: RootfsGuestConfig {
                    control_port: 52,
                    pids: 256,
                },
                inventory: self.inventory.clone(),
            }),
        }
    }
    fn close(mut self) {
        self.vmm.kill().unwrap();
        self.vmm.wait().unwrap();
        self.directory.take().unwrap().close().unwrap();
        assert!(!self.path.exists());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.vmm.kill();
        let _ = self.vmm.wait();
    }
}
fn root() -> bool {
    (unsafe { libc::geteuid() }) == 0
}

#[test]
fn disk_is_sparse_independent_persistent_and_ready_only_after_recovery_and_inspection() {
    if !root() {
        return;
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut session = fixture.session(&store);
    let reference = session
        .capture(
            File::open(&fixture.source).unwrap(),
            0,
            fixture.manifest.barrier.clone(),
        )
        .unwrap();
    assert_eq!(store.reserved_bytes().unwrap(), 64 * MIB);
    assert!(
        store
            .read(&reference, &fixture.manifest.intent.boot)
            .is_err()
    );
    let file = session.inspection_input().unwrap();
    assert!(file.metadata().unwrap().blocks() * 512 < 32 * MIB);
    assert_eq!(
        crate::fileio::digest_exact(file, 64 * MIB).unwrap(),
        (fixture.manifest.disk.sha256.clone(), 64 * MIB)
    );
    let mut source = OpenOptions::new()
        .write(true)
        .open(&fixture.source)
        .unwrap();
    source.write_all(b"later mutation").unwrap();
    source.sync_all().unwrap();
    drop(source);
    session.confirm_source_resumed(fixture.resumed()).unwrap();
    assert_eq!(
        store.inspect(reference.capture).unwrap()["phase"],
        "captured"
    );
    assert!(
        store
            .read(&reference, &fixture.manifest.intent.boot)
            .is_err()
    );
    session
        .confirm_inspection_report(
            fixture.report(session.record.manifest.as_ref().unwrap()),
            fixture.inventory.clone(),
        )
        .unwrap();
    drop(session);
    drop(store);
    let store = fixture.store();
    let lease = store
        .read(&reference, &fixture.manifest.intent.boot)
        .unwrap();
    assert_eq!(
        crate::fileio::digest_exact(lease.file().try_clone().unwrap(), 64 * MIB).unwrap(),
        (fixture.manifest.disk.sha256.clone(), 64 * MIB)
    );
    assert!(store.collect(reference.capture).is_err());
    drop(lease);
    assert_eq!(
        store.collect(reference.capture).unwrap()["disk_absent"],
        true
    );
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    assert!(
        store
            .reserve(fixture.manifest.intent.clone(), fixture.vmm.id())
            .is_err()
    );
    assert!(
        store
            .read(&reference, &fixture.manifest.intent.boot)
            .is_err()
    );
    assert_eq!(
        store.collect(reference.capture).unwrap()["reserved_bytes"],
        0
    );
    fixture.close();
}
#[test]
fn failed_or_dropped_capture_never_releases_live_producer_or_source_reservations() {
    if !root() {
        return;
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut session = fixture.session(&store);
    let reference = session
        .capture(
            File::open(&fixture.source).unwrap(),
            0,
            fixture.manifest.barrier.clone(),
        )
        .unwrap();
    drop(session);
    assert!(store.collect(reference.capture).is_err());
    let mut session = store.resume(&fixture.manifest.intent).unwrap();
    session
        .fail("fixture interrupted after independent disk publication")
        .unwrap();
    drop(session);
    assert!(store.collect(reference.capture).is_err());
    assert_eq!(store.reserved_bytes().unwrap(), 64 * MIB);
    let mut other = fixture.manifest.intent.clone();
    other.source.capture = Uuid::new_v4();
    assert!(store.reserve(other, fixture.vmm.id()).is_err());
    let mut session = store.resume(&fixture.manifest.intent).unwrap();
    let mut foreign = fixture.resumed();
    foreign.generation = Uuid::new_v4();
    assert!(session.confirm_source_resumed(foreign).is_err());
    session.confirm_source_resumed(fixture.resumed()).unwrap();
    drop(session);
    assert_eq!(
        store.collect(reference.capture).unwrap()["disk_absent"],
        true
    );
    fixture.close();
}
#[test]
fn foreign_inspector_unknown_cleanup_and_corrupt_disk_cannot_become_ready() {
    if !root() {
        return;
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut session = fixture.session(&store);
    let reference = session
        .capture(
            File::open(&fixture.source).unwrap(),
            0,
            fixture.manifest.barrier.clone(),
        )
        .unwrap();
    session.confirm_source_resumed(fixture.resumed()).unwrap();
    let manifest = session.record.manifest.clone().unwrap();
    let mut report = fixture.report(&manifest);
    report.tools_collected = false;
    assert!(
        session
            .confirm_inspection_report(report, fixture.inventory.clone())
            .is_err()
    );
    let mut inventory = fixture.inventory.clone();
    inventory.debugfs.sha256 = "0".repeat(64);
    let mut report = fixture.report(&manifest);
    report.inspection.as_mut().unwrap().inventory = inventory.clone();
    assert!(
        session
            .confirm_inspection_report(report, inventory)
            .is_err()
    );
    let disk = fixture
        .path
        .join("store")
        .join(format!("capture-{}.disk", reference.capture));
    let mut file = OpenOptions::new().write(true).open(&disk).unwrap();
    file.write_all(b"corrupt").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(
        session
            .confirm_inspection_report(fixture.report(&manifest), fixture.inventory.clone())
            .is_err()
    );
    session.fail("corrupt independent disk").unwrap();
    drop(session);
    assert!(
        store
            .read(&reference, &fixture.manifest.intent.boot)
            .is_err()
    );
    store.collect(reference.capture).unwrap();
    fixture.close();
}
#[test]
fn replaced_object_and_changed_intent_are_preserved_without_releasing_quota() {
    if !root() {
        return;
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut session = fixture.session(&store);
    let reference = session
        .capture(
            File::open(&fixture.source).unwrap(),
            0,
            fixture.manifest.barrier.clone(),
        )
        .unwrap();
    session.confirm_source_resumed(fixture.resumed()).unwrap();
    session.fail("fixture refusal").unwrap();
    drop(session);
    let mut changed = fixture.manifest.intent.clone();
    changed.disk_id = Uuid::new_v4();
    assert!(store.resume(&changed).is_err());
    let disk = fixture
        .path
        .join("store")
        .join(format!("capture-{}.disk", reference.capture));
    let retained = fixture.path.join("retained.disk");
    std::fs::rename(&disk, &retained).unwrap();
    std::fs::write(&disk, b"foreign occupied file").unwrap();
    std::fs::set_permissions(&disk, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(store.collect(reference.capture).is_err());
    assert_eq!(std::fs::read(&disk).unwrap(), b"foreign occupied file");
    assert!(store.reserved_bytes().is_err());
    assert_eq!(
        store.inspect(reference.capture).unwrap()["reserved_bytes"],
        64 * MIB
    );
    std::fs::remove_file(&disk).unwrap();
    std::fs::rename(&retained, &disk).unwrap();
    store.collect(reference.capture).unwrap();
    fixture.close();
}
#[test]
fn descriptor_alias_permissions_lengths_and_unknown_store_owner_are_refused() {
    if !root() {
        return;
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut session = fixture.session(&store);
    let frozen = fixture.manifest.barrier.clone();
    assert!(
        session
            .capture(File::open(&fixture.source).unwrap(), 123, frozen.clone())
            .is_err()
    );
    let alias = fixture.path.join("alias.disk");
    std::fs::hard_link(&fixture.source, &alias).unwrap();
    assert!(
        session
            .capture(File::open(&fixture.source).unwrap(), 0, frozen.clone())
            .is_err()
    );
    std::fs::remove_file(&alias).unwrap();
    std::fs::set_permissions(&fixture.source, std::fs::Permissions::from_mode(0o622)).unwrap();
    assert!(
        session
            .capture(File::open(&fixture.source).unwrap(), 0, frozen.clone())
            .is_err()
    );
    std::fs::set_permissions(&fixture.source, std::fs::Permissions::from_mode(0o600)).unwrap();
    let file = OpenOptions::new()
        .write(true)
        .open(&fixture.source)
        .unwrap();
    file.set_len(64 * MIB - 1).unwrap();
    drop(file);
    assert!(
        session
            .capture(File::open(&fixture.source).unwrap(), 0, frozen)
            .is_err()
    );
    assert_eq!(store.reserved_bytes().unwrap(), 64 * MIB);
    assert!(
        RootfsStore::open_or_initialize(
            &fixture.path.join("store"),
            Uuid::new_v4(),
            store.policy.clone()
        )
        .is_err()
    );
    let foreign = fixture.path.join("foreign");
    std::fs::create_dir(&foreign).unwrap();
    std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(foreign.join("keep"), b"do not adopt").unwrap();
    assert!(
        RootfsStore::open_or_initialize(
            &foreign,
            fixture.manifest.intent.source.installation,
            store.policy.clone()
        )
        .is_err()
    );
    assert_eq!(
        std::fs::read(foreign.join("keep")).unwrap(),
        b"do not adopt"
    );
    session.fail("refused inputs").unwrap();
    session.confirm_source_resumed(fixture.resumed()).unwrap();
    drop(session);
    store
        .collect(fixture.manifest.intent.source.capture)
        .unwrap();
    fixture.close();
}

#[test]
fn crash_child_entry() {
    let Some(path) = std::env::var_os("GH_ROOTFS_STORE_CRASH_FIXTURE") else {
        return;
    };
    let path = PathBuf::from(path);
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("child.json")).unwrap()).unwrap();
    let intent: RootfsCaptureIntent = serde_json::from_value(value["intent"].clone()).unwrap();
    let frozen: GuestRootfsBarrierInfo = serde_json::from_value(value["frozen"].clone()).unwrap();
    let store = RootfsStore::open_or_initialize(
        &path.join("store"),
        intent.source.installation,
        RootfsStorePolicy {
            max_bytes: 64 * MIB,
            max_captures: 1,
        },
    )
    .unwrap();
    let mut session = store
        .reserve(intent, value["source_pid"].as_u64().unwrap() as u32)
        .unwrap();
    session.begin().unwrap();
    let cut = value["cut_point"]
        .as_str()
        .unwrap_or("captured_record_persisted");
    session
        .capture_observed(
            File::open(path.join("original.disk")).unwrap(),
            0,
            frozen,
            |phase| {
                if phase == cut {
                    std::fs::write(path.join("child.ready"), phase).unwrap();
                    loop {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            },
        )
        .unwrap();
    panic!("requested capture cut point was not reached");
}
#[test]
fn transposed_capture_records_refuse_inspection_and_collection_before_effects() {
    if !root() {
        return;
    }
    let fixture = Fixture::new();
    let store = RootfsStore::open_or_initialize(
        &fixture.path.join("store"),
        fixture.manifest.intent.source.installation,
        RootfsStorePolicy {
            max_bytes: 128 * MIB,
            max_captures: 2,
        },
    )
    .unwrap();
    let first = fixture.manifest.intent.clone();
    let mut second = first.clone();
    second.source.capture = Uuid::new_v4();
    second.barrier = Uuid::new_v4();
    second.disk_id = Uuid::new_v4();
    drop(store.reserve(first.clone(), fixture.vmm.id()).unwrap());
    drop(store.reserve(second.clone(), fixture.vmm.id()).unwrap());
    let a = fixture
        .path
        .join("store")
        .join(record_name(first.source.capture));
    let b = fixture
        .path
        .join("store")
        .join(record_name(second.source.capture));
    let first_bytes = std::fs::read(&a).unwrap();
    let second_bytes = std::fs::read(&b).unwrap();
    std::fs::write(&a, &second_bytes).unwrap();
    std::fs::write(&b, &first_bytes).unwrap();
    assert!(store.inspect(first.source.capture).is_err());
    assert!(store.inspect(second.source.capture).is_err());
    assert!(store.collect(first.source.capture).is_err());
    assert!(store.resume(&first).is_err());
    assert!(store.reserved_bytes().is_err());
    assert_eq!(std::fs::read(&a).unwrap(), second_bytes);
    assert_eq!(std::fs::read(&b).unwrap(), first_bytes);
    std::fs::write(&a, first_bytes).unwrap();
    std::fs::write(&b, second_bytes).unwrap();
    drop(store);
    fixture.close();
}
#[test]
fn sigkill_original_producer_reconciles_same_content_without_refreezing_or_implicit_thaw() {
    crash_at_publication("captured_record_persisted", false);
}
#[test]
fn sigkill_after_link_recovers_original_receipt_and_before_link_retains_failed_reservation() {
    crash_at_publication("publishing_record_persisted", true);
    crash_at_publication("disk_link_persisted", false);
}
fn crash_at_publication(cut_point: &str, missing_disk: bool) {
    if !root() {
        return;
    }
    let fixture = Fixture::new();
    std::fs::write(fixture.path.join("child.json"),serde_json::to_vec(&serde_json::json!({"intent":fixture.manifest.intent,"frozen":fixture.manifest.barrier,"source_pid":fixture.vmm.id(),"cut_point":cut_point})).unwrap()).unwrap();
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "rootfs::storage::tests::crash_child_entry",
                "--test-threads=1",
            ])
            .env("GH_ROOTFS_STORE_CRASH_FIXTURE", &fixture.path)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !fixture.path.join("child.ready").exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("rootfs fixture producer exited before capture: {status}");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("rootfs fixture producer missed its bounded capture deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let store = fixture.store();
    let id = fixture.manifest.intent.source.capture;
    assert!(store.resume(&fixture.manifest.intent).is_err());
    assert!(store.collect(id).is_err());
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success());
    let mut session = store.resume(&fixture.manifest.intent).unwrap();
    assert_eq!(
        session.record.phase,
        if missing_disk {
            Phase::Failed
        } else {
            Phase::Captured
        }
    );
    assert!(session.record.resumed.is_none());
    assert!(
        session
            .capture(
                File::open(&fixture.source).unwrap(),
                0,
                fixture.manifest.barrier.clone()
            )
            .is_err()
    );
    let reference = session
        .record
        .manifest
        .as_ref()
        .unwrap()
        .reference()
        .unwrap();
    session.confirm_source_resumed(fixture.resumed()).unwrap();
    if missing_disk {
        assert!(session.inspection_input().is_err());
        drop(session);
        assert_eq!(store.reserved_bytes().unwrap(), 64 * MIB);
        store.collect(id).unwrap();
        assert_eq!(store.reserved_bytes().unwrap(), 0);
        fixture.close();
        return;
    }
    session
        .confirm_inspection_report(
            fixture.report(session.record.manifest.as_ref().unwrap()),
            fixture.inventory.clone(),
        )
        .unwrap();
    drop(session);
    let lease = store
        .read(&reference, &fixture.manifest.intent.boot)
        .unwrap();
    assert_eq!(
        crate::fileio::digest_exact(lease.file().try_clone().unwrap(), 64 * MIB).unwrap(),
        (fixture.manifest.disk.sha256.clone(), 64 * MIB)
    );
    drop(lease);
    store.collect(id).unwrap();
    fixture.close();
}
