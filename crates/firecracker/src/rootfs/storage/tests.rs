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
            .reserve(
                self.manifest.intent.clone(),
                self.vmm.id(),
                &File::open(&self.source).unwrap(),
                0,
            )
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
fn two_durable_boot_targets_fence_gc_until_both_independent_copies_are_acknowledged() {
    if !root() {
        return;
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut producer = fixture.session(&store);
    let reference = producer
        .capture(
            File::open(&fixture.source).unwrap(),
            0,
            fixture.manifest.barrier.clone(),
        )
        .unwrap();
    producer.confirm_source_resumed(fixture.resumed()).unwrap();
    producer
        .confirm_inspection_report(
            fixture.report(producer.manifest().unwrap()),
            fixture.inventory.clone(),
        )
        .unwrap();
    drop(producer);
    let parent = fixture.path.join("vm");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = || {
        let generation = Uuid::new_v4();
        RootfsBootTarget::observe(
            reference.clone(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            generation,
            "e".repeat(64),
            parent.join(&generation.simple().to_string()[..12]),
        )
        .unwrap()
    };
    let first = target();
    let second = target();
    let boot = &fixture.manifest.intent.boot;
    store.reserve_boot(first.clone(), boot).unwrap();
    store.reserve_boot(second.clone(), boot).unwrap();
    store.reserve_boot(first.clone(), boot).unwrap();
    let mut changed = first.clone();
    changed.request_sha256 = "f".repeat(64);
    assert!(store.reserve_boot(changed, boot).is_err());
    assert!(store.collect(reference.capture).is_err());
    let first_reader = store.boot_reader(&first, boot).unwrap();
    let second_reader = store.boot_reader(&second, boot).unwrap();
    store.dispatch_boot(&first).unwrap();
    store.dispatch_boot(&second).unwrap();
    assert!(store.dispatch_boot(&first).is_err());
    let copy = |target: &RootfsBootTarget, reader: &RootfsReadLease| {
        let root = crate::lifecycle::root::Root::create(target.path(), target.generation).unwrap();
        let disk = target.disk_path();
        std::fs::create_dir_all(disk.parent().unwrap()).unwrap();
        crate::fileio::copy(
            reader.file().try_clone().unwrap(),
            &disk,
            &reader.manifest.disk.sha256,
            reader.manifest.disk.size_bytes,
            0o600,
        )
        .unwrap();
        store
            .confirm_boot_materialized(target, reader, &root)
            .unwrap();
        root
    };
    let first_root = copy(&first, &first_reader);
    drop(first_reader);
    assert!(store.collect(reference.capture).is_err());
    drop(second_reader);
    // The durable second reference survives losing every live source reader.
    assert!(store.collect(reference.capture).is_err());
    let second_reader = store.boot_reader(&second, boot).unwrap();
    let second_root = copy(&second, &second_reader);
    drop(second_reader);
    store.collect(reference.capture).unwrap();
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    let original = crate::fileio::digest(File::open(second.disk_path()).unwrap()).unwrap();
    let mut writer = OpenOptions::new()
        .write(true)
        .open(first.disk_path())
        .unwrap();
    writer.write_all(b"changed independent target").unwrap();
    writer.sync_all().unwrap();
    drop(writer);
    assert_eq!(
        crate::fileio::digest(File::open(second.disk_path()).unwrap()).unwrap(),
        original
    );
    assert_ne!(
        std::fs::metadata(first.disk_path()).unwrap().ino(),
        std::fs::metadata(second.disk_path()).unwrap().ino()
    );
    assert!(store.boot_reader(&first, boot).is_err());
    first_root.remove_all().unwrap();
    second_root.remove_all().unwrap();
    assert!(!first.path().exists() && !second.path().exists());
    fixture.close();
}
#[test]
fn inherited_reader_handoff_preserves_original_object_and_independent_receiver_offsets() {
    if !root() {
        return;
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut producer = fixture.session(&store);
    let reference = producer
        .capture(
            File::open(&fixture.source).unwrap(),
            0,
            fixture.manifest.barrier.clone(),
        )
        .unwrap();
    producer.confirm_source_resumed(fixture.resumed()).unwrap();
    producer
        .confirm_inspection_report(
            fixture.report(producer.manifest().unwrap()),
            fixture.inventory.clone(),
        )
        .unwrap();
    drop(producer);
    let sender = store
        .read(&reference, &fixture.manifest.intent.boot)
        .unwrap();
    let first_descriptor = sender.supervisor_lock().unwrap();
    let second_descriptor = sender.supervisor_lock().unwrap();
    let foreign = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(fixture.path.join("foreign.lock"))
        .unwrap();
    assert!(
        store
            .read_inherited(&reference, &fixture.manifest.intent.boot, foreign)
            .is_err()
    );
    drop(sender);
    assert!(store.collect(reference.capture).is_err());
    let first = store
        .read_inherited(&reference, &fixture.manifest.intent.boot, first_descriptor)
        .unwrap();
    let second = store
        .read_inherited(&reference, &fixture.manifest.intent.boot, second_descriptor)
        .unwrap();
    let mut first_file = first.file().try_clone().unwrap();
    let mut second_file = second.file().try_clone().unwrap();
    let mut bytes = [0u8; 8];
    first_file.read_exact(&mut bytes).unwrap();
    assert_eq!(first_file.stream_position().unwrap(), 8);
    assert_eq!(second_file.stream_position().unwrap(), 0);
    drop(first_file);
    drop(second_file);
    drop(first);
    assert!(store.collect(reference.capture).is_err());
    drop(second);
    store.collect(reference.capture).unwrap();
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    fixture.close();
}
#[test]
fn original_inspector_journal_fences_gc_and_foreign_provider_or_self_report_cannot_publish_ready() {
    if !root() {
        return;
    }
    use goldenhoop_images::rootfs::{InspectionPhase, InspectionState};
    let fixture = Fixture::new();
    let store = fixture.store();
    let id = fixture.manifest.intent.source.capture;
    let mut session = fixture.session(&store);
    session
        .capture(
            File::open(&fixture.source).unwrap(),
            0,
            fixture.manifest.barrier.clone(),
        )
        .unwrap();
    session.confirm_source_resumed(fixture.resumed()).unwrap();
    session.settle().unwrap();
    let intent = session
        .inspection_intent(
            format!("sha256:{}", "d".repeat(64)),
            fixture.inventory.clone(),
            RootfsGuestConfig::default(),
        )
        .unwrap();
    // Synthetic parent state only; no Docker/host inspection is claimed.
    let mut state =
        InspectionState::reserve(intent, "fixture-engine".into(), Uuid::new_v4()).unwrap();
    state.seeder_id = Some("b".repeat(64));
    session.save_inspection_job(&state).unwrap();
    let mut foreign = state.clone();
    foreign.seeder_id = Some("c".repeat(64));
    assert!(session.save_inspection_job(&foreign).is_err());
    let mut foreign = state.clone();
    foreign.engine_id = "foreign-engine".into();
    assert!(session.save_inspection_job(&foreign).is_err());
    let mut foreign = state.clone();
    foreign.intent.request.disk.sha256 = "a".repeat(64);
    assert!(session.save_inspection_job(&foreign).is_err());
    let mut unobserved = state.clone();
    unobserved.phase = InspectionPhase::Collected;
    unobserved.result = Some(fixture.report(session.manifest().unwrap()));
    assert!(session.save_inspection_job(&unobserved).is_err());
    assert!(session.confirm_parent_inspection().is_err());
    session.settle().unwrap();
    drop(session);
    assert!(store.collect(id).is_err());
    assert_eq!(store.reserved_bytes().unwrap(), 64 * MIB);
    assert!(
        fixture
            .path
            .join("store")
            .join(format!("capture-{id}.disk"))
            .is_file()
    );
    let mut session = store.resume(&fixture.manifest.intent).unwrap();
    // No provider resources were ever created in this local state fixture.
    state.phase = InspectionPhase::Collected;
    state.error = Some("fixture inspection ended without an accepted tool result".into());
    session.save_inspection_job(&state).unwrap();
    session.settle().unwrap();
    drop(session);
    store.collect(id).unwrap();
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    assert!(
        !fixture
            .path
            .join("store")
            .join(format!("capture-{id}.disk"))
            .exists()
    );
    fixture.close();
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
            .reserve(
                fixture.manifest.intent.clone(),
                fixture.vmm.id(),
                &File::open(&fixture.source).unwrap(),
                0
            )
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
    assert!(
        store
            .reserve(
                other,
                fixture.vmm.id(),
                &File::open(&fixture.source).unwrap(),
                0
            )
            .is_err()
    );
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
    let began = Instant::now();
    let progress = |phase: &str| {
        std::fs::write(
            path.join("child.progress"),
            format!("{phase} elapsed={:?}", began.elapsed()),
        )
        .unwrap();
    };
    progress("started");
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
    progress("store_opened");
    let mut session = store
        .reserve(
            intent,
            value["source_pid"].as_u64().unwrap() as u32,
            &File::open(path.join("original.disk")).unwrap(),
            0,
        )
        .unwrap();
    progress("reserved");
    session.begin().unwrap();
    progress("begun");
    let cut = value["cut_point"]
        .as_str()
        .unwrap_or("captured_record_persisted");
    session
        .capture_observed(
            File::open(path.join("original.disk")).unwrap(),
            0,
            frozen,
            |phase| {
                progress(phase);
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
fn original_vmm_control_intents_close_capture_before_resume_and_cannot_be_replayed() {
    if !root() {
        return;
    }
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut session = fixture.session(&store);
    assert!(session.pause_observed().is_err());
    assert!(session.resume_started().is_err());
    session.pause_dispatched().unwrap();
    assert!(session.pause_dispatched().is_err());
    session.pause_observed().unwrap();
    assert!(session.resume_started().is_err());
    session
        .fail("fixture closes capture before recovery")
        .unwrap();
    session.resume_started().unwrap();
    assert!(session.resume_started().is_err());
    assert!(
        session.vm_control().pause_dispatched
            && session.vm_control().pause_observed
            && session.vm_control().resume_started
    );
    session.confirm_source_resumed(fixture.resumed()).unwrap();
    drop(session);
    store
        .collect(fixture.manifest.intent.source.capture)
        .unwrap();
    fixture.close();
}
#[test]
fn reserved_source_inode_cannot_be_replaced_and_settled_io_still_requires_source_recovery_or_death()
{
    if !root() {
        return;
    }
    let mut fixture = Fixture::new();
    let store = fixture.store();
    let mut session = fixture.session(&store);
    let foreign = fixture.path.join("same-size-foreign.disk");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&foreign)
        .unwrap();
    file.set_len(64 * MIB).unwrap();
    assert!(
        session
            .capture(file, 0, fixture.manifest.barrier.clone())
            .is_err()
    );
    assert!(session.record.frozen.is_none() && session.manifest().is_none());
    let reference = session
        .capture(
            File::open(&fixture.source).unwrap(),
            0,
            fixture.manifest.barrier.clone(),
        )
        .unwrap();
    session.settle().unwrap();
    drop(session);
    assert!(store.collect(reference.capture).is_err());
    let original = lifecycle::process_identity(fixture.vmm.id()).unwrap();
    fixture.vmm.kill().unwrap();
    fixture.vmm.wait().unwrap();
    assert!(lifecycle::reaper::process_absent(&original).unwrap());
    store.collect(reference.capture).unwrap();
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    drop(store);
    fixture.close();
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
    drop(
        store
            .reserve(
                first.clone(),
                fixture.vmm.id(),
                &File::open(&fixture.source).unwrap(),
                0,
            )
            .unwrap(),
    );
    drop(
        store
            .reserve(
                second.clone(),
                fixture.vmm.id(),
                &File::open(&fixture.source).unwrap(),
                0,
            )
            .unwrap(),
    );
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
    let started = Instant::now();
    let deadline = started + Duration::from_secs(15);
    while !fixture.path.join("child.ready").exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("rootfs fixture producer exited before capture: {status}");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let progress = std::fs::read_to_string(fixture.path.join("child.progress"))
                .unwrap_or_else(|_| "no child progress".into());
            let executable_bytes = std::fs::metadata(std::env::current_exe().unwrap())
                .unwrap()
                .len();
            panic!(
                "rootfs fixture producer missed its bounded capture deadline: {progress}; test executable bytes={executable_bytes}"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    println!(
        "ROOTFS_CAPTURE_METRIC={}",
        serde_json::json!({"cut":cut_point,
        "readiness_ms":started.elapsed().as_millis(),
        "test_executable_bytes":std::fs::metadata(std::env::current_exe().unwrap()).unwrap().len(),
        "last_progress":std::fs::read_to_string(fixture.path.join("child.progress")).unwrap()})
    );
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
