use super::restore::{RestoreAdmission, RestoreIntent};
use super::*;
use std::{
    io::{Seek, SeekFrom, Write},
    os::unix::fs::PermissionsExt,
    process::{Child, Command},
    time::{Duration, Instant},
};

struct ChildOwner(Child);
impl ChildOwner {
    fn stop(&mut self) {
        let _ = self.0.kill();
        self.0.wait().unwrap();
    }
}
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Fixture {
    directory: tempfile::TempDir,
    cfg: CheckpointProbeConfig,
    manifest: CheckpointManifest,
    intent: Intent,
    writer: ChildOwner,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("ghcp-store-")
            .tempdir_in("/var/lib")
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = directory.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
        let writer = ChildOwner(Command::new("/bin/sleep").arg("180").spawn().unwrap());
        let mut manifest = super::super::tests::fixture();
        let observed = Writer::observe(writer.0.id()).unwrap();
        manifest.runtime.firecracker_sha256 = observed.process.executable_sha256.clone();
        for (role, content) in [
            ("state", &mut manifest.state),
            ("memory", &mut manifest.memory),
            ("disk", &mut manifest.disk),
        ] {
            let path = source.join(role);
            let mut f = File::create(&path).unwrap();
            f.set_len(content.size_bytes).unwrap();
            f.write_all(role.as_bytes()).unwrap();
            f.seek(SeekFrom::Start(content.size_bytes - 4)).unwrap();
            f.write_all(b"tail").unwrap();
            f.sync_all().unwrap();
            drop(f);
            content.sha256 = crate::fileio::digest(File::open(path).unwrap()).unwrap().0;
        }
        let cfg = CheckpointProbeConfig {
            root: directory.path().join("store"),
            installation: manifest.source.installation,
            capture: manifest.source.capture,
            policy: CheckpointStorePolicy {
                max_bytes: 2 * 1024 * MIB,
                max_checkpoints: 2,
            },
        };
        let intent = Intent {
            source: manifest.source.clone(),
            runtime: manifest.runtime.clone(),
            resources: manifest.resources.clone(),
            barrier: manifest.barrier.barrier,
            disk_bytes: manifest.disk.size_bytes,
            writer: observed,
            source_directory: SourceDirectory::observe(&source, manifest.source.source_generation)
                .unwrap(),
        };
        Self {
            directory,
            cfg,
            manifest,
            intent,
            writer,
        }
    }
    fn source(&self) -> PathBuf {
        self.directory.path().join("source")
    }
    fn store(&self) -> CheckpointStore {
        CheckpointStore::open_or_initialize(&self.cfg).unwrap()
    }
    fn staged(&self) -> StagedCheckpoint {
        stage(&self.cfg, &self.manifest, &self.source())
    }
    fn publish(&self, store: &CheckpointStore) -> CheckpointReference {
        let mut session = store.reserve(self.intent.clone()).unwrap();
        session.begin().unwrap();
        session.publish(self.staged()).unwrap()
    }
    fn collect_source(&mut self) {
        self.writer.stop();
        for role in ["state", "memory", "disk"] {
            std::fs::remove_file(self.source().join(role)).unwrap();
        }
        std::fs::remove_dir(self.source()).unwrap();
        assert!(!self.source().exists());
    }
    fn close(self) {
        let path = self.directory.path().to_owned();
        drop(self.writer);
        self.directory.close().unwrap();
        assert!(!path.exists());
    }
}
fn stage(
    cfg: &CheckpointProbeConfig,
    manifest: &CheckpointManifest,
    source: &Path,
) -> StagedCheckpoint {
    StagedCheckpoint::materialize(
        manifest.clone(),
        &manifest.reference().unwrap(),
        &manifest.runtime,
        1024 * MIB,
        CheckpointFiles {
            state: File::open(source.join("state")).unwrap(),
            memory: File::open(source.join("memory")).unwrap(),
            disk: File::open(source.join("disk")).unwrap(),
        },
        0,
        &cfg.root,
    )
    .unwrap()
}

#[test]
fn owned_session_reports_pending_and_settled_failure_still_requires_source_collection() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let mut f = Fixture::new();
    let store = f.store();
    let mut session = store.reserve(f.intent.clone()).unwrap();
    assert_eq!(
        store.source(f.cfg.capture).unwrap(),
        Some(f.intent.source.clone())
    );
    assert_eq!(store.inspect(f.cfg.capture).unwrap()["phase"], "reserved");
    // Session owns its pinned store handle independently of its admission caller.
    drop(store);
    session.begin().unwrap();
    let store = f.store();
    let pending = store.inspect(f.cfg.capture).unwrap();
    assert_eq!(pending["capture_outcome"], "pending");
    assert_eq!(pending["content_verified"], false);
    assert!(
        store.collect(f.cfg.capture).is_err(),
        "active job lease is required"
    );
    session.fail("positively settled worker failure").unwrap();
    drop(session);
    assert!(
        store.collect(f.cfg.capture).is_err(),
        "live source remains reserved"
    );
    f.collect_source();
    // The actual producer is this live process. Positive settlement permits GC
    // only after the independent original writer and source root are absent.
    let collected = store.collect(f.cfg.capture).unwrap();
    assert_eq!(collected["capture_outcome"], "failed");
    assert_eq!(collected["reserved_bytes"], 0);
    assert_eq!(collected["error"], "positively settled worker failure");
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    f.close();
}

#[test]
fn settled_publication_error_preserves_foreign_output_and_collects_own_partial_objects() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let mut f = Fixture::new();
    let store = f.store();
    let mut session = store.reserve(f.intent.clone()).unwrap();
    session.begin().unwrap();
    let occupied = f.cfg.root.join(files::object_name(f.cfg.capture, "memory"));
    let failure = session.publish_observed(f.staged(), |event| {
        if event == "object_linked_0" {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(&occupied)
                .unwrap();
            file.write_all(b"foreign-output").unwrap();
            file.sync_all().unwrap();
        }
    });
    assert!(failure.is_err());
    assert_eq!(
        store.inspect(f.cfg.capture).unwrap()["capture_outcome"],
        "failed"
    );
    f.collect_source();
    assert!(store.collect(f.cfg.capture).is_err());
    assert_eq!(std::fs::read(&occupied).unwrap(), b"foreign-output");
    // This test created the conflicting inode; production GC preserved it.
    std::fs::remove_file(occupied).unwrap();
    assert_eq!(
        store.collect(f.cfg.capture).unwrap()["capture_outcome"],
        "failed"
    );
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    f.close();
}

#[test]
fn ready_objects_survive_source_collection_quota_is_shared_and_never_freed_early() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let mut f = Fixture::new();
    let mut store = f.store();
    let reference = f.publish(&store);
    let reserved = f.intent.validate().unwrap();
    assert_eq!(store.reserved_bytes().unwrap(), reserved);
    assert!(store.collect(f.cfg.capture).is_err());
    assert!(store.reserve(f.intent.clone()).is_err());
    let mut another = f.intent.clone();
    another.source.capture = Uuid::new_v4();
    assert!(
        store.reserve(another.clone()).is_err(),
        "same source cannot mint another continuation capture"
    );
    // Distinct synthetic source scope and actual separate writer, same store.
    let other = Fixture::new();
    another = other.intent.clone();
    another.source.installation = f.cfg.installation;
    store.policy.max_bytes = reserved;
    let refused = store.reserve(another).err().unwrap();
    assert_eq!(
        refused
            .downcast_ref::<goldenhoop_protocol::ApiError>()
            .unwrap()
            .code,
        goldenhoop_protocol::ErrorCode::QuotaExceeded
    );
    assert_eq!(store.reserved_bytes().unwrap(), reserved);
    other.close();
    f.writer.stop();
    assert!(
        store.collect(f.cfg.capture).is_err(),
        "raw source files still consume the reservation"
    );
    f.collect_source();
    store
        .verify(&reference, |m, files| {
            assert_eq!(m.reference().unwrap(), reference);
            assert_eq!(files.memory.metadata()?.len(), 128 * MIB);
            Ok(())
        })
        .unwrap();
    let value = store.collect(f.cfg.capture).unwrap();
    assert_eq!(value["objects_absent"], true);
    assert_eq!(value["capture_outcome"], "ready");
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    assert!(store.verify(&reference, |_, _| Ok(())).is_err());
    assert_eq!(store.collect(f.cfg.capture).unwrap()["reserved_bytes"], 0);
    drop(store);
    f.close();
}

#[test]
fn corrupt_owned_content_collects_but_replaced_objects_and_context_changes_are_preserved() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let mut f = Fixture::new();
    let store = f.store();
    let reference = f.publish(&store);
    let id = f.cfg.capture;
    let state = f.cfg.root.join(files::object_name(id, "state"));
    f.collect_source();
    // Ready reads do not require the producer's original observer context.
    let original: Record = store.root.json(&record_name(id)).unwrap();
    let mut changed = original.clone();
    let boot = Uuid::new_v4().to_string();
    changed.producer.context.boot = boot.clone();
    changed.producer.process.boot_id = boot.clone();
    changed.intent.writer.context.boot = boot.clone();
    changed.intent.writer.process.boot_id = boot;
    metadata::atomic_json(&f.cfg.root.join(record_name(id)), &changed).unwrap();
    assert!(changed.producer.require_absent().is_err());
    assert!(changed.intent.writer.require_absent().is_err());
    assert!(
        store.verify(&reference, |_, _| Ok(())).is_err(),
        "changed immutable intent must fail its mutex binding"
    );
    assert!(store.collect(id).is_err());
    metadata::atomic_json(&f.cfg.root.join(record_name(id)), &original).unwrap();
    store.verify(&reference, |_, _| Ok(())).unwrap();
    let memory = f.cfg.root.join(files::object_name(id, "memory"));
    let mut altered = OpenOptions::new().write(true).open(memory).unwrap();
    altered.write_all(b"corrupt").unwrap();
    altered.sync_all().unwrap();
    drop(altered);
    assert!(store.verify(&reference, |_, _| Ok(())).is_err());
    assert!(store.reserved_bytes().unwrap() > 0);
    let saved = f.directory.path().join("saved-state");
    std::fs::rename(&state, &saved).unwrap();
    std::fs::write(&state, b"foreign").unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o400)).unwrap();
    assert!(store.collect(id).is_err());
    assert_eq!(std::fs::read(&state).unwrap(), b"foreign");
    std::fs::remove_file(&state).unwrap();
    std::fs::rename(saved, &state).unwrap();
    // The exact original state inode returns; corrupt but owned memory can collect.
    assert_eq!(store.collect(id).unwrap()["objects_absent"], true);
    drop(store);
    f.close();
}

#[derive(Serialize, Deserialize)]
struct Parameters {
    cfg: CheckpointProbeConfig,
    intent: Intent,
    manifest: CheckpointManifest,
    source: PathBuf,
    marker: PathBuf,
}
#[test]
fn real_producer_sigkill_preserves_partial_receipts_and_waits_for_original_source_absence() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    const CHILD: &str = "GOLDENHOOP_CHECKPOINT_STORE_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let p: Parameters = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let store = CheckpointStore::open(&p.cfg).unwrap();
        let mut session = store.reserve(p.intent).unwrap();
        session.begin().unwrap();
        session
            .publish_observed(stage(&p.cfg, &p.manifest, &p.source), |event| {
                if event == "object_linked_0" {
                    std::fs::write(&p.marker, b"state-linked").unwrap();
                    File::open(&p.marker).unwrap().sync_all().unwrap();
                    assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
                }
            })
            .unwrap();
        return;
    }
    let mut first = Fixture::new();
    let store = first.store();
    let ready = first.publish(&store);
    let mut interrupted = Fixture::new();
    interrupted.cfg.root = first.cfg.root.clone();
    interrupted.cfg.installation = first.cfg.installation;
    interrupted.manifest.source.installation = first.cfg.installation;
    interrupted.intent.source = interrupted.manifest.source.clone();
    let marker = interrupted.directory.path().join("linked");
    let path = interrupted.directory.path().join("child.json");
    let p = Parameters {
        cfg: interrupted.cfg.clone(),
        intent: interrupted.intent.clone(),
        manifest: interrupted.manifest.clone(),
        source: interrupted.source(),
        marker: marker.clone(),
    };
    std::fs::write(&path, serde_json::to_vec(&p).unwrap()).unwrap();
    let mut child=ChildOwner(Command::new(std::env::current_exe().unwrap()).args(["--exact","checkpoint::storage::tests::real_producer_sigkill_preserves_partial_receipts_and_waits_for_original_source_absence","--nocapture","--test-threads=1"]).env(CHILD,&path).spawn().unwrap());
    let until = Instant::now() + Duration::from_secs(120);
    while !marker.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "producer exited before boundary"
        );
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(10));
    }
    store.verify(&ready, |_, _| Ok(())).unwrap();
    assert!(store.collect(interrupted.cfg.capture).is_err());
    child.stop();
    assert!(
        store.collect(interrupted.cfg.capture).is_err(),
        "original VMM writer still present"
    );
    interrupted.writer.stop();
    assert!(
        store.collect(interrupted.cfg.capture).is_err(),
        "source directory still present"
    );
    interrupted.collect_source();
    let collected = store.collect(interrupted.cfg.capture).unwrap();
    assert_eq!(collected["capture_outcome"], "unconfirmed");
    assert_eq!(collected["objects_absent"], true);
    store.verify(&ready, |_, _| Ok(())).unwrap();
    first.collect_source();
    store.collect(first.cfg.capture).unwrap();
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    drop(store);
    interrupted.close();
    first.close();
}

#[test]
fn unmarked_store_and_replaced_quota_inode_never_gain_ownership() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let f = Fixture::new();
    std::fs::create_dir(&f.cfg.root).unwrap();
    std::fs::set_permissions(&f.cfg.root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let canary = f.cfg.root.join("unclaimed");
    std::fs::write(&canary, b"keep").unwrap();
    assert!(CheckpointStore::open_or_initialize(&f.cfg).is_err());
    assert_eq!(std::fs::read(&canary).unwrap(), b"keep");
    std::fs::remove_file(canary).unwrap();
    std::fs::remove_dir(&f.cfg.root).unwrap();
    let store = f.store();
    let lock = f.cfg.root.join("quota.lock");
    let saved = f.directory.path().join("saved-quota");
    std::fs::rename(&lock, &saved).unwrap();
    std::fs::copy(&saved, &lock).unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(CheckpointStore::open(&f.cfg).is_err());
    assert!(store.reserved_bytes().is_err());
    drop(store);
    f.close();
}

fn continuation(f: &Fixture) -> RestoreIntent {
    let generation = Uuid::new_v4();
    RestoreIntent {
        reference: f.manifest.reference().unwrap(),
        runtime: f.manifest.runtime.clone(),
        restoration: Uuid::new_v4(),
        sandbox: Uuid::new_v4(),
        generation,
        destination: Destination::observe(&f.directory.path().join("target"), generation).unwrap(),
    }
}
#[test]
fn continuation_requires_source_absence_reserves_drive_and_never_reissues_an_occupied_claim() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let mut f = Fixture::new();
    let mut store = f.store();
    f.publish(&store);
    let intent = continuation(&f);
    let id = f.cfg.capture;
    assert!(store.claim_restore(intent.clone()).is_err());
    assert!(!store.root.continuation_exists(id).unwrap());
    f.writer.stop();
    assert!(
        store.claim_restore(intent.clone()).is_err(),
        "raw source directory still exists"
    );
    f.collect_source();
    let base = store.reserved_bytes().unwrap();
    store.policy.max_bytes = base;
    assert_eq!(
        store
            .claim_restore(intent.clone())
            .err()
            .unwrap()
            .downcast_ref::<goldenhoop_protocol::ApiError>()
            .unwrap()
            .code,
        goldenhoop_protocol::ErrorCode::QuotaExceeded
    );
    assert!(!store.root.continuation_exists(id).unwrap());
    store.policy.max_bytes = base + f.intent.disk_bytes;
    let RestoreAdmission::Granted(mut session) = store.claim_restore(intent.clone()).unwrap()
    else {
        panic!("first claim was not granted")
    };
    assert_eq!(store.reserved_bytes().unwrap(), base + f.intent.disk_bytes);
    assert!(matches!(
        store.claim_restore(intent.clone()).unwrap(),
        RestoreAdmission::Existing(_)
    ));
    let mut changed = intent.clone();
    changed.restoration = Uuid::new_v4();
    assert!(store.claim_restore(changed).is_err());
    assert!(store.collect(id).is_err());
    assert!(store.close_restore(id).is_err());
    let acknowledged: Record = store.root.json(&record_name(id)).unwrap();
    let mut old = acknowledged.clone();
    old.restoration = None;
    metadata::atomic_json(&f.cfg.root.join(record_name(id)), &old).unwrap();
    assert!(
        store.inspect(id).is_err(),
        "permanent witness prevents lost claim rollback"
    );
    assert!(store.claim_restore(intent.clone()).is_err());
    assert!(store.collect(id).is_err());
    metadata::atomic_json(&f.cfg.root.join(record_name(id)), &acknowledged).unwrap();
    std::fs::create_dir(intent.destination.path()).unwrap();
    std::fs::set_permissions(
        intent.destination.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    session.allocated().unwrap();
    session.launching().unwrap();
    let mut target = ChildOwner(Command::new("/bin/sleep").arg("180").spawn().unwrap());
    session.tracked(target.0.id()).unwrap();
    session.fail("settled synthetic restore failure").unwrap();
    assert_eq!(store.inspect(id).unwrap()["content_verified"], true);
    drop(session);
    assert!(
        store.close_restore(id).is_err(),
        "live target writer still retains backing references"
    );
    target.stop();
    assert!(
        store.close_restore(id).is_err(),
        "target directory still exists"
    );
    std::fs::remove_dir(intent.destination.path()).unwrap();
    let closed = store.close_restore(id).unwrap();
    assert_eq!(closed["target_absent"], true);
    assert_eq!(closed["restoration"]["outcome"], "failed");
    assert_eq!(store.reserved_bytes().unwrap(), base);
    assert!(matches!(
        store.claim_restore(intent).unwrap(),
        RestoreAdmission::Existing(_)
    ));
    store.collect(id).unwrap();
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    f.close();
}

#[derive(Serialize, Deserialize)]
struct ContinuationParameters {
    cfg: CheckpointProbeConfig,
    intent: RestoreIntent,
    marker: PathBuf,
}
#[test]
fn real_continuation_owner_sigkill_never_mints_a_second_target_and_releases_only_observed_absence()
{
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    const CHILD: &str = "GH_CONTINUATION_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let p: ContinuationParameters =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let store = CheckpointStore::open(&p.cfg).unwrap();
        let RestoreAdmission::Granted(_session) = store.claim_restore(p.intent).unwrap() else {
            panic!("claim not fresh")
        };
        std::fs::write(&p.marker, b"actual_claim_acknowledged").unwrap();
        File::open(&p.marker).unwrap().sync_all().unwrap();
        assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
        return;
    }
    let mut f = Fixture::new();
    let store = f.store();
    f.publish(&store);
    f.collect_source();
    let intent = continuation(&f);
    let marker = f.directory.path().join("claimed");
    let path = f.directory.path().join("continuation.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&ContinuationParameters {
            cfg: f.cfg.clone(),
            intent: intent.clone(),
            marker: marker.clone(),
        })
        .unwrap(),
    )
    .unwrap();
    let mut child=ChildOwner(Command::new(std::env::current_exe().unwrap()).args(["--exact","checkpoint::storage::tests::real_continuation_owner_sigkill_never_mints_a_second_target_and_releases_only_observed_absence","--nocapture","--test-threads=1"]).env(CHILD,&path).spawn().unwrap());
    let until = Instant::now() + Duration::from_secs(120);
    while !marker.exists() {
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(
        store.claim_restore(intent.clone()).unwrap(),
        RestoreAdmission::Existing(_)
    ));
    assert!(store.close_restore(f.cfg.capture).is_err());
    child.stop();
    let closed = store.close_restore(f.cfg.capture).unwrap();
    assert_eq!(closed["restoration"]["outcome"], "unconfirmed");
    assert!(matches!(
        store.claim_restore(intent).unwrap(),
        RestoreAdmission::Existing(_)
    ));
    store.collect(f.cfg.capture).unwrap();
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    f.close();
}
