//! Actual root-owned files and process death; no KVM success is inferred here.
use super::*;
use goldenhoop_protocol::{ApiError, ErrorCode};

fn reason() -> ApiError {
    ApiError::new(
        ErrorCode::QuotaExceeded,
        "/operator/private/capacity-diagnostic",
    )
}

#[test]
fn durable_refusal_survives_reopen_blocks_late_producer_and_preserves_healthy_source() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let mut f = Fixture::new();
    let store = f.store();
    let source = f.intent.source.clone();
    let status = store
        .close_unstarted(source.clone(), &reason())
        .unwrap()
        .unwrap();
    assert_eq!(status["capture_outcome"], "not_started");
    assert_eq!(status["objects_absent"], true);
    assert!(!status.to_string().contains("/operator/private"));
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    f.intent.writer.require_present().unwrap();
    f.intent.source_directory.require_present().unwrap();
    assert!(!f.cfg.root.join(files::lock_name(source.capture)).exists());
    drop(store);
    let store = f.store();
    assert_eq!(store.inspect(source.capture).unwrap(), status);
    assert_eq!(store.collect(source.capture).unwrap(), status);
    assert_eq!(store.source(source.capture).unwrap(), Some(source.clone()));
    assert_eq!(
        store
            .close_unstarted(
                source.clone(),
                &ApiError::new(ErrorCode::Internal, "later error")
            )
            .unwrap()
            .unwrap(),
        status
    );
    assert!(
        store.reserve(f.intent.clone()).is_err(),
        "late producer reused a refused capture ID"
    );
    assert!(!f.cfg.root.join(record_name(source.capture)).exists());
    assert!(!f.cfg.root.join(files::lock_name(source.capture)).exists());
    let mut foreign = source;
    foreign.source_generation = Uuid::new_v4();
    assert!(store.close_unstarted(foreign, &reason()).is_err());
    let mut fresh = f.intent.clone();
    fresh.source.capture = Uuid::new_v4();
    let fresh_id = fresh.source.capture;
    let mut session = store.reserve(fresh).unwrap();
    assert!(
        store
            .close_unstarted(session.record.intent.source.clone(), &reason())
            .unwrap()
            .is_none(),
        "existing reservation became a refusal"
    );
    session
        .fail("test producer settled without beginning capture")
        .unwrap();
    drop(session);
    f.collect_source();
    store.collect(fresh_id).unwrap();
    assert_eq!(store.inspect(f.cfg.capture).unwrap(), status);
    assert_eq!(store.reserved_bytes().unwrap(), 0);
    drop(store);
    f.close();
}

#[test]
fn bound_partial_admission_can_close_but_legacy_unbound_mutex_and_foreign_receipts_cannot() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let f = Fixture::new();
    let store = f.store();
    let id = f.cfg.capture;
    store
        .root
        .ensure_job_lock(id, &f.intent.digest().unwrap())
        .unwrap();
    assert!(
        store
            .close_unstarted(f.intent.source.clone(), &reason())
            .is_err()
    );
    assert!(f.cfg.root.join(files::lock_name(id)).exists());
    assert!(!f.cfg.root.join(files::refusal_name(id)).exists());
    // A new-format admission positively binds this exact interrupted producer.
    store.root.admit_capture(&f.intent).unwrap();
    let mut foreign = f.intent.source.clone();
    foreign.sandbox = Uuid::new_v4();
    assert!(store.close_unstarted(foreign, &reason()).is_err());
    let refusal = store
        .close_unstarted(f.intent.source.clone(), &reason())
        .unwrap()
        .unwrap();
    assert!(store.reserve(f.intent.clone()).is_err());
    assert_eq!(store.inspect(id).unwrap(), refusal);
    let path = f.cfg.root.join(files::refusal_name(id));
    let original: serde_json::Value = store.root.json(&files::refusal_name(id)).unwrap();
    let mut changed = original.clone();
    changed["receipt"]["source"]["sandbox"] = serde_json::json!(Uuid::new_v4());
    metadata::atomic_json(&path, &changed).unwrap();
    assert!(
        store.inspect(id).is_err(),
        "foreign source receipt gained authority"
    );
    metadata::atomic_json(&path, &original).unwrap();
    assert_eq!(store.inspect(id).unwrap(), refusal);
    drop(store);
    f.close();
}

#[derive(Serialize, Deserialize)]
struct ClosureParameters {
    cfg: CheckpointProbeConfig,
    intent: Intent,
    marker: PathBuf,
    stage: String,
}

#[test]
fn actual_sigkill_before_reservation_and_after_refusal_never_reopens_closed_identifier() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    const CHILD: &str = "GOLDENHOOP_CAPTURE_CLOSURE_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let p: ClosureParameters = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let store = CheckpointStore::open(&p.cfg).unwrap();
        if p.stage == "admitted" {
            let _quota = store.root.quota(true).unwrap();
            store.root.admit_capture(&p.intent).unwrap();
            store
                .root
                .ensure_job_lock(p.cfg.capture, &p.intent.digest().unwrap())
                .unwrap();
        } else {
            store
                .close_unstarted(p.intent.source, &reason())
                .unwrap()
                .unwrap();
        }
        std::fs::write(&p.marker, b"durable-boundary").unwrap();
        File::open(&p.marker).unwrap().sync_all().unwrap();
        assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
        return;
    }
    for stage in ["admitted", "refused"] {
        let f = Fixture::new();
        let store = f.store();
        let marker = f.directory.path().join("durable-boundary");
        let parameter = f.directory.path().join("closure-child.json");
        let p = ClosureParameters {
            cfg: f.cfg.clone(),
            intent: f.intent.clone(),
            marker: marker.clone(),
            stage: stage.into(),
        };
        std::fs::write(&parameter, serde_json::to_vec(&p).unwrap()).unwrap();
        let mut child = ChildOwner(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "checkpoint::storage::tests::outcomes::actual_sigkill_before_reservation_and_after_refusal_never_reopens_closed_identifier", "--nocapture", "--test-threads=1"])
            .env(CHILD, &parameter).spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(60);
        while !marker.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "producer exited before {stage}"
            );
            assert!(
                Instant::now() < deadline,
                "producer failed to reach {stage}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        child.stop();
        drop(store);
        let store = f.store();
        let status = store
            .close_unstarted(f.intent.source.clone(), &reason())
            .unwrap()
            .unwrap();
        assert_eq!(status["capture_outcome"], "not_started");
        assert!(store.reserve(f.intent.clone()).is_err());
        assert!(!f.cfg.root.join(record_name(f.cfg.capture)).exists());
        assert_eq!(store.reserved_bytes().unwrap(), 0);
        f.intent.writer.require_present().unwrap();
        f.intent.source_directory.require_present().unwrap();
        drop(store);
        f.close();
    }
}
