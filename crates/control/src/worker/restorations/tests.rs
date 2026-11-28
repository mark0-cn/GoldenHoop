//! Actual SQLite/reopen and worker RPC; VM/agent observations are synthetic.
use super::*;
use async_trait::async_trait;
use futures_util::FutureExt;
use std::{
    collections::{BTreeMap, HashSet},
    future::Future,
    panic::AssertUnwindSafe,
    sync::{
        Mutex as StdMutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

fn profile() -> RuntimeProfile {
    serde_json::from_value(serde_json::json!({"id":"restore-worker-fixture","placement":"local","isolation":"firecracker","availability":"available","capabilities":["commands","files","pause","network_isolation","memory_snapshot"],"max_resources":{"cpu_millis":4000,"memory_bytes":4294967296_u64,"pids":1024},"max_ttl_seconds":3600})).unwrap()
}
fn uncertain() -> ApiError {
    ApiError::new(ErrorCode::BackendUnavailable, "synthetic lost native reply")
}
#[derive(Default)]
struct Backend {
    target: StdMutex<Option<(Uuid, Uuid, RuntimeHandle)>>,
    execution: StdMutex<Option<Execution>>,
    events: StdMutex<Vec<ExecutionEvent>>,
    closed: StdMutex<HashSet<Uuid>>,
    lose_restore: AtomicBool,
    lose_close: AtomicBool,
    allocations: AtomicUsize,
    starts: AtomicUsize,
    closes: AtomicUsize,
    cancellations: StdMutex<Vec<Uuid>>,
    event_cursors: StdMutex<Vec<u64>>,
}
#[async_trait]
impl RuntimeDriver for Backend {
    fn supports_memory_restore(&self) -> bool {
        true
    }
    async fn restore_memory(&self, r: &MemoryRestoreRequest) -> Result<RuntimeHandle, ApiError> {
        r.validate_identity()?;
        if self.closed.lock().unwrap().contains(&r.target.id) {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "synthetic target is closed",
            ));
        }
        let mut target = self.target.lock().unwrap();
        if target.is_none() {
            *target = Some((
                r.target.id,
                r.restoration,
                RuntimeHandle {
                    sandbox_id: r.target.id,
                    profile: r.target.profile.clone(),
                    backend_ref: format!("new-private-generation-{}", Uuid::new_v4()),
                },
            ));
            self.allocations.fetch_add(1, Ordering::SeqCst);
        }
        let (id, operation, handle) = target.as_ref().unwrap();
        assert_eq!((*id, *operation), (r.target.id, r.restoration));
        if self.lose_restore.swap(false, Ordering::SeqCst) {
            return Err(uncertain());
        }
        Ok(handle.clone())
    }
    async fn collect_memory_restore(&self, r: &MemoryRestoreRequest) -> Result<(), ApiError> {
        r.validate_identity()?;
        self.closed.lock().unwrap().insert(r.target.id);
        self.closes.fetch_add(1, Ordering::SeqCst);
        if self.lose_close.swap(false, Ordering::SeqCst) {
            return Err(uncertain());
        }
        Ok(())
    }
    async fn probe(&self) -> RuntimeProfile {
        profile()
    }
    async fn create(&self, _: &Sandbox, _: &CreateSandbox) -> Result<RuntimeHandle, ApiError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        panic!("restoration attempted ordinary create")
    }
    async fn inspect(&self, handle: &RuntimeHandle) -> Result<RuntimeObservation, ApiError> {
        let target = self.target.lock().unwrap();
        assert!(target.as_ref().is_some_and(
            |(id, _, h)| *id == handle.sandbox_id && h.backend_ref == handle.backend_ref
        ));
        Ok(RuntimeObservation {
            state: if self.closed.lock().unwrap().contains(&handle.sandbox_id) {
                ObservedState::Missing
            } else {
                ObservedState::Running
            },
            exit_code: None,
            oom_killed: None,
            observed_at: Utc::now(),
        })
    }
    async fn remove(&self, handle: &RuntimeHandle) -> Result<(), ApiError> {
        assert!(
            self.closed.lock().unwrap().contains(&handle.sandbox_id),
            "generic remove preceded durable restoration close"
        );
        Ok(())
    }
    async fn discover(&self) -> Result<Vec<RuntimeHandle>, ApiError> {
        Ok(self
            .target
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(id, _, _)| !self.closed.lock().unwrap().contains(id))
            .map(|(_, _, h)| vec![h.clone()])
            .unwrap_or_default())
    }
}
#[async_trait]
impl AgentTransport for Backend {
    async fn rpc(
        &self,
        handle: &RuntimeHandle,
        request: &AgentRequest,
    ) -> Result<AgentResponse, ApiError> {
        assert!(!self.closed.lock().unwrap().contains(&handle.sandbox_id));
        let mut job = self.execution.lock().unwrap();
        match request {
            AgentRequest::Inspect { id } => {
                let job = job.as_ref().filter(|job| job.id == *id).ok_or_else(|| {
                    ApiError::new(ErrorCode::NotFound, "retained execution missing")
                })?;
                Ok(AgentResponse::Execution(job.clone()))
            }
            AgentRequest::Cancel { id } => {
                self.cancellations.lock().unwrap().push(*id);
                let job = job.as_mut().filter(|job| job.id == *id).unwrap();
                job.state = ExecutionState::Cancelled;
                job.cleanup = CleanupState::Complete;
                job.finished_at = Some(Utc::now());
                let mut events = self.events.lock().unwrap();
                let sequence = events.last().unwrap().sequence + 1;
                events.push(ExecutionEvent {
                    sequence,
                    execution_id: *id,
                    timestamp: Utc::now(),
                    kind: EventKind::Completed,
                    data: serde_json::to_value(&*job).unwrap(),
                });
                Ok(AgentResponse::Execution(job.clone()))
            }
            AgentRequest::Events { id, after } => {
                assert_eq!(job.as_ref().unwrap().id, *id);
                self.event_cursors.lock().unwrap().push(*after);
                Ok(AgentResponse::Events(
                    self.events
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|e| e.sequence > *after)
                        .cloned()
                        .collect(),
                ))
            }
            AgentRequest::Start { .. } | AgentRequest::StartSession { .. } => {
                self.starts.fetch_add(1, Ordering::SeqCst);
                panic!("retained command was replayed through Start")
            }
            _ => panic!("unexpected synthetic restoration RPC"),
        }
    }
}
#[async_trait]
impl WorkerDriver for Backend {
    async fn profile_snapshot(&self) -> RuntimeProfile {
        profile()
    }
    async fn reap_expired(&self) -> Result<Vec<Uuid>, ApiError> {
        Ok(Vec::new())
    }
}
fn worker(
    store: Store,
    backend: Arc<Backend>,
    artifacts: goldenhoop_artifacts::BlobStore,
) -> Arc<Worker> {
    Arc::new(Worker {
        store,
        drivers: HashMap::from([(profile().id, backend as Arc<dyn WorkerDriver>)]),
        registration: WorkerRegistration {
            id: Uuid::new_v4(),
            endpoint: "http://127.0.0.1:1".into(),
            token: "restore-worker-synthetic-token-0123456789".into(),
            heartbeat: Utc::now(),
            profiles: vec![profile()],
        },
        locks: Mutex::new(HashMap::new()),
        concurrency: Arc::new(Semaphore::new(4)),
        cancellations: Mutex::new(HashMap::new()),
        context_closures: Mutex::new(HashMap::new()),
        artifacts,
        artifact_concurrency: Arc::new(Semaphore::new(2)),
        snapshot_concurrency: Arc::new(Semaphore::new(1)),
        network_controller_image: None,
        network_options: None,
        credentials: None,
        network_tasks: Mutex::new(HashMap::new()),
    })
}
type Pools = Arc<StdMutex<Vec<Store>>>;
async fn checked<F, Fut>(test: F)
where
    F: FnOnce(Arc<Worker>, Arc<Backend>, std::path::PathBuf, Pools) -> Fut,
    Fut: Future<Output = ()>,
{
    let directory = tempfile::Builder::new()
        .prefix("gh-restore-worker-")
        .tempdir()
        .unwrap();
    let root = directory.path().to_owned();
    let path = root.join("state.db");
    let store = Store::open(&path).await.unwrap();
    let pools = Arc::new(StdMutex::new(vec![store.clone()]));
    let backend = Arc::new(Backend::default());
    let blobs =
        goldenhoop_artifacts::BlobStore::local(&root.join("blobs"), store.installation_id())
            .unwrap();
    let w = worker(store, backend.clone(), blobs);
    let result = AssertUnwindSafe(test(w.clone(), backend, path, pools.clone()))
        .catch_unwind()
        .await;
    let all = std::mem::take(&mut *pools.lock().unwrap());
    for pool in all {
        pool.close().await;
    }
    drop(w);
    directory.close().unwrap();
    assert!(!root.exists());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
async fn prepared(w: &Worker, b: &Backend) -> (Uuid, RestoreSnapshot, Execution) {
    let request = CreateSandbox::new(profile().id, "synthetic-image");
    let src = w
        .store
        .create_sandbox(&profile(), &request, "source")
        .await
        .unwrap()
        .sandbox
        .id;
    let source_handle = RuntimeHandle {
        sandbox_id: src,
        profile: profile().id,
        backend_ref: "original-private-generation".into(),
    };
    let mut stored = w.store.sandbox(src).await.unwrap();
    stored.sandbox.state = SandboxState::Starting;
    w.store.observe(stored.clone()).await.unwrap();
    stored.sandbox.state = SandboxState::Running;
    stored.handle = Some(source_handle.clone());
    w.store.observe(stored).await.unwrap();
    let mut old = w
        .store
        .create_execution(src, &CommandSpec::new(["retained-command"]), "command")
        .await
        .unwrap();
    old.state = ExecutionState::Running;
    old.started_at = Some(Utc::now());
    old.cleanup = CleanupState::Pending;
    let first = ExecutionEvent {
        sequence: 1,
        execution_id: old.id,
        timestamp: Utc::now(),
        kind: EventKind::Started,
        data: serde_json::json!({}),
    };
    w.store
        .persist_execution(&old, std::slice::from_ref(&first))
        .await
        .unwrap();
    *b.execution.lock().unwrap() = Some(old.clone());
    *b.events.lock().unwrap() = vec![
        first,
        ExecutionEvent {
            sequence: 2,
            execution_id: old.id,
            timestamp: Utc::now(),
            kind: EventKind::Stdout,
            data: serde_json::json!({"data":"YWZ0ZXI="}),
        },
    ];
    let created = w
        .store
        .create_snapshot(
            &profile(),
            src,
            &CreateSnapshot {
                kind: SnapshotKind::MemoryAndDisk,
            },
            "capture",
        )
        .await
        .unwrap();
    let id = created.snapshot.id;
    w.store
        .begin_snapshot_capture(id, &source_handle)
        .await
        .unwrap();
    let manifest = SnapshotManifest {
        format_version: 1,
        id,
        source_sandbox_id: src,
        kind: SnapshotKind::MemoryAndDisk,
        driver: profile().id,
        architecture: "x86_64".into(),
        image_digest: request.image.clone(),
        objects: BTreeMap::from([
            ("state".into(), format!("sha256:{}", "a".repeat(64))),
            ("memory".into(), format!("sha256:{}", "b".repeat(64))),
            ("disk".into(), format!("sha256:{}", "c".repeat(64))),
        ]),
        runtime_version: "synthetic".into(),
        created_at: created.snapshot.created_at,
    };
    w.store
        .snapshot_capture_ready(
            id,
            &source_handle,
            &manifest,
            &serde_json::json!({"capture":id,"private":"not-public"}),
        )
        .await
        .unwrap();
    w.store
        .set_desired(src, DesiredState::Terminated, "explicit-source-delete")
        .await
        .unwrap();
    let mut source = w.store.sandbox(src).await.unwrap();
    source.sandbox.state = SandboxState::Stopping;
    w.store.observe(source.clone()).await.unwrap();
    source.sandbox.state = SandboxState::Terminated;
    source.sandbox.cleanup = CleanupState::Complete;
    source.handle = None;
    w.store.observe(source).await.unwrap();
    w.store
        .finish_execution(old.id, ExecutionState::Cancelled, "source collected")
        .await
        .unwrap();
    (id, RestoreSnapshot { target: request }, old)
}
async fn step(w: &Worker, target: Uuid) -> Result<(), ApiError> {
    let _guard = w.lock(target).await.lock_owned().await;
    w.reconcile(target).await
}

#[tokio::test]
async fn lost_restore_reply_reopens_the_same_target_and_maps_retained_events_and_cancellation() {
    checked(|mut w, b, path, pools| async move {
        let (snapshot, intent, old) = prepared(&w, &b).await;
        let restored = w
            .admit_restoration(snapshot, &intent, "restore")
            .await
            .unwrap();
        let target = restored.sandbox.id;
        let eid = restored.executions[0].execution.id;
        b.lose_restore.store(true, Ordering::SeqCst);
        step(&w, target).await.unwrap();
        assert_eq!(
            w.store.sandbox(target).await.unwrap().sandbox.state,
            SandboxState::Unknown
        );
        assert_eq!(
            w.store
                .operation(restored.operation.id)
                .await
                .unwrap()
                .state,
            OperationState::Running
        );
        assert_eq!(b.allocations.load(Ordering::SeqCst), 1);
        assert!(w.store.delete_snapshot(snapshot, "held").await.is_err());
        w.store.close().await;
        let reopened = Store::open(&path).await.unwrap();
        pools.lock().unwrap().push(reopened.clone());
        w = worker(reopened, b.clone(), w.artifacts.clone());
        let retry = w
            .admit_restoration(snapshot, &intent, "restore")
            .await
            .unwrap();
        assert_eq!(
            (retry.sandbox.id, retry.operation.id),
            (target, restored.operation.id)
        );
        step(&w, target).await.unwrap();
        assert_eq!(
            w.store
                .operation(restored.operation.id)
                .await
                .unwrap()
                .state,
            OperationState::Succeeded
        );
        assert_eq!(b.allocations.load(Ordering::SeqCst), 1);
        step(&w, target).await.unwrap();
        let events = w.store.events(eid, 0).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            (events[0].sequence, events[0].execution_id, events[0].kind),
            (1, eid, EventKind::Stdout)
        );
        w.store.cancel_execution(eid).await.unwrap();
        step(&w, target).await.unwrap();
        assert_eq!(*b.cancellations.lock().unwrap(), vec![old.id]);
        let events = w.store.events(eid, 0).await.unwrap();
        assert_eq!(events.len(), 2);
        let completed: Execution = serde_json::from_value(events[1].data.clone()).unwrap();
        assert_eq!(
            (
                completed.id,
                completed.sandbox_id,
                completed.state,
                completed.cleanup
            ),
            (
                eid,
                target,
                ExecutionState::Cancelled,
                CleanupState::Complete
            )
        );
        assert_eq!(events[1].sequence, 2);
        assert_eq!(
            w.store.execution(eid).await.unwrap().execution.state,
            ExecutionState::Cancelled
        );
        assert!(!w.store.execution(old.id).await.unwrap().cancel_requested);
        assert_eq!(*b.event_cursors.lock().unwrap(), vec![1, 2]);
        assert_eq!(b.starts.load(Ordering::SeqCst), 0);
    })
    .await;
}

#[tokio::test]
async fn missing_retained_execution_fails_without_start_and_lost_collection_reply_keeps_references()
{
    checked(|w, b, _, _| async move {
        let (snapshot, intent, _) = prepared(&w, &b).await;
        let restored = w
            .admit_restoration(snapshot, &intent, "restore")
            .await
            .unwrap();
        let target = restored.sandbox.id;
        *b.execution.lock().unwrap() = None;
        b.lose_close.store(true, Ordering::SeqCst);
        assert_eq!(
            step(&w, target).await.unwrap_err().code,
            ErrorCode::BackendUnavailable
        );
        assert_eq!(
            w.store
                .operation(restored.operation.id)
                .await
                .unwrap()
                .state,
            OperationState::Failed
        );
        assert_ne!(
            w.store.sandbox(target).await.unwrap().sandbox.cleanup,
            CleanupState::Complete
        );
        assert!(
            !w.store
                .restoration(target)
                .await
                .unwrap()
                .unwrap()
                .collected
        );
        assert!(w.store.delete_snapshot(snapshot, "held").await.is_err());
        assert!(
            w.store
                .snapshot(snapshot)
                .await
                .unwrap()
                .runtime_reference
                .is_some()
        );
        step(&w, target).await.unwrap();
        assert_eq!(
            w.store.sandbox(target).await.unwrap().sandbox.cleanup,
            CleanupState::Complete
        );
        assert!(
            w.store
                .restoration(target)
                .await
                .unwrap()
                .unwrap()
                .collected
        );
        assert_eq!(
            w.store
                .operation(restored.operation.id)
                .await
                .unwrap()
                .state,
            OperationState::Failed
        );
        assert!(w.store.delete_snapshot(snapshot, "held").await.is_ok());
        assert_eq!(b.starts.load(Ordering::SeqCst), 0);
        assert_eq!(b.allocations.load(Ordering::SeqCst), 1);
        assert_eq!(b.closes.load(Ordering::SeqCst), 2);
    })
    .await;
}

#[tokio::test]
async fn deleting_an_undispatched_target_closes_late_restore_authority_without_allocating_a_vm() {
    checked(|w, b, _, _| async move {
        let (snapshot, intent, _) = prepared(&w, &b).await;
        let restored = w
            .admit_restoration(snapshot, &intent, "restore")
            .await
            .unwrap();
        let target = restored.sandbox.id;
        let r = w.store.restoration(target).await.unwrap().unwrap();
        let original = w.restoration_request(&r).await.unwrap();
        assert!(!r.dispatched);
        w.store
            .set_desired(target, DesiredState::Terminated, "delete-target")
            .await
            .unwrap();
        step(&w, target).await.unwrap();
        assert_eq!(
            w.store.sandbox(target).await.unwrap().sandbox.state,
            SandboxState::Terminated
        );
        assert_eq!(
            w.store.sandbox(target).await.unwrap().sandbox.cleanup,
            CleanupState::Complete
        );
        assert_eq!(
            b.restore_memory(&original).await.unwrap_err().code,
            ErrorCode::InvalidState
        );
        assert_eq!(b.allocations.load(Ordering::SeqCst), 0);
        assert_eq!(b.starts.load(Ordering::SeqCst), 0);
        assert!(
            w.store
                .delete_snapshot(snapshot, "delete-content")
                .await
                .is_ok()
        );
        assert_eq!(
            w.store
                .prior_restoration(snapshot, &intent, "restore")
                .await
                .unwrap()
                .unwrap()
                .sandbox
                .id,
            target
        );
    })
    .await;
}
