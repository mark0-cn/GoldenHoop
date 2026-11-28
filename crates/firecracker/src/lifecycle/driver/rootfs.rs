//! Manager-owned disk-only jobs. Client IPC owns neither the original source
//! lease nor a producer which might continue after a reply is lost.
use super::*;
use crate::rootfs::{RootfsCaptureIntent, storage::RootfsStore};

impl DriverConfig {
    pub(crate) fn rootfs_store(&self) -> Result<RootfsStore> {
        let policy = self.rootfs.as_ref().ok_or_else(|| {
            ApiError::new(
                ErrorCode::UnsupportedCapability,
                "native rootfs capture is disabled",
            )
        })?;
        RootfsStore::open_or_initialize(
            &self.data_root.join("rootfs"),
            self.installation_id,
            policy.store.clone(),
        )
    }
}
fn bound(intent: &RootfsCaptureIntent, record: &VmJournal) -> Result<()> {
    let source = &intent.source;
    let owner = &record.owner;
    if source.installation != owner.installation_id
        || source.sandbox != owner.sandbox_id
        || source.source_generation != owner.generation
        || source.request_sha256 != owner.request_sha256
    {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "rootfs capture belongs to another original source intent",
        )
        .into());
    }
    Ok(())
}
impl NativeEngine {
    pub(in crate::lifecycle) async fn rootfs_capture(
        &self,
        handle: &RuntimeHandle,
        capture: Uuid,
    ) -> std::result::Result<serde_json::Value, ApiError> {
        let result:Result<serde_json::Value>=async {
            if capture.is_nil() {return Err(ApiError::new(ErrorCode::InvalidRequest,"rootfs capture ID is nil").into());}
            let store=self.inner.cfg.rootfs_store()?;
            let before=self.for_handle(handle)?;
            let original=store.intent(capture)?;
            if let Some(intent)=&original {
                bound(intent,&before)?;
                let status=store.inspect(capture)?;
                if matches!(status["phase"].as_str(),Some("ready"|"collected")) || status["source_resumed"]==true && status["producer_settled"]==true && before.rootfs_hold!=Some(capture) {return Ok(status);}
            }
            let guard=match self.vm_lock(handle.sandbox_id).await.try_lock_owned() {
                Ok(guard)=>guard,
                Err(_) if original.is_some()=>return store.inspect(capture),
                Err(_)=>return Err(ApiError::new(ErrorCode::BackendUnavailable,"original source operation is busy; reconcile its intent").into()),
            };
            let record=self.for_handle(handle)?;
            if record.capture_hold.is_some() || record.rootfs_hold.is_some_and(|id|id!=capture) {return Err(ApiError::new(ErrorCode::InvalidState,"source is fenced by another capture kind or operation").into());}
            let machine=Machine::recover(&self.inner.cfg,record.clone())?;
            let input=record.artifacts.clone();
            let policy=self.inner.cfg.rootfs.as_ref().expect("validated rootfs policy").clone();
            let permit=self.inner.capture_slot.clone().try_acquire_owned().map_err(|_|ApiError::new(ErrorCode::QuotaExceeded,"native capture worker is reserved"))?;
            let mut session=if let Some(intent)=&original {bound(intent,&record)?;store.resume(intent)?} else {
                self.live_agent(&record).await?;
                machine.reserve_rootfs(&input,capture,&policy,&store).await?
            };
            // A stored recovery receipt closes all guest/VMM effects. Finish a
            // lost final acknowledgement without taking a new source hold.
            if session.source_resumed() && record.rootfs_hold.is_none() {
                session.settle()?;drop(session);return store.inspect(capture);
            }
            let accepted=store.inspect(capture)?;
            let actor=self.clone();let recovered=original.is_some();let handle=handle.clone();
            let task=tokio::task::spawn_blocking(move || {
                let _source_guard=guard;let _permit=permit;
                let runtime=match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(runtime)=>runtime,Err(error)=>{session.fail(&error.to_string())?;return Err(error.into());}
                };
                let outcome=runtime.block_on(async {
                    if let Err(error)=actor.supervisor_call(&record,SupervisorOperation::RootfsHold {capture}).await {session.fail(&error.to_string())?;return Err(error);}
                    if recovered {
                        if session.manifest().is_none() {session.fail("original producer stopped before a captured disk was acknowledged; source recovery only")?;}
                    } else if let Err(error)=machine.capture_rootfs(&input,&mut session).await {session.fail(&error.to_string())?;}
                    // Captured/Failed is durable before any VMM resume or thaw.
                    machine.recover_rootfs_source(&input,&mut session).await?;
                    let current=actor.for_handle(&handle)?;
                    if actor.supervisor_call(&current,SupervisorOperation::RootfsRelease {capture}).await?!=ObservedState::Running {return Err(invalid("rootfs recovered source release is unconfirmed").into());}
                    session.settle()?;
                    Ok(())
                });
                if let Err(error)=&outcome
                    && let Err(record_error)=session.settle() {
                    return Err(invalid(format!("{error}; producer I/O settlement is unconfirmed: {record_error}")).into());
                }
                outcome
            });
            self.inner.capture_tasks.lock().map_err(|_|invalid("capture task registry poisoned"))?.push(task);
            Ok(accepted)
        }.await;
        result.map_err(|e| {
            e.downcast_ref::<ApiError>()
                .cloned()
                .unwrap_or_else(|| unavailable(e))
        })
    }
    pub(in crate::lifecycle) async fn rootfs_read(
        &self,
        handle: &RuntimeHandle,
        capture: Uuid,
        collect: bool,
    ) -> std::result::Result<serde_json::Value, ApiError> {
        let result: Result<serde_json::Value> = async {
            if capture.is_nil() {
                return Err(
                    ApiError::new(ErrorCode::InvalidRequest, "rootfs capture ID is nil").into(),
                );
            }
            let store = self.inner.cfg.rootfs_store()?;
            let record = self.for_handle(handle)?;
            if collect && record.rootfs_hold == Some(capture) && record.phase != "collected" {
                return Err(ApiError::new(
                    ErrorCode::InvalidState,
                    "original rootfs source release remains unconfirmed",
                )
                .into());
            }
            let intent = store
                .intent(capture)?
                .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "rootfs capture not found"))?;
            bound(&intent, &record)?;
            tokio::task::spawn_blocking(move || {
                if collect {
                    store.collect(capture)
                } else {
                    store.inspect(capture)
                }
            })
            .await?
        }
        .await;
        result.map_err(|e| {
            e.downcast_ref::<ApiError>()
                .cloned()
                .unwrap_or_else(|| unavailable(e))
        })
    }
}
