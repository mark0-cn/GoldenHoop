//! A dedicated held session per staged owned network. Persisted observations
//! never construct this task's process-local monotonic authority.
use super::*;
use goldenhoop_docker::{
    ControllerSession, QuarantineProtection, VerifiedPolicyLease, WorkloadNetworkPlan,
};
use goldenhoop_egress::controller::{Reply, Request};
use goldenhoop_store::{NetworkPolicyOwner, NetworkPolicyPhase};
use tokio::time::Instant as LeaseInstant;

const PUBLICATION_MARGIN: Duration = Duration::from_secs(1);
const RENEWAL_TICK: Duration = Duration::from_millis(300);

fn renewal_due(since_last: Duration, remaining: Duration, slowest_exchange: Duration) -> bool {
    // Reserve the actual exchange cost *before* the old publication expires.
    // One further second covers scheduling/readback variance. Neither this
    // estimate nor an exchange in flight extends any verified lease.
    let headroom = slowest_exchange
        .saturating_add(PUBLICATION_MARGIN)
        .saturating_add(Duration::from_secs(1))
        .max(Duration::from_secs(
            u64::from(goldenhoop_egress::LEASE_SECONDS) / 2,
        ));
    since_last >= Duration::from_secs(2) || remaining <= headroom
}

#[derive(Clone)]
struct Live {
    owner: NetworkPolicyOwner,
    desired_revision: u64,
    until: LeaseInstant,
}
struct RenewalTiming {
    sandbox_id: Uuid,
    controller_generation: Uuid,
    started: LeaseInstant,
    finished: LeaseInstant,
    previous_verified: Duration,
    previous_published_until: Option<LeaseInstant>,
    since_last_exchange: Duration,
}
impl RenewalTiming {
    fn report(self, outcome: &str, remaining: Option<Duration>, error: Option<&ApiError>) {
        eprintln!(
            "{}",
            serde_json::json!({
                "event":"network_policy_renewal_window",
                "sandbox_id":self.sandbox_id,
                "controller_generation":self.controller_generation,
                "outcome":outcome,
                "exchange_milliseconds":self.finished.duration_since(self.started).as_millis(),
                "since_last_exchange_milliseconds":self.since_last_exchange.as_millis(),
                "previous_verified_milliseconds":self.previous_verified.as_millis(),
                "previous_published_milliseconds":self.previous_published_until.map(|end|end.saturating_duration_since(self.started).as_millis()),
                "publication_expired_at_start":self.previous_published_until.map(|end|end<=self.started),
                "publication_expired_at_finish":self.previous_published_until.map(|end|end<=self.finished),
                "next_verified_milliseconds":remaining.map(|value|value.as_millis()),
                "error_code":error.map(|value|&value.code),
            })
        );
    }
}
pub(super) struct NetworkTask {
    live: watch::Receiver<Option<Live>>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}
fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "owned network has no current worker-held policy lease",
    )
}
fn dispatch_error(reason: &'static str) -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        format!("protected dispatch is unavailable: {reason}"),
    )
}
impl Worker {
    /// None-network profiles retain their existing dispatch path. Owned network
    /// work requires both the current desired metadata and this process's lease.
    pub(super) async fn require_network_dispatch(&self, id: Uuid) -> Result<(), ApiError> {
        let allocation = match self.store.network_allocation(id).await {
            Err(e) if e.code == ErrorCode::NotFound => return Ok(()),
            Err(e) => return Err(e),
            Ok(value) => value,
        };
        if allocation.phase != goldenhoop_store::NetworkPhase::Bound {
            return Err(dispatch_error("allocation is not bound"));
        }
        let tasks = self.network_tasks.lock().await;
        let task = tasks
            .get(&id)
            .ok_or_else(|| dispatch_error("controller task is absent"))?;
        let live = task
            .live
            .borrow()
            .clone()
            .ok_or_else(|| dispatch_error("controller has not published a private lease"))?;
        if task.task.is_finished() || task.live.has_changed().is_err() {
            return Err(dispatch_error(
                "controller task or publication channel ended",
            ));
        }
        if live.until <= LeaseInstant::now() {
            return Err(dispatch_error("published private readiness expired"));
        }
        // Do not keep the task-map mutex across a store operation.
        drop(tasks);
        let current = self.store.network_policy(id).await?;
        let controller = self
            .store
            .network_controller(id, live.owner.controller_generation)
            .await?;
        if current.phase != NetworkPolicyPhase::Active
            || current.allocation_generation != allocation.generation
        {
            return Err(dispatch_error(
                "policy is not active for the current allocation",
            ));
        }
        if controller.phase != goldenhoop_store::ControllerPhase::Running
            || controller.container_id.as_ref() != Some(&live.owner.container_id)
        {
            return Err(dispatch_error(
                "controller is not the observed running owner",
            ));
        }
        if current.desired_revision != live.desired_revision
            || current.owner.as_ref() != Some(&live.owner)
        {
            return Err(dispatch_error(
                "desired revision or controller owner changed",
            ));
        }
        if live.owner.worker_id != self.registration.id
            || self.store.worker().await?.id != self.registration.id
        {
            return Err(dispatch_error("worker registration changed"));
        }
        if self.store.effective_desired(id).await? != DesiredState::Running {
            return Err(dispatch_error(
                "sandbox or ancestor is not accepting running work",
            ));
        }
        if live.until <= LeaseInstant::now() {
            return Err(dispatch_error(
                "private readiness expired during durable validation",
            ));
        }
        Ok(())
    }
    pub(super) async fn rpc(
        &self,
        driver: &DockerDriver,
        handle: &RuntimeHandle,
        request: &AgentRequest,
    ) -> Result<AgentResponse, ApiError> {
        self.require_network_dispatch(handle.sandbox_id).await?;
        driver.rpc(handle, request).await
    }
    pub(super) async fn rpc_reply(
        &self,
        driver: &DockerDriver,
        handle: &RuntimeHandle,
        request: &AgentRequest,
    ) -> Result<AgentReply, ApiError> {
        self.require_network_dispatch(handle.sandbox_id).await?;
        driver.rpc_reply(handle, request).await
    }
    pub(super) async fn stop_network_task(&self, id: Uuid) -> Result<(), ApiError> {
        let Some(mut task) = self.network_tasks.lock().await.remove(&id) else {
            return Ok(());
        };
        let _ = task.stop.send(true);
        if tokio::time::timeout(Duration::from_secs(30), &mut task.task)
            .await
            .is_err()
        {
            // Preserve the still-running creator. Collection must not race it.
            self.network_tasks.lock().await.insert(id, task);
            return Err(unavailable());
        }
        Ok(())
    }
    pub(super) async fn ensure_network_task(
        &self,
        id: Uuid,
        driver: Arc<DockerDriver>,
    ) -> Result<(), ApiError> {
        let mut tasks = self.network_tasks.lock().await;
        if tasks.get(&id).is_some_and(|task| !task.task.is_finished()) {
            return Ok(());
        }
        tasks.remove(&id);
        let image = self
            .network_controller_image
            .clone()
            .ok_or_else(unavailable)?;
        let (stop, shutdown) = watch::channel(false);
        let (sender, live) = watch::channel(None);
        let store = self.store.clone();
        let worker = self.registration.id;
        let task = tokio::spawn(async move {
            if let Err(error) = hold(store, driver, worker, image, id, sender, shutdown).await {
                report("network_policy_session_failed", &error);
            }
        });
        tasks.insert(id, NetworkTask { live, stop, task });
        Ok(())
    }
    /// Adopt only an explicitly staged complete protected allocation. Legacy or
    /// partial journals keep their existing terminal collection path.
    pub(super) async fn reconcile_network(
        &self,
        mut stored: StoredSandbox,
        driver: Arc<DockerDriver>,
    ) -> Result<(), ApiError> {
        let id = stored.sandbox.id;
        let desired = self.store.effective_desired(id).await?;
        if desired == DesiredState::Terminated
            && stored.sandbox.desired_state != DesiredState::Terminated
        {
            self.store
                .set_desired(id, DesiredState::Terminated, &format!("tree-close-{id}"))
                .await?;
            stored = self.store.sandbox(id).await?;
        }
        if desired == DesiredState::Terminated
            || matches!(
                stored.sandbox.state,
                SandboxState::Failed | SandboxState::Terminated
            )
        {
            return self
                .stop(
                    stored,
                    &driver,
                    "owned network termination requested",
                    ExecutionState::Cancelled,
                )
                .await;
        }
        let handle = stored.handle.clone().ok_or_else(unavailable)?;
        let observed = driver.inspect(&handle).await?;
        if !matches!(
            observed.state,
            ObservedState::Running | ObservedState::Paused
        ) {
            if matches!(
                observed.state,
                ObservedState::Missing | ObservedState::Exited
            ) {
                return self
                    .stop(
                        stored,
                        &driver,
                        "owned runtime disappeared; it cannot be recreated",
                        ExecutionState::Failed,
                    )
                    .await;
            }
            self.save(
                stored,
                SandboxState::Unknown,
                CleanupState::Unknown,
                Some("owned runtime observation is uncertain".into()),
            )
            .await?;
            return Err(unavailable());
        }
        if desired == DesiredState::Paused {
            self.stop_network_task(id).await?;
            let policy = self.store.network_policy(id).await?;
            if let Some(owner) = &policy.owner {
                self.store.fence_network_policy(id, owner).await?;
            }
            // A stopped/restarted worker may have no local task to quarantine.
            // Settle that exact controller before pausing; finite lease expiry
            // remains the failure bound if native quarantine cannot be read back.
            if let Some(active) = self.store.active_network_controller(id).await? {
                crate::host_process::collect(&self.store, active).await?;
            }
            if observed.state != ObservedState::Paused {
                driver.pause(&handle).await?;
            }
            self.save(stored, SandboxState::Paused, CleanupState::Pending, None)
                .await?;
            if self.store.subtree_settled(id).await? {
                self.store
                    .finish_operations(id, "pause", OperationState::Succeeded, None)
                    .await?;
            }
            return Ok(());
        }
        self.ensure_network_task(id, driver.clone()).await?;
        if let Err(error) = self.require_network_dispatch(id).await {
            // A historical Running observation is not Ready during recovery.
            stored = self.store.sandbox(id).await?;
            if stored.sandbox.state == SandboxState::Running {
                self.save(
                    stored,
                    SandboxState::Unknown,
                    CleanupState::Unknown,
                    Some(format!(
                        "waiting for fresh protected policy lease: {}",
                        error.message
                    )),
                )
                .await?;
            }
            return Ok(());
        }
        // The actor resumes a paused runtime only after fresh quarantine and
        // actual DNS restoration, then activates and reads back the policy.
        if driver.inspect(&handle).await?.state != ObservedState::Running {
            return Err(unavailable());
        }
        self.require_network_dispatch(id).await?;
        stored = self.store.sandbox(id).await?;
        self.save(stored, SandboxState::Running, CleanupState::Pending, None)
            .await?;
        self.store
            .finish_operations(id, "create", OperationState::Succeeded, None)
            .await?;
        if self.store.subtree_settled(id).await? {
            self.store
                .finish_operations(id, "resume", OperationState::Succeeded, None)
                .await?;
        }
        if !self.sync_contexts(&handle, &driver).await? {
            return Ok(());
        }
        for execution in self.store.execution_work(id).await?.into_iter().take(16) {
            self.require_network_dispatch(id).await?;
            if !self.sync_execution(&handle, &driver, execution).await? {
                break;
            }
        }
        Ok(())
    }
}
async fn call(
    session: &mut ControllerSession,
    request: Request,
) -> Result<serde_json::Value, ApiError> {
    match session
        .call(request, LeaseInstant::now() + Duration::from_secs(10))
        .await
        .map_err(|_| unavailable())?
    {
        Reply::Result(value) => Ok(value),
        Reply::Error(error) => Err(error),
    }
}
async fn hold(
    store: Store,
    driver: Arc<DockerDriver>,
    worker: Uuid,
    image: String,
    id: Uuid,
    live: watch::Sender<Option<Live>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ApiError> {
    let mut intent = store.network_policy(id).await?;
    if let Some(owner) = &intent.owner {
        store.fence_network_policy(id, owner).await?;
    }
    if let Some(old) = store.active_network_controller(id).await? {
        crate::host_process::collect(&store, old).await?;
    }
    if *shutdown.borrow()
        || store.effective_desired(id).await? != DesiredState::Running
        || store.worker().await?.id != worker
    {
        return Ok(());
    }
    let reserved = store
        .reserve_network_controller(id, intent.allocation_generation, Uuid::new_v4(), &image)
        .await?;
    let started = crate::host_process::start_controller(&store, &reserved).await;
    let (record, mut session) = match started {
        Ok(value) => value,
        Err(error) => {
            let fresh = store
                .network_controller(id, reserved.controller_generation)
                .await?;
            crate::host_process::collect(&store, fresh).await?;
            return Err(error);
        }
    };
    let result = async {
        intent = store.network_policy(id).await?;
        intent = store
            .claim_network_policy(id, intent.revision, worker, record.controller_generation)
            .await?;
        let owner = intent.owner.clone().ok_or_else(unavailable)?;
        let sandbox = store.sandbox(id).await?;
        let handle = sandbox.handle.as_ref().ok_or_else(unavailable)?;
        let network = store.network_allocation(id).await?;
        let network = WorkloadNetworkPlan {
            native: record.plan.controller()?.native.clone(),
            network_id: network.native_binding().ok_or_else(unavailable)?.network_id,
        };
        let protection = QuarantineProtection {
            upstream: intent.upstream,
            private_exceptions: intent
                .checkpoint
                .destinations
                .scope
                .private_exceptions
                .clone(),
            control_addresses: intent
                .checkpoint
                .destinations
                .scope
                .control_addresses
                .clone(),
        };
        let frozen = driver
            .recover_quarantined_network(
                handle,
                &network,
                &mut session,
                &intent.checkpoint,
                &protection,
            )
            .await?;
        if driver.inspect(handle).await?.state == ObservedState::Paused {
            if store.effective_desired(id).await? != DesiredState::Running {
                return Ok(());
            }
            driver.resume(handle).await?;
        }
        let mut lease: Option<VerifiedPolicyLease> = None;
        let mut applied_revision = None;
        let mut last = LeaseInstant::now();
        let mut timing_records_left = 8;
        let mut slowest_exchange = Duration::from_secs(2);
        loop {
            if *shutdown.borrow() || store.effective_desired(id).await? != DesiredState::Running {
                break;
            }
            if store.worker().await?.id != worker {
                return Err(unavailable());
            }
            intent = store.network_policy(id).await?;
            if intent.owner.as_ref() != Some(&owner) || intent.phase == NetworkPolicyPhase::Fenced {
                return Err(unavailable());
            }
            let mut renewal_timing = None;
            if applied_revision != Some(intent.desired_revision) {
                let started = LeaseInstant::now();
                live.send_replace(None);
                intent = store
                    .begin_network_policy_apply(id, intent.revision, &owner)
                    .await?;
                let next = if let Some(previous) = &lease {
                    driver
                        .replace_protected_policy(
                            handle,
                            &network,
                            &mut session,
                            previous,
                            &intent.config,
                        )
                        .await?
                } else {
                    driver
                        .apply_protected_policy(
                            handle,
                            &network,
                            &mut session,
                            &frozen,
                            &intent.config,
                        )
                        .await?
                };
                intent = store
                    .confirm_network_policy(
                        id,
                        intent.revision,
                        &owner,
                        intent.attempt.ok_or_else(unavailable)?,
                        next.receipt().clone(),
                    )
                    .await?;
                applied_revision = Some(intent.desired_revision);
                lease = Some(next);
                last = LeaseInstant::now();
                slowest_exchange = slowest_exchange.max(last.duration_since(started));
            } else if renewal_due(
                last.elapsed(),
                lease.as_ref().ok_or_else(unavailable)?.remaining(),
                slowest_exchange,
            ) {
                // Native readback deducts the entire exchange latency. A
                // successful exchange can therefore leave much less than the
                // maximum lease. Renew promptly when that remaining budget is
                // low; a fixed post-exchange delay can expire the published
                // readiness window even while the controller stays healthy.
                // The native lifetime and old live-until fence are unchanged.
                if intent.phase != NetworkPolicyPhase::Active {
                    return Err(unavailable());
                }
                let started = LeaseInstant::now();
                let previous_verified = lease.as_ref().ok_or_else(unavailable)?.remaining();
                let previous_published_until = live.borrow().as_ref().map(|value| value.until);
                let since_last_exchange = last.elapsed();
                let result = driver
                    .renew_protected_policy(
                        handle,
                        &network,
                        &mut session,
                        lease.as_ref().ok_or_else(unavailable)?,
                    )
                    .await;
                slowest_exchange = slowest_exchange.max(started.elapsed());
                if timing_records_left > 0 {
                    timing_records_left -= 1;
                    renewal_timing = Some(RenewalTiming {
                        sandbox_id: id,
                        controller_generation: record.controller_generation,
                        started,
                        finished: LeaseInstant::now(),
                        previous_verified,
                        previous_published_until,
                        since_last_exchange,
                    });
                }
                let next = match result {
                    Ok(next) => next,
                    Err(error) => {
                        if let Some(timing) = renewal_timing {
                            timing.report("exchange_failed", None, Some(&error));
                        }
                        return Err(error);
                    }
                };
                lease = Some(next);
                last = LeaseInstant::now();
            }
            let remaining = lease.as_ref().ok_or_else(unavailable)?.remaining();
            let usable = remaining
                .checked_sub(PUBLICATION_MARGIN)
                .filter(|d| !d.is_zero());
            let Some(usable) = usable else {
                let error = unavailable();
                if let Some(timing) = renewal_timing {
                    timing.report("insufficient_margin", Some(remaining), Some(&error));
                }
                return Err(error);
            };
            live.send_replace(Some(Live {
                owner: owner.clone(),
                desired_revision: intent.desired_revision,
                until: LeaseInstant::now() + usable,
            }));
            // Diagnostics follow successful publication and never grant a lease.
            // Each epoch emits at most eight records without policy payloads.
            if let Some(timing) = renewal_timing {
                timing.report("published", Some(remaining), None);
            }
            tokio::select! {
                result=shutdown.changed()=>{if result.is_err() || *shutdown.borrow(){break;}},
                _=tokio::time::sleep(RENEWAL_TICK)=>{},
            }
        }
        Ok::<_, ApiError>(())
    }
    .await;
    live.send_replace(None);
    // Fence before cleanup. A lost/failed response never leaves Ready intact.
    let fenced = if let Some(owner) = &intent.owner
        && owner.controller_generation == record.controller_generation
    {
        store.fence_network_policy(id, owner).await
    } else {
        Ok(())
    };
    // Best-effort immediate native quarantine; its response is not cleanup.
    // Physical positive collection below is mandatory, including error paths.
    if let Ok(state) = call(&mut session, Request::Inspect {}).await
        && let Some(revision) = state["revision"].as_u64()
    {
        let _ = call(
            &mut session,
            Request::Quarantine {
                expected_revision: revision,
            },
        )
        .await;
    }
    let _ = session.close().await;
    let fresh = store
        .network_controller(id, record.controller_generation)
        .await?;
    crate::host_process::collect(&store, fresh).await?;
    fenced?;
    result
}

#[cfg(test)]
mod renewal_tests {
    use super::*;
    #[test]
    fn observed_slow_exchange_is_reserved_before_private_publication_expires() {
        let exchange = Duration::from_millis(4800);
        let remaining = Duration::from_millis(6800);
        // The old two-second/half-native-lifetime rule waited here. Its next
        // observed 4.8 s exchange crossed the private (native minus 1 s) fence.
        assert!(renewal_due(Duration::from_millis(300), remaining, exchange));
        assert!(remaining.checked_sub(PUBLICATION_MARGIN).unwrap() > exchange);
        assert!(!renewal_due(
            Duration::from_millis(300),
            Duration::from_secs(9),
            Duration::from_millis(50)
        ));
        assert!(renewal_due(
            Duration::from_secs(2),
            Duration::from_secs(9),
            Duration::from_millis(50)
        ));
    }
}
