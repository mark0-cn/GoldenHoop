use super::*;

impl Worker {
    fn runtime_request(&self, stored: &StoredSandbox) -> Result<CreateSandbox, ApiError> {
        let profile = self
            .registration
            .profiles
            .iter()
            .find(|profile| profile.id == stored.request.profile)
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::UnsupportedCapability,
                    "runtime profile is not registered",
                )
            })?;
        goldenhoop_core::validate_create(profile, &stored.request)?;
        let mut native = stored.request.clone();
        // Artifact retention is implemented by the probed host storage worker.
        // Its availability is checked above; the native driver owns file capture.
        native.required_capabilities.remove(&Capability::Artifacts);
        // Hierarchy allocation and feature ceilings are enforced by the host.
        // The native runtime receives only this node's workload hard limits.
        native
            .required_capabilities
            .remove(&Capability::IsolatedSessions);
        native.child_budget = None;
        native.feature_limit = None;
        Ok(native)
    }
    pub(super) async fn recovered_handle(
        &self,
        stored: &StoredSandbox,
        driver: &DockerDriver,
    ) -> Result<Option<RuntimeHandle>, ApiError> {
        if let Some(handle) = &stored.handle {
            return Ok(Some(handle.clone()));
        }
        Ok(driver
            .discover()
            .await?
            .into_iter()
            .find(|handle| handle.sandbox_id == stored.sandbox.id))
    }

    pub(super) async fn reconcile(&self, id: Uuid) -> Result<(), ApiError> {
        let mut stored = self.store.sandbox(id).await?;
        // Only explicitly staged complete allocations enter live control.
        // Partial/legacy journals cannot fall through to none-network creation.
        match self.store.network_allocation(id).await {
            Ok(network) if stored.sandbox.desired_state != DesiredState::Terminated => {
                match self.store.network_policy(id).await {
                    Ok(_) => {
                        let driver = self
                            .drivers
                            .get(&stored.sandbox.profile)
                            .cloned()
                            .ok_or_else(|| {
                                ApiError::new(
                                    ErrorCode::UnsupportedCapability,
                                    "worker has no matching runtime driver",
                                )
                            })?;
                        return self.reconcile_network(stored, driver).await;
                    }
                    Err(error) if error.code == ErrorCode::NotFound => {}
                    Err(error) => return Err(error),
                }
                self.store
                    .set_desired(
                        id,
                        DesiredState::Terminated,
                        &format!("network-recovery-{}", network.generation),
                    )
                    .await?;
                stored = self.store.sandbox(id).await?;
            }
            Ok(_) => {}
            Err(error) if error.code == ErrorCode::NotFound => {}
            Err(error) => return Err(error),
        }
        let driver = self.drivers.get(&stored.sandbox.profile).ok_or_else(|| {
            ApiError::new(
                ErrorCode::UnsupportedCapability,
                "worker has no matching runtime driver",
            )
        })?;
        if self.store.effective_desired(id).await? == DesiredState::Terminated
            && stored.sandbox.desired_state != DesiredState::Terminated
        {
            self.store
                .set_desired(id, DesiredState::Terminated, &format!("tree-close-{id}"))
                .await?;
            stored = self.store.sandbox(id).await?;
        }
        if stored.sandbox.desired_state == DesiredState::Terminated
            || matches!(
                stored.sandbox.state,
                SandboxState::Failed | SandboxState::Terminated
            )
        {
            let state = if stored.sandbox.state == SandboxState::Failed {
                ExecutionState::Failed
            } else {
                ExecutionState::Cancelled
            };
            return self
                .stop(stored, driver, "sandbox termination requested", state)
                .await;
        }
        stored.handle = self.recovered_handle(&stored, driver).await?;
        let observation = if let Some(handle) = &stored.handle {
            Some(driver.inspect(handle).await?)
        } else {
            None
        };
        match observation.as_ref().map(|observation| observation.state) {
            None | Some(ObservedState::Missing) if !stored.ever_running => {
                // No workload command was accepted before the first durable Running
                // observation. Confirmed absence permits an idempotent create retry.
                stored.handle = None;
                stored = self
                    .save(stored, SandboxState::Starting, CleanupState::Pending, None)
                    .await?;
                self.store
                    .finish_operations(id, "create", OperationState::Running, None)
                    .await?;
                let handle = driver
                    .create(&stored.sandbox, &self.runtime_request(&stored)?)
                    .await?;
                stored.handle = Some(handle);
                self.save(stored, SandboxState::Running, CleanupState::Pending, None)
                    .await?;
                self.store
                    .finish_operations(id, "create", OperationState::Succeeded, None)
                    .await?;
                return Ok(());
            }
            None | Some(ObservedState::Missing | ObservedState::Exited) => {
                let reason = match &observation {
                    Some(observation) if observation.state == ObservedState::Exited => format!(
                        "runtime exited before a terminal result was collected; exit_code={:?}, oom_killed={:?}",
                        observation.exit_code, observation.oom_killed
                    ),
                    _ => "runtime disappeared before a terminal result was collected".into(),
                };
                return self
                    .stop(stored, driver, &reason, ExecutionState::Failed)
                    .await;
            }
            Some(ObservedState::Starting) if !stored.ever_running => {
                stored = self
                    .save(stored, SandboxState::Starting, CleanupState::Pending, None)
                    .await?;
                let handle = driver
                    .create(&stored.sandbox, &self.runtime_request(&stored)?)
                    .await?;
                stored.handle = Some(handle);
                self.save(stored, SandboxState::Running, CleanupState::Pending, None)
                    .await?;
                self.store
                    .finish_operations(id, "create", OperationState::Succeeded, None)
                    .await?;
                return Ok(());
            }
            Some(ObservedState::Starting | ObservedState::Unknown) => {
                self.save(stored,SandboxState::Unknown,CleanupState::Unknown,Some("runtime observation is uncertain; an existing workload will not be recreated".into())).await?;
                return Ok(());
            }
            Some(ObservedState::Running) => {
                stored = self
                    .save(stored, SandboxState::Running, CleanupState::Pending, None)
                    .await?;
            }
            Some(ObservedState::Paused) => {
                stored = self
                    .save(stored, SandboxState::Paused, CleanupState::Pending, None)
                    .await?;
            }
        }
        if stored.ever_running {
            self.store
                .finish_operations(id, "create", OperationState::Succeeded, None)
                .await?;
        }
        let effective = self.store.effective_desired(id).await?;
        if effective == DesiredState::Terminated {
            return self
                .stop(
                    stored,
                    driver,
                    "sandbox deadline or termination requested",
                    ExecutionState::Cancelled,
                )
                .await;
        }
        let handle = stored.handle.clone().ok_or_else(|| {
            ApiError::new(ErrorCode::BackendUnavailable, "runtime handle is absent")
        })?;
        if effective == DesiredState::Paused {
            if stored.sandbox.state != SandboxState::Paused {
                stored = self
                    .save(stored, SandboxState::Pausing, CleanupState::Pending, None)
                    .await?;
                driver.pause(&handle).await?;
                self.save(stored, SandboxState::Paused, CleanupState::Pending, None)
                    .await?;
            }
            if self.store.subtree_settled(id).await? {
                self.store
                    .finish_operations(id, "pause", OperationState::Succeeded, None)
                    .await?;
            }
            return Ok(());
        }
        if stored.sandbox.state == SandboxState::Paused {
            stored = self
                .save(stored, SandboxState::Resuming, CleanupState::Pending, None)
                .await?;
            driver.resume(&handle).await?;
            self.save(stored, SandboxState::Running, CleanupState::Pending, None)
                .await?;
        }
        self.store
            .finish_operations(id, "create", OperationState::Succeeded, None)
            .await?;
        if self.store.subtree_settled(id).await? {
            self.store
                .finish_operations(id, "resume", OperationState::Succeeded, None)
                .await?;
        }
        if !self.sync_contexts(&handle, driver).await? {
            return Ok(());
        }
        for execution in self.store.execution_work(id).await?.into_iter().take(16) {
            if self.store.effective_desired(id).await? != DesiredState::Running {
                break;
            }
            if !self.sync_execution(&handle, driver, execution).await? {
                break;
            }
        }
        Ok(())
    }

    pub(super) async fn stop(
        &self,
        mut stored: StoredSandbox,
        driver: &DockerDriver,
        reason: &str,
        execution_state: ExecutionState,
    ) -> Result<(), ApiError> {
        let id = stored.sandbox.id;
        let expired = expired(&stored.sandbox, Utc::now());
        let failed = stored.sandbox.state == SandboxState::Failed
            || execution_state == ExecutionState::Failed;
        self.stop_network_task(id).await?;
        stored.handle = self.recovered_handle(&stored, driver).await?;
        if !matches!(
            stored.sandbox.state,
            SandboxState::Failed | SandboxState::Terminated
        ) {
            stored = self
                .save(
                    stored,
                    if failed {
                        SandboxState::Failed
                    } else {
                        SandboxState::Stopping
                    },
                    CleanupState::Pending,
                    Some(reason.into()),
                )
                .await?;
        }
        if let Some(handle) = &stored.handle {
            driver.remove(handle).await?;
        }
        stored.handle = None;
        for context in self.store.code_context_work(id).await? {
            if expired || !failed {
                self.store
                    .close_code_context(context.context.id, &format!("source-stop-{id}"))
                    .await?;
            }
            let outcome = if expired {
                CodeRunState::TimedOut
            } else if failed {
                CodeRunState::Unknown
            } else {
                CodeRunState::Cancelled
            };
            self.store
                .finish_code_context_absent_with_state(context.context.id, reason, outcome)
                .await?;
            self.context_closures
                .lock()
                .await
                .remove(&context.context.id);
        }
        for execution in self.store.execution_work(id).await? {
            self.store
                .finish_execution(
                    execution.execution.id,
                    if expired {
                        ExecutionState::TimedOut
                    } else {
                        execution_state
                    },
                    reason,
                )
                .await?;
            self.cancellations
                .lock()
                .await
                .remove(&execution.execution.id);
        }
        if !self.store.children_collected(id).await? {
            self.save(
                stored,
                if failed {
                    SandboxState::Failed
                } else {
                    SandboxState::Stopping
                },
                CleanupState::Pending,
                Some(format!("{reason}; awaiting child collection")),
            )
            .await?;
            return Ok(());
        }
        self.collect_network(&stored).await?;
        self.save(
            stored,
            if failed {
                SandboxState::Failed
            } else {
                SandboxState::Terminated
            },
            CleanupState::Complete,
            Some(reason.into()),
        )
        .await?;
        let error = Some(ApiError::new(ErrorCode::InvalidState, reason));
        for kind in ["create", "pause", "resume"] {
            self.store
                .finish_operations(id, kind, OperationState::Failed, error.clone())
                .await?;
        }
        self.store
            .finish_operations(id, "terminate", OperationState::Succeeded, None)
            .await?;
        Ok(())
    }

    pub(super) async fn record_error(&self, id: Uuid, error: &ApiError) -> Result<(), ApiError> {
        let mut stored = self.store.sandbox(id).await?;
        if stored.sandbox.cleanup == CleanupState::Complete {
            return Ok(());
        }
        if !stored.ever_running
            && matches!(
                error.code,
                ErrorCode::InvalidRequest
                    | ErrorCode::UnsupportedCapability
                    | ErrorCode::NotFound
                    | ErrorCode::QuotaExceeded
            )
        {
            let driver = self
                .drivers
                .get(&stored.sandbox.profile)
                .ok_or_else(|| error.clone())?;
            stored.handle = self.recovered_handle(&stored, driver).await?;
            if let Some(handle) = &stored.handle {
                driver.remove(handle).await?;
            }
            stored.handle = None;
            self.save(
                stored,
                SandboxState::Failed,
                CleanupState::Complete,
                Some(error.message.clone()),
            )
            .await?;
            self.store
                .finish_operations(id, "create", OperationState::Failed, Some(error.clone()))
                .await?;
            self.store
                .finish_operations(id, "terminate", OperationState::Succeeded, None)
                .await?;
        } else {
            let state = if stored.sandbox.state == SandboxState::Failed {
                SandboxState::Failed
            } else {
                SandboxState::Unknown
            };
            self.save(
                stored,
                state,
                CleanupState::Unknown,
                Some(error.message.clone()),
            )
            .await?;
        }
        Ok(())
    }
}
