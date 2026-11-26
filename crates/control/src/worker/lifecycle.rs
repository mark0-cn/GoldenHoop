use super::*;

impl Worker {
    pub(super) fn runtime_request(
        &self,
        stored: &StoredSandbox,
    ) -> Result<CreateSandbox, ApiError> {
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
        project_runtime_request(profile, &stored.request)
    }
    pub(super) async fn recovered_handle(
        &self,
        stored: &StoredSandbox,
        driver: &dyn WorkerDriver,
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
            Err(error) if error.code == ErrorCode::NotFound => {
                if self.network_options.is_some()
                    && driver.protected_docker().is_ok()
                    && !stored.ever_running
                    && stored.sandbox.desired_state == DesiredState::Running
                    && !matches!(
                        stored.sandbox.state,
                        SandboxState::Failed | SandboxState::Terminated
                    )
                {
                    if stored.sandbox.state != SandboxState::Pending {
                        return self.stop(stored, driver.as_ref(), "uncertain protected bootstrap has no allocation; refusing none-network creation", ExecutionState::Failed).await;
                    }
                    let profile = self
                        .registration
                        .profiles
                        .iter()
                        .find(|p| p.id == stored.sandbox.profile)
                        .ok_or_else(|| {
                            ApiError::new(
                                ErrorCode::UnsupportedCapability,
                                "protected runtime profile is absent",
                            )
                        })?;
                    require_capability(profile, Capability::NetworkPolicy)?;
                    Box::pin(self.bootstrap_network(stored, driver.as_ref())).await?;
                    return self
                        .reconcile_network(self.store.sandbox(id).await?, driver)
                        .await;
                }
            }
            Err(error) => return Err(error),
        }
        let driver = self
            .drivers
            .get(&stored.sandbox.profile)
            .map(Arc::as_ref)
            .ok_or_else(|| {
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
        driver: &dyn WorkerDriver,
        reason: &str,
        execution_state: ExecutionState,
    ) -> Result<(), ApiError> {
        let id = stored.sandbox.id;
        // Expiry or ancestor closure can become effective after reconcile's
        // first intent check. Persist it before collection: observations retain
        // desired state, and a completely collected node can leave the work scan.
        if stored.sandbox.desired_state != DesiredState::Terminated
            && self.store.effective_desired(id).await? == DesiredState::Terminated
        {
            self.store
                .set_desired(id, DesiredState::Terminated, &format!("tree-close-{id}"))
                .await?;
            stored = self.store.sandbox(id).await?;
        }
        let expired = expired(&stored.sandbox, Utc::now());
        let failed = stored.sandbox.state == SandboxState::Failed
            || execution_state == ExecutionState::Failed;
        self.stop_network_task(id).await?;
        stored.handle = self.recovered_handle(&stored, driver).await?;
        self.settle_create_dispatches(&stored, driver).await?;
        self.store.require_network_creates_settled(id).await?;
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
        // Whole-runtime context completion must follow the durable source
        // cleanup observation. A crash here remains in Store::work while any
        // context is unsettled, even though the source is already collected.
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
        if !stored.ever_running {
            match self.store.network_allocation(id).await {
                Ok(_) => {
                    let driver = self
                        .drivers
                        .get(&stored.sandbox.profile)
                        .map(Arc::as_ref)
                        .ok_or_else(|| error.clone())?;
                    // An interrupted create is already being collected when
                    // termination is effective. A temporary absence-check
                    // failure must not turn that cancellation into a failed
                    // creation. stop() retains any previously observed Failed
                    // state and still requires actual resource collection.
                    let outcome =
                        if self.store.effective_desired(id).await? == DesiredState::Terminated {
                            ExecutionState::Cancelled
                        } else {
                            ExecutionState::Failed
                        };
                    return self.stop(stored, driver, &error.message, outcome).await;
                }
                Err(error) if error.code == ErrorCode::NotFound => {}
                Err(error) => return Err(error),
            }
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
                .map(Arc::as_ref)
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

fn project_runtime_request(
    profile: &RuntimeProfile,
    request: &CreateSandbox,
) -> Result<CreateSandbox, ApiError> {
    goldenhoop_core::validate_create(profile, request)?;
    let mut native = request.clone();
    // Artifact retention is implemented by the probed host storage worker.
    // Its availability is checked above; the native driver owns file capture.
    native.required_capabilities.remove(&Capability::Artifacts);
    // The verified protected host broker supplies credentials. Docker owns
    // the workload, not this composed capability; admission was checked above.
    native
        .required_capabilities
        .remove(&Capability::SecretInjection);
    // Hierarchy allocation and feature ceilings are enforced by the host.
    // The native runtime receives only this node's workload hard limits.
    native
        .required_capabilities
        .remove(&Capability::IsolatedSessions);
    native.child_budget = None;
    native.feature_limit = None;
    Ok(native)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_credential_capability_is_checked_before_runtime_projection() {
        // Synthetic registration tests projection only, never native support.
        let mut profile = RuntimeProfile {
            id: "projection-fixture".into(),
            placement: Placement::Local,
            isolation: Isolation::Oci,
            availability: Availability::Available,
            capabilities: [
                Capability::Commands,
                Capability::NetworkIsolation,
                Capability::NetworkPolicy,
                Capability::SecretInjection,
                Capability::Artifacts,
                Capability::IsolatedSessions,
            ]
            .into(),
            code_languages: Default::default(),
            max_resources: ResourceLimits::default(),
            max_ttl_seconds: 86400,
            reason: None,
        };
        let mut request = CreateSandbox::new(&profile.id, "projection-fixture:test");
        request.required_capabilities = [
            Capability::Commands,
            Capability::NetworkPolicy,
            Capability::SecretInjection,
            Capability::Artifacts,
            Capability::IsolatedSessions,
        ]
        .into();
        request.network.rules.push(NetworkRule {
            destination: "192.0.2.10".into(),
            ports: vec![443],
            action: NetworkAction::Allow,
        });
        let original = serde_json::to_value(&request).unwrap();
        let native = project_runtime_request(&profile, &request).unwrap();
        assert_eq!(
            native.required_capabilities,
            [Capability::Commands, Capability::NetworkPolicy].into()
        );
        assert_eq!(native.network, request.network);
        assert_eq!(native.resources, request.resources);
        assert_eq!(serde_json::to_value(&request).unwrap(), original);

        profile.capabilities.remove(&Capability::SecretInjection);
        assert_eq!(
            project_runtime_request(&profile, &request)
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedCapability
        );
        profile.capabilities.insert(Capability::SecretInjection);
        request.feature_limit = Some(
            profile
                .capabilities
                .iter()
                .copied()
                .filter(|cap| *cap != Capability::SecretInjection)
                .collect(),
        );
        assert_eq!(
            project_runtime_request(&profile, &request)
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        request.feature_limit = None;
        request
            .required_capabilities
            .insert(Capability::MemorySnapshot);
        assert_eq!(
            project_runtime_request(&profile, &request)
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedCapability
        );
        request
            .required_capabilities
            .remove(&Capability::MemorySnapshot);
        profile.availability = Availability::Unavailable;
        assert_eq!(
            project_runtime_request(&profile, &request)
                .unwrap_err()
                .code,
            ErrorCode::BackendUnavailable
        );
    }
}
