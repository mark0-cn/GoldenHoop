//! Deployment availability requires actual protected application and collection.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

fn unknown() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "protected network availability or probe cleanup is unconfirmed",
    )
}

pub(super) async fn pending_heartbeat(
    store: Store,
    mut registration: WorkerRegistration,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ApiError> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        registration.heartbeat = Utc::now();
        store.register_worker(&registration).await?;
        tokio::select! {
            result = shutdown.changed() => { if result.is_err() || *shutdown.borrow() { return Ok(()); } },
            _ = tokio::time::sleep(Duration::from_secs(2)) => {},
        }
    }
}

impl Worker {
    pub(super) async fn probe_network_profiles(
        &self,
        image: &str,
    ) -> Result<Vec<RuntimeProfile>, ApiError> {
        // These durable internal roots are never adopted as user workloads,
        // including after a process dies between dispatch and acknowledgement.
        for old in self.store.network_profile_probes().await? {
            self.collect_probe_root(old.sandbox.id).await?;
            self.store
                .finish_operations(
                    old.sandbox.id,
                    "network_profile_probe",
                    OperationState::Failed,
                    Some(unknown()),
                )
                .await?;
        }
        let mut profiles = self.registration.profiles.clone();
        for profile in &mut profiles {
            if profile.availability != Availability::Available {
                continue;
            }
            let limits = ResourceLimits {
                cpu_millis: 500,
                memory_bytes: 256 * 1024 * 1024,
                pids: 64,
            };
            let mut request = CreateSandbox::new(&profile.id, image);
            request.resources = limits.clone();
            request.ttl_seconds = 300;
            if profile.capabilities.contains(&Capability::IsolatedSessions) {
                request.child_budget = Some(limits.clone());
            }
            let created = match self
                .store
                .create_network_profile_probe(profile, &request, &Uuid::new_v4().to_string())
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    report("network_profile_probe_admission_failed", &error);
                    profile.availability = Availability::Unavailable;
                    profile.capabilities.remove(&Capability::NetworkPolicy);
                    profile.reason =
                        Some("protected network probe could not reserve its resources".into());
                    continue;
                }
            };
            let root = created.sandbox.id;
            self.store
                .finish_operations(root, "network_profile_probe", OperationState::Running, None)
                .await?;
            let result = Box::pin(self.probe_network_tree(profile, root, &limits)).await;
            // A failed feature check is an unavailable profile. Unconfirmed
            // collection is a failed startup, never a successful probe.
            self.collect_probe_root(root).await?;
            self.store
                .finish_operations(
                    root,
                    "network_profile_probe",
                    if result.is_ok() {
                        OperationState::Succeeded
                    } else {
                        OperationState::Failed
                    },
                    result.as_ref().err().cloned(),
                )
                .await?;
            if let Err(error) = result {
                report("network_profile_probe_failed", &error);
                profile.availability = Availability::Unavailable;
                profile.capabilities.remove(&Capability::NetworkPolicy);
                profile.reason =
                    Some("actual protected network application failed; no runtime fallback".into());
            }
            println!(
                "{}",
                serde_json::json!({"event":"network_profile_probe_collected","profile":profile.id,"sandbox_id":root,"available":profile.availability==Availability::Available})
            );
        }
        Ok(profiles)
    }

    async fn wait_probe_ready(&self, ids: &[Uuid]) -> Result<(), ApiError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        loop {
            let mut ready = true;
            for id in ids {
                Box::pin(self.reconcile(*id)).await?;
                let stored = self.store.sandbox(*id).await?;
                if matches!(
                    stored.sandbox.state,
                    SandboxState::Failed | SandboxState::Terminated
                ) {
                    return Err(unknown());
                }
                ready &= stored.sandbox.state == SandboxState::Running
                    && self.require_network_dispatch(*id).await.is_ok();
            }
            if ready {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(unknown());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn probe_command(&self, id: Uuid) -> Result<(), ApiError> {
        let spec: CommandSpec = serde_json::from_value(serde_json::json!({
            "argv":["/bin/sh","-c","printf goldenhoop_network_profile_probe"],"timeout_seconds":10
        }))
        .map_err(|_| unknown())?;
        let execution = self
            .store
            .create_execution(id, &spec, &Uuid::new_v4().to_string())
            .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        loop {
            Box::pin(self.reconcile(id)).await?;
            let current = self.store.execution(execution.id).await?.execution;
            if current.state.is_terminal() {
                if current.state != ExecutionState::Succeeded || current.exit_code != Some(0) {
                    return Err(unknown());
                }
                let mut stdout = Vec::new();
                let mut completed = 0;
                for event in self.store.events(execution.id, 0).await? {
                    if event.kind == EventKind::Stdout {
                        stdout.extend(
                            STANDARD
                                .decode(event.data["data"].as_str().ok_or_else(unknown)?)
                                .map_err(|_| unknown())?,
                        );
                    }
                    if event.kind == EventKind::Completed {
                        completed += 1;
                    }
                }
                if stdout != b"goldenhoop_network_profile_probe" || completed != 1 {
                    return Err(unknown());
                }
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(unknown());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn probe_network_tree(
        &self,
        profile: &RuntimeProfile,
        root: Uuid,
        limits: &ResourceLimits,
    ) -> Result<(), ApiError> {
        self.wait_probe_ready(&[root]).await?;
        let mut ids = vec![root];
        if profile.capabilities.contains(&Capability::IsolatedSessions) {
            let child = self
                .store
                .create_isolated_session(
                    profile,
                    root,
                    &CreateIsolatedSession {
                        resources: limits.clone(),
                        network: Some(NetworkPolicy {
                            default_action: NetworkAction::Deny,
                            rules: vec![NetworkRule {
                                destination: "93.184.216.34".into(),
                                ports: vec![443],
                                action: NetworkAction::Allow,
                            }],
                        }),
                        ..Default::default()
                    },
                    &Uuid::new_v4().to_string(),
                )
                .await?;
            ids.push(child.sandbox.id);
            self.wait_probe_ready(&ids).await?;
        }
        let mut original = Vec::new();
        for id in &ids {
            original.push(
                self.store
                    .sandbox(*id)
                    .await?
                    .handle
                    .ok_or_else(unknown)?
                    .backend_ref,
            );
            self.probe_command(*id).await?;
        }
        for (expected, action) in [(0, NetworkAction::Allow), (1, NetworkAction::Deny)] {
            let changed = self
                .store
                .set_public_network_policy(
                    root,
                    &SetNetworkPolicy {
                        expected_revision: expected,
                        policy: NetworkPolicy {
                            default_action: action,
                            rules: vec![],
                        },
                    },
                    &Uuid::new_v4().to_string(),
                )
                .await?;
            self.wait_probe_ready(&ids).await?;
            self.store.settle_network_policy_changes().await?;
            if self.store.operation(changed.operation.id).await?.state != OperationState::Succeeded
            {
                return Err(unknown());
            }
            for (id, physical) in ids.iter().zip(&original) {
                let policy = self.store.network_policy(*id).await?;
                if policy
                    .public_inputs
                    .as_ref()
                    .and_then(|p| p.lineage.first())
                    .map(|s| (s.sandbox_id, s.revision))
                    != Some((root, expected + 1))
                    || self
                        .store
                        .sandbox(*id)
                        .await?
                        .handle
                        .as_ref()
                        .map(|h| &h.backend_ref)
                        != Some(physical)
                {
                    return Err(unknown());
                }
                self.probe_command(*id).await?;
            }
        }
        Ok(())
    }

    async fn collect_probe_root(&self, root: Uuid) -> Result<(), ApiError> {
        self.store
            .set_desired(
                root,
                DesiredState::Terminated,
                &format!("network-probe-close-{root}"),
            )
            .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(100);
        loop {
            let mut members = Vec::new();
            for stored in self.store.work().await? {
                let scope = self.store.sandbox_scope(stored.sandbox.id).await?;
                if scope.root_id == root {
                    members.push((scope.depth, stored.sandbox.id));
                }
            }
            members.sort_by_key(|(depth, _)| std::cmp::Reverse(*depth));
            for (_, id) in members {
                Box::pin(self.reconcile(id)).await?;
            }
            if self.store.sandbox(root).await?.sandbox.cleanup == CleanupState::Complete {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(unknown());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}
