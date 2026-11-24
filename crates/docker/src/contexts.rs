use super::*;

impl DockerDriver {
    /// Cached observations from completed probes; this performs no new runtime check.
    pub async fn profile_snapshot(&self) -> RuntimeProfile {
        self.profile.read().await.clone()
    }
    /// Explicit optional-feature probe against an administrator-selected cached
    /// workload image. Default worker startup does not invoke this until public
    /// context reconciliation is configured. No runtime/image fallback is used.
    pub async fn probe_code_contexts(&self, image: &str) -> Result<RuntimeProfile, ApiError> {
        let _probe = self.probes.lock().await;
        self.profile
            .write()
            .await
            .capabilities
            .remove(&Capability::CodeContexts);
        let profile = self.profile.read().await.clone();
        if profile.availability != Availability::Available {
            return Err(unavailable(
                "the mandatory runtime probe must pass before the kernel probe",
            ));
        }
        if image.trim().is_empty() || image.len() > 1024 || image.contains('\0') {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "invalid cached kernel-probe image",
            ));
        }
        let mut request = CreateSandbox::new(&profile.id, image);
        request.ttl_seconds = 60;
        let created = Utc::now();
        let sandbox = Sandbox {
            id: Uuid::new_v4(),
            profile: profile.id.clone(),
            image: image.into(),
            state: SandboxState::Starting,
            desired_state: DesiredState::Running,
            cleanup: CleanupState::Pending,
            created_at: created,
            expires_at: created + chrono::Duration::seconds(60),
            observed_at: None,
            resources: request.resources.clone(),
            metadata: Default::default(),
            reason: None,
        };
        let mut handle = None;
        let outcome = tokio::time::timeout(Duration::from_secs(45), async {
            let actual = self.create(&sandbox, &request).await?;
            handle = Some(actual.clone());
            self.kernel_loop(&actual).await
        })
        .await
        .map_err(|_| unavailable("code-context probe timed out"))
        .and_then(|result| result);
        if let Some(handle) = &handle {
            self.remove(handle).await?;
        }
        // Covers a provisioning error after Docker created an owned container but
        // before a handle was returned. Only this fresh sandbox UUID is in scope.
        for owned in self
            .discover()
            .await?
            .into_iter()
            .filter(|owned| owned.sandbox_id == sandbox.id)
        {
            self.remove(&owned).await?;
        }
        if self
            .discover()
            .await?
            .iter()
            .any(|owned| owned.sandbox_id == sandbox.id)
        {
            return Err(unavailable("code-context probe cleanup is unconfirmed"));
        }
        outcome?;
        let mut current = self.profile.write().await;
        if current.availability != Availability::Available {
            return Err(unavailable(
                "runtime availability changed during the kernel probe",
            ));
        }
        current.capabilities.insert(Capability::CodeContexts);
        Ok(current.clone())
    }

    async fn kernel_loop(&self, handle: &RuntimeHandle) -> Result<(), ApiError> {
        let context = Uuid::new_v4();
        let response = self
            .bridge(
                handle,
                &AgentRequest::CodeContextCreate {
                    id: context,
                    spec: CodeContextSpec::default(),
                },
            )
            .await?;
        if !matches!(response, AgentResponse::CodeContext(record) if record.id==context) {
            return Err(unavailable(
                "kernel probe creation returned a different identity",
            ));
        }
        self.wait_kernel_context(handle, context, CodeContextState::Ready)
            .await?;
        let mut cursor = 0;
        let first_spec = CodeRunSpec::new(
            "import os\nassert 20000<=os.getuid()<20004 and os.getgid()==1000 and os.getgroups()==[]\nassert 'CapEff:\\t0000000000000000' in open('/proc/self/status').read()\nprobe_value=globals().get('probe_value',39)+1\nprint('kernel-start')",
        );
        let first = Uuid::new_v4();
        let request = AgentRequest::CodeRunStart {
            context_id: context,
            id: first,
            spec: first_spec,
        };
        self.bridge(handle, &request).await?;
        self.bridge(handle, &request).await?;
        let (first_record, _) = self
            .wait_kernel_run(handle, context, first, &mut cursor)
            .await?;
        if first_record.state != CodeRunState::KernelSucceeded
            || first_record.kernel_status.as_deref() != Some("ok")
        {
            return Err(unavailable("kernel identity/state probe failed"));
        }
        match self.bridge(handle, &request).await? {
            AgentResponse::CodeRun(replay)
                if serde_json::to_value(&replay).ok()
                    == serde_json::to_value(&first_record).ok() => {}
            _ => return Err(unavailable("kernel run replay changed the observed result")),
        }
        let second = Uuid::new_v4();
        self.bridge(
            handle,
            &AgentRequest::CodeRunStart {
                context_id: context,
                id: second,
                spec: CodeRunSpec::new("probe_value+=2\nprint(probe_value)\nprobe_value"),
            },
        )
        .await?;
        let (record, events) = self
            .wait_kernel_run(handle, context, second, &mut cursor)
            .await?;
        let output = events
            .iter()
            .filter(|event| {
                event.run_id == Some(second) && event.kind == CodeContextEventKind::Stdout
            })
            .filter_map(|event| event.data["content"]["text"].as_str())
            .collect::<String>();
        if record.state != CodeRunState::KernelSucceeded
            || output != "42\n"
            || !events.iter().any(|event| {
                event.run_id == Some(second)
                    && event.kind == CodeContextEventKind::Result
                    && event.data["content"]["data"]["text/plain"] == "42"
            })
        {
            return Err(unavailable(
                "kernel retained-state/output/result probe failed",
            ));
        }
        let exception = Uuid::new_v4();
        self.bridge(
            handle,
            &AgentRequest::CodeRunStart {
                context_id: context,
                id: exception,
                spec: CodeRunSpec::new("raise ValueError('expected probe exception')"),
            },
        )
        .await?;
        let (record, _) = self
            .wait_kernel_run(handle, context, exception, &mut cursor)
            .await?;
        if record.state != CodeRunState::KernelFailed
            || record.kernel_status.as_deref() != Some("error")
        {
            return Err(unavailable("kernel exception probe failed"));
        }
        self.bridge(handle, &AgentRequest::CodeContextClose { id: context })
            .await?;
        let closed = self
            .wait_kernel_context(handle, context, CodeContextState::Closed)
            .await?;
        let events = self.kernel_events(handle, context, &mut cursor).await?;
        if !events.iter().any(|event| {
            event.kind == CodeContextEventKind::Closed
                && serde_json::from_value::<CodeContext>(event.data.clone())
                    .ok()
                    .is_some_and(|event| {
                        serde_json::to_value(event).ok() == serde_json::to_value(&closed).ok()
                    })
        }) {
            return Err(unavailable(
                "kernel close lacks a matching collection event",
            ));
        }
        Ok(())
    }

    async fn wait_kernel_context(
        &self,
        handle: &RuntimeHandle,
        id: Uuid,
        target: CodeContextState,
    ) -> Result<CodeContext, ApiError> {
        loop {
            match self
                .bridge(handle, &AgentRequest::CodeContextGet { id })
                .await?
            {
                AgentResponse::CodeContext(record) if record.id == id => {
                    if record.state == target {
                        if target == CodeContextState::Closed
                            && (record.cleanup != CleanupState::Complete
                                || record.finished_at.is_none())
                        {
                            return Err(unavailable("kernel close has unconfirmed collection"));
                        }
                        return Ok(record);
                    }
                    if matches!(
                        record.state,
                        CodeContextState::Closed
                            | CodeContextState::Failed
                            | CodeContextState::Unknown
                    ) {
                        return Err(unavailable(&format!(
                            "kernel context probe failed: state={:?}, cleanup={:?}, reason={}",
                            record.state,
                            record.cleanup,
                            record.reason.as_deref().unwrap_or("not reported")
                        )));
                    }
                }
                _ => {
                    return Err(unavailable(
                        "kernel context probe returned an invalid identity",
                    ));
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn kernel_events(
        &self,
        handle: &RuntimeHandle,
        context: Uuid,
        cursor: &mut u64,
    ) -> Result<Vec<CodeContextEvent>, ApiError> {
        match self
            .bridge(
                handle,
                &AgentRequest::CodeContextEvents {
                    id: context,
                    after: *cursor,
                },
            )
            .await?
        {
            AgentResponse::CodeContextEvents(events) => {
                for event in &events {
                    if event.context_id != context || event.sequence != *cursor + 1 {
                        return Err(unavailable("kernel event identity/cursor is invalid"));
                    }
                    *cursor = event.sequence;
                }
                Ok(events)
            }
            _ => Err(unavailable(
                "kernel event probe returned an unexpected response",
            )),
        }
    }
    async fn wait_kernel_run(
        &self,
        handle: &RuntimeHandle,
        context: Uuid,
        id: Uuid,
        cursor: &mut u64,
    ) -> Result<(CodeRun, Vec<CodeContextEvent>), ApiError> {
        let mut events = Vec::new();
        loop {
            let response = self
                .bridge(
                    handle,
                    &AgentRequest::CodeRunGet {
                        context_id: context,
                        id,
                    },
                )
                .await?;
            events.extend(self.kernel_events(handle, context, cursor).await?);
            if events.len() > 256 {
                return Err(unavailable("kernel probe output exceeds its event budget"));
            }
            match response {
                AgentResponse::CodeRun(record)
                    if record.id == id && record.context_id == context =>
                {
                    if record.finished_at.is_some() {
                        if !events.iter().any(|event| {
                            event.run_id == Some(id)
                                && event.kind == CodeContextEventKind::RunCompleted
                                && serde_json::from_value::<CodeRun>(event.data.clone())
                                    .ok()
                                    .is_some_and(|event| {
                                        serde_json::to_value(event).ok()
                                            == serde_json::to_value(&record).ok()
                                    })
                        }) {
                            return Err(unavailable(
                                "kernel run has no matching completion observation",
                            ));
                        }
                        return Ok((record, events));
                    }
                }
                _ => return Err(unavailable("kernel run probe returned an invalid identity")),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
