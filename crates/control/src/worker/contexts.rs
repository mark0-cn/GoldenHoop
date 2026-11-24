use super::*;
use goldenhoop_store::StoredCodeContext;

fn unexpected() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "unexpected code-context agent response",
    )
}
fn identity(actual: &CodeContext, stored: &StoredCodeContext) -> Result<(), ApiError> {
    if actual.id != stored.context.id
        || (actual.sandbox_id != Uuid::nil() && actual.sandbox_id != stored.context.sandbox_id)
        || goldenhoop_store::fingerprint(&actual.spec)?
            != goldenhoop_store::fingerprint(&stored.context.spec)?
    {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "agent code-context identity differs",
        ));
    }
    Ok(())
}

impl Worker {
    pub(super) async fn sync_contexts(
        &self,
        handle: &RuntimeHandle,
        driver: &DockerDriver,
    ) -> Result<bool, ApiError> {
        for stored in self.store.code_context_work(handle.sandbox_id).await? {
            if self.store.effective_desired(handle.sandbox_id).await? != DesiredState::Running {
                break;
            }
            if !self.sync_context(handle, driver, stored).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn context_stop(
        &self,
        handle: &RuntimeHandle,
        driver: &DockerDriver,
        reason: &str,
        state: ExecutionState,
    ) -> Result<bool, ApiError> {
        self.stop(
            self.store.sandbox(handle.sandbox_id).await?,
            driver,
            reason,
            state,
        )
        .await?;
        Ok(false)
    }
    async fn sync_context(
        &self,
        handle: &RuntimeHandle,
        driver: &DockerDriver,
        mut stored: StoredCodeContext,
    ) -> Result<bool, ApiError> {
        let id = stored.context.id;
        if stored.context.desired_state == CodeContextDesiredState::Closed {
            let elapsed = self
                .context_closures
                .lock()
                .await
                .entry(id)
                .or_insert_with(Instant::now)
                .elapsed();
            if elapsed > Duration::from_secs(5) {
                return self.context_stop(handle, driver, "context close exceeded its grace period; whole sandbox removal is required", ExecutionState::Cancelled).await;
            }
        }
        if !stored.dispatched {
            if stored.context.desired_state == CodeContextDesiredState::Closed {
                self.store
                    .finish_code_context_absent(id, "context closed before dispatch")
                    .await?;
                self.context_closures.lock().await.remove(&id);
                return Ok(true);
            }
            if !driver
                .profile_snapshot()
                .await
                .capabilities
                .contains(&Capability::CodeContexts)
            {
                self.store.finish_code_context_absent(id, "runtime no longer has verified code-context support; context was not dispatched").await?;
                return Ok(true);
            }
            let dispatch = match self.store.dispatch_code_context(id).await {
                Ok(value) => value,
                Err(error) if error.code == ErrorCode::InvalidState => return Ok(true),
                Err(error) => return Err(error),
            };
            if dispatch {
                let request = AgentRequest::CodeContextCreate {
                    id,
                    spec: stored.context.spec.clone(),
                };
                match driver.rpc_reply(handle, &request).await? {
                    AgentReply::Success(AgentResponse::CodeContext(actual)) => {
                        if identity(&actual, &stored).is_err() {
                            return self
                                .context_stop(
                                    handle,
                                    driver,
                                    "created code-context identity is uncertain",
                                    ExecutionState::Failed,
                                )
                                .await;
                        }
                    }
                    AgentReply::Error(error) if error.code != ErrorCode::Conflict => {
                        let mut reason =
                            format!("agent rejected context creation: {}", error.message);
                        if reason.len() > 4096 {
                            let mut end = 4096;
                            while !reason.is_char_boundary(end) {
                                end -= 1;
                            }
                            reason.truncate(end);
                        }
                        self.store.finish_code_context_absent(id, &reason).await?;
                        return Ok(true);
                    }
                    _ => {
                        return self
                            .context_stop(
                                handle,
                                driver,
                                "context creation returned conflicting identity or content",
                                ExecutionState::Failed,
                            )
                            .await;
                    }
                }
            }
            stored = self.store.code_context(id).await?;
        }
        let actual = match driver
            .rpc_reply(handle, &AgentRequest::CodeContextGet { id })
            .await?
        {
            AgentReply::Success(AgentResponse::CodeContext(actual)) => actual,
            AgentReply::Error(error) if error.code == ErrorCode::NotFound => {
                return self
                    .context_stop(
                        handle,
                        driver,
                        "previously dispatched context is absent; refusing to recreate it",
                        ExecutionState::Failed,
                    )
                    .await;
            }
            AgentReply::Error(error) => return Err(error),
            _ => return Err(unexpected()),
        };
        if identity(&actual, &stored).is_err() {
            return self
                .context_stop(
                    handle,
                    driver,
                    "code-context identity is uncertain",
                    ExecutionState::Failed,
                )
                .await;
        }
        for _ in 0..4 {
            let cursor = self.store.code_context(id).await?.cursor;
            let events = match driver
                .rpc_reply(
                    handle,
                    &AgentRequest::CodeContextEvents { id, after: cursor },
                )
                .await?
            {
                AgentReply::Success(AgentResponse::CodeContextEvents(events)) => events,
                AgentReply::Error(error) if error.code == ErrorCode::NotFound => {
                    return self
                        .context_stop(
                            handle,
                            driver,
                            "code-context event history disappeared",
                            ExecutionState::Failed,
                        )
                        .await;
                }
                AgentReply::Error(error) => return Err(error),
                _ => return Err(unexpected()),
            };
            if self
                .store
                .append_code_context_events(id, &events)
                .await
                .is_err()
            {
                return self
                    .context_stop(
                        handle,
                        driver,
                        "code-context event identity, cursor, result or budget is invalid",
                        ExecutionState::Failed,
                    )
                    .await;
            }
            if events.len() < 256 {
                break;
            }
        }
        let latest = self.store.code_context(id).await?;
        if latest.context.cleanup == CleanupState::Complete {
            self.context_closures.lock().await.remove(&id);
            return Ok(true);
        }
        if actual.cleanup == CleanupState::Unknown || actual.state == CodeContextState::Unknown {
            return self
                .context_stop(
                    handle,
                    driver,
                    "code-context scoped collection is unconfirmed; removing whole sandbox",
                    ExecutionState::Failed,
                )
                .await;
        }
        if latest.context.desired_state == CodeContextDesiredState::Closed {
            self.context_closures
                .lock()
                .await
                .entry(id)
                .or_insert_with(Instant::now);
            match driver
                .rpc_reply(handle, &AgentRequest::CodeContextClose { id })
                .await?
            {
                AgentReply::Success(AgentResponse::CodeContext(record))
                    if record.id == id
                        && matches!(
                            record.state,
                            CodeContextState::Closing
                                | CodeContextState::Closed
                                | CodeContextState::Failed
                        ) => {}
                _ => {
                    return self
                        .context_stop(
                            handle,
                            driver,
                            "context close was not acknowledged",
                            ExecutionState::Cancelled,
                        )
                        .await;
                }
            }
            return Ok(true);
        }
        if actual.state != CodeContextState::Ready {
            return Ok(true);
        }
        for run in self.store.code_run_work(id).await? {
            let current = self.store.code_context(id).await?.context;
            if current.desired_state != CodeContextDesiredState::Open
                || self.store.effective_desired(handle.sandbox_id).await? != DesiredState::Running
            {
                break;
            }
            if !run.dispatched {
                if !driver
                    .profile_snapshot()
                    .await
                    .capabilities
                    .contains(&Capability::CodeContexts)
                {
                    self.store
                        .reject_code_run(
                            run.run.id,
                            &ApiError::new(
                                ErrorCode::UnsupportedCapability,
                                "runtime no longer has verified kernel support",
                            ),
                        )
                        .await?;
                    continue;
                }
                let dispatch = match self.store.dispatch_code_run(run.run.id).await {
                    Ok(value) => value,
                    Err(error) if error.code == ErrorCode::InvalidState => break,
                    Err(error) => return Err(error),
                };
                if !dispatch {
                    continue;
                }
                let request = AgentRequest::CodeRunStart {
                    context_id: id,
                    id: run.run.id,
                    spec: run.spec,
                };
                match driver.rpc_reply(handle, &request).await? {
                    AgentReply::Success(AgentResponse::CodeRun(record))
                        if record.id == run.run.id && record.context_id == id => {}
                    AgentReply::Error(error) if error.code != ErrorCode::Conflict => {
                        self.store.reject_code_run(run.run.id, &error).await?
                    }
                    _ => {
                        return self
                            .context_stop(
                                handle,
                                driver,
                                "code request identity is conflicting; refusing to replay it",
                                ExecutionState::Failed,
                            )
                            .await;
                    }
                }
            } else {
                match driver
                    .rpc_reply(
                        handle,
                        &AgentRequest::CodeRunGet {
                            context_id: id,
                            id: run.run.id,
                        },
                    )
                    .await?
                {
                    AgentReply::Success(AgentResponse::CodeRun(record))
                        if record.id == run.run.id && record.context_id == id => {}
                    AgentReply::Error(error) if error.code == ErrorCode::NotFound => {
                        return self
                            .context_stop(
                                handle,
                                driver,
                                "previously dispatched code run is absent; refusing to resend it",
                                ExecutionState::Failed,
                            )
                            .await;
                    }
                    AgentReply::Error(error) => return Err(error),
                    _ => return Err(unexpected()),
                }
            }
        }
        Ok(true)
    }
}
