use super::*;
use goldenhoop_store::{RestoredExecutionBinding, StoredExecution};

pub(super) fn normalize(
    mut record: Execution,
    stored: &StoredExecution,
    binding: Option<&RestoredExecutionBinding>,
) -> Result<Execution, ApiError> {
    let agent_id = binding.map_or(stored.execution.id, |b| b.agent_id);
    let agent_sandbox = binding.map_or(stored.execution.sandbox_id, |b| b.agent_sandbox_id);
    if record.id != agent_id
        || (record.sandbox_id != Uuid::nil() && record.sandbox_id != agent_sandbox)
        || binding.is_some_and(|b| {
            b.target_id != stored.execution.sandbox_id
                || record.started_at != stored.execution.started_at
                || record.started_at.is_none()
                || record.state == ExecutionState::Pending
        })
    {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "agent returned a different execution identity",
        ));
    }
    record.id = stored.execution.id;
    record.sandbox_id = stored.execution.sandbox_id;
    record.created_at = stored.execution.created_at;
    Ok(record)
}
fn unexpected() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "unexpected execution-agent response",
    )
}

impl Worker {
    pub(super) async fn sync_execution(
        &self,
        handle: &RuntimeHandle,
        driver: &dyn WorkerDriver,
        stored: StoredExecution,
    ) -> Result<bool, ApiError> {
        let id = stored.execution.id;
        let binding = self.store.restored_execution_binding(id).await?;
        if binding
            .as_ref()
            .is_some_and(|b| b.target_id != handle.sandbox_id)
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "retained execution belongs to a different target generation",
            ));
        }
        let agent_id = binding.as_ref().map_or(id, |b| b.agent_id);
        let offset = binding.as_ref().map_or(0, |b| b.event_offset);
        let session = self.store.session_spec(id).await?;
        if stored.cancel_requested {
            self.cancellations
                .lock()
                .await
                .entry(id)
                .or_insert_with(Instant::now);
        }
        let mut actual = match self
            .rpc(driver, handle, &AgentRequest::Inspect { id: agent_id })
            .await
        {
            Ok(AgentResponse::Execution(record)) => normalize(record, &stored, binding.as_ref())?,
            Ok(_) => return Err(unexpected()),
            Err(error) if error.code == ErrorCode::NotFound => {
                if binding.is_some() {
                    self.stop(
                        self.store.sandbox(handle.sandbox_id).await?,
                        driver,
                        "retained snapshot execution is absent; refusing to replay Start",
                        ExecutionState::Failed,
                    )
                    .await?;
                    return Ok(false);
                }
                if session.is_some() && stored.execution.started_at.is_some() {
                    self.stop(
                        self.store.sandbox(handle.sandbox_id).await?,
                        driver,
                        "previously started session is absent from its agent; refusing to rerun it",
                        ExecutionState::Failed,
                    )
                    .await?;
                    return Ok(false);
                }
                if driver.inspect(handle).await?.state != ObservedState::Running {
                    let sandbox = self.store.sandbox(handle.sandbox_id).await?;
                    self.stop(
                        sandbox,
                        driver,
                        "runtime was lost while locating an execution",
                        ExecutionState::Failed,
                    )
                    .await?;
                    return Ok(false);
                }
                if stored.cancel_requested {
                    self.store
                        .finish_execution(
                            id,
                            ExecutionState::Cancelled,
                            "cancelled before agent launch",
                        )
                        .await?;
                    self.cancellations.lock().await.remove(&id);
                    return Ok(true);
                }
                let feature = if session.is_some() {
                    Capability::ShellSessions
                } else {
                    Capability::Commands
                };
                if let Err(error) = self.store.authorize_work(handle.sandbox_id, feature).await {
                    if error.code == ErrorCode::InvalidState {
                        return Ok(false);
                    }
                    return Err(error);
                }
                let start = if let Some(session) = &session {
                    if session.terminal.is_some() {
                        self.store
                            .authorize_feature(handle.sandbox_id, Capability::Pty)
                            .await?;
                    }
                    AgentRequest::StartSession {
                        id,
                        session: session.clone(),
                    }
                } else {
                    AgentRequest::Start {
                        id,
                        command: stored.spec.clone(),
                    }
                };
                match self.rpc(driver, handle, &start).await {
                    Ok(AgentResponse::Execution(record)) => {
                        normalize(record, &stored, binding.as_ref())?
                    }
                    Ok(_) => return Err(unexpected()),
                    Err(error)
                        if matches!(
                            error.code,
                            ErrorCode::InvalidRequest
                                | ErrorCode::Forbidden
                                | ErrorCode::QuotaExceeded
                                | ErrorCode::NotFound
                        ) =>
                    {
                        if driver.inspect(handle).await?.state != ObservedState::Running {
                            self.stop(
                                self.store.sandbox(handle.sandbox_id).await?,
                                driver,
                                "runtime disappeared before command launch",
                                ExecutionState::Failed,
                            )
                            .await?;
                            return Ok(false);
                        }
                        self.store
                            .finish_execution(id, ExecutionState::Failed, &error.message)
                            .await?;
                        return Ok(true);
                    }
                    Err(error) => {
                        return self.execution_unknown(handle, driver, stored, &error).await;
                    }
                }
            }
            Err(error) => {
                return self.execution_unknown(handle, driver, stored, &error).await;
            }
        };
        if stored.cancel_requested && !actual.state.is_terminal() {
            match self
                .rpc(driver, handle, &AgentRequest::Cancel { id: agent_id })
                .await
            {
                Ok(AgentResponse::Execution(record)) => {
                    actual = normalize(record, &stored, binding.as_ref())?
                }
                Ok(_) => return Err(unexpected()),
                Err(error) => {
                    return self.execution_unknown(handle, driver, stored, &error).await;
                }
            }
        }
        if session.is_some()
            && let Err(error) = self
                .sync_session_controls(handle, driver, &stored, &actual)
                .await
        {
            if actual.state.is_terminal() {
                report("terminal_session_input_unconfirmed", &error);
            } else {
                return self.execution_unknown(handle, driver, stored, &error).await;
            }
        }
        let AgentResponse::Events(mut events) = self
            .rpc(
                driver,
                handle,
                &AgentRequest::Events {
                    id: agent_id,
                    after: stored
                        .cursor
                        .checked_add(offset)
                        .filter(|n| *n <= i64::MAX as u64)
                        .ok_or_else(|| {
                            ApiError::new(
                                ErrorCode::Conflict,
                                "retained execution event cursor overflows",
                            )
                        })?,
                },
            )
            .await?
        else {
            return Err(unexpected());
        };
        let mut completion = None;
        let mut escalate = false;
        for event in &mut events {
            if event.execution_id != agent_id || event.sequence <= offset {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "retained execution event identity or cursor differs",
                ));
            }
            event.execution_id = id;
            event.sequence -= offset;
            if event.kind == EventKind::Completed {
                let reported = normalize(
                    serde_json::from_value(event.data.clone()).map_err(|_| unexpected())?,
                    &stored,
                    binding.as_ref(),
                )?;
                if !reported.state.is_terminal() || reported.cleanup != CleanupState::Complete {
                    event.kind = EventKind::Diagnostic;
                    event.data = serde_json::json!({"reason":"agent_cleanup_unconfirmed","reported_result":reported});
                    escalate = true;
                } else {
                    event.data = serde_json::to_value(&reported).map_err(|_| unexpected())?;
                    completion = Some(reported);
                }
            }
        }
        let terminated = actual.state.is_terminal() && actual.cleanup == CleanupState::Complete;
        let mut record = completion.clone().unwrap_or(actual);
        if record.state.is_terminal() && completion.is_none() {
            // The terminal event may be in a later output batch. Do not publish a
            // terminal API result until that event is durably collected.
            record.state = if record.started_at.is_some() {
                ExecutionState::Running
            } else {
                ExecutionState::Pending
            };
            record.exit_code = None;
            record.finished_at = None;
            record.cleanup = if record.started_at.is_some() {
                CleanupState::Pending
            } else {
                CleanupState::NotRequired
            };
        }
        if escalate {
            record.state = ExecutionState::Unknown;
            record.cleanup = CleanupState::Unknown;
            record.finished_at = None;
        }
        self.store.persist_execution(&record, &events).await?;
        if escalate {
            self.stop(
                self.store.sandbox(handle.sandbox_id).await?,
                driver,
                "worker terminated the whole sandbox after unconfirmed descendant cleanup",
                ExecutionState::Failed,
            )
            .await?;
            return Ok(false);
        }
        if record.state.is_terminal() {
            self.cancellations.lock().await.remove(&id);
        } else if stored.cancel_requested && !terminated && self.cancel_overdue(id).await {
            return self.escalate_cancel(handle, driver, id).await;
        }
        Ok(true)
    }

    async fn execution_unknown(
        &self,
        handle: &RuntimeHandle,
        driver: &dyn WorkerDriver,
        stored: StoredExecution,
        error: &ApiError,
    ) -> Result<bool, ApiError> {
        let id = stored.execution.id;
        let cancel = stored.cancel_requested;
        let mut record = stored.execution;
        if record.state.is_terminal() {
            return Ok(true);
        }
        record.state = ExecutionState::Unknown;
        record.cleanup = CleanupState::Unknown;
        record.reason = Some(error.message.clone());
        record.finished_at = None;
        self.store.persist_execution(&record, &[]).await?;
        if cancel && self.cancel_overdue(id).await {
            return self.escalate_cancel(handle, driver, id).await;
        }
        Ok(true)
    }

    async fn cancel_overdue(&self, id: Uuid) -> bool {
        self.cancellations
            .lock()
            .await
            .get(&id)
            .is_some_and(|start| start.elapsed() >= Duration::from_secs(5))
    }

    async fn escalate_cancel(
        &self,
        handle: &RuntimeHandle,
        driver: &dyn WorkerDriver,
        id: Uuid,
    ) -> Result<bool, ApiError> {
        self.store
            .set_desired(
                handle.sandbox_id,
                DesiredState::Terminated,
                &format!("cancel-escalation-{id}"),
            )
            .await?;
        self.stop(
            self.store.sandbox(handle.sandbox_id).await?,
            driver,
            "whole sandbox terminated because command cancellation could not be confirmed",
            ExecutionState::Cancelled,
        )
        .await?;
        Ok(false)
    }
}
