use super::*;
use goldenhoop_store::StoredExecution;

fn normalize(mut record: Execution, stored: &StoredExecution) -> Result<Execution, ApiError> {
    if record.id != stored.execution.id
        || (record.sandbox_id != Uuid::nil() && record.sandbox_id != stored.execution.sandbox_id)
    {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "agent returned a different execution identity",
        ));
    }
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
        driver: &DockerDriver,
        stored: StoredExecution,
    ) -> Result<bool, ApiError> {
        let id = stored.execution.id;
        if stored.cancel_requested {
            self.cancellations
                .lock()
                .await
                .entry(id)
                .or_insert_with(Instant::now);
        }
        let mut actual = match driver.rpc(handle, &AgentRequest::Inspect { id }).await {
            Ok(AgentResponse::Execution(record)) => normalize(record, &stored)?,
            Ok(_) => return Err(unexpected()),
            Err(error) if error.code == ErrorCode::NotFound => {
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
                match driver
                    .rpc(
                        handle,
                        &AgentRequest::Start {
                            id,
                            command: stored.spec.clone(),
                        },
                    )
                    .await
                {
                    Ok(AgentResponse::Execution(record)) => normalize(record, &stored)?,
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
            match driver.rpc(handle, &AgentRequest::Cancel { id }).await {
                Ok(AgentResponse::Execution(record)) => actual = normalize(record, &stored)?,
                Ok(_) => return Err(unexpected()),
                Err(error) => {
                    return self.execution_unknown(handle, driver, stored, &error).await;
                }
            }
        }
        let AgentResponse::Events(mut events) = driver
            .rpc(
                handle,
                &AgentRequest::Events {
                    id,
                    after: stored.cursor,
                },
            )
            .await?
        else {
            return Err(unexpected());
        };
        let mut completion = None;
        let mut escalate = false;
        for event in &mut events {
            if event.kind == EventKind::Completed {
                let reported = normalize(
                    serde_json::from_value(event.data.clone()).map_err(|_| unexpected())?,
                    &stored,
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
        driver: &DockerDriver,
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
        driver: &DockerDriver,
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
