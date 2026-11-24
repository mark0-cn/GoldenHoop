use super::*;
use goldenhoop_store::StoredExecution;

impl Worker {
    pub(super) async fn sync_session_controls(
        &self,
        handle: &RuntimeHandle,
        driver: &DockerDriver,
        stored: &StoredExecution,
        actual: &Execution,
    ) -> Result<(), ApiError> {
        let id = stored.execution.id;
        for pending in self.store.session_control_work(id).await? {
            let sequence = pending.request.sequence;
            let receipt = match driver
                .rpc(handle, &AgentRequest::SessionControlStatus { id, sequence })
                .await
            {
                Ok(AgentResponse::SessionControl(receipt)) => receipt,
                Ok(_) => return Err(unexpected()),
                Err(error) if error.code == ErrorCode::NotFound => {
                    let latest = self.store.execution(id).await?;
                    let sandbox = self.store.sandbox(handle.sandbox_id).await?.sandbox;
                    if actual.state != ExecutionState::Running
                        || latest.cancel_requested
                        || sandbox.desired_state != DesiredState::Running
                        || expired(&sandbox, Utc::now())
                    {
                        break;
                    }
                    match driver
                        .rpc(
                            handle,
                            &AgentRequest::SessionControl {
                                id,
                                control: pending.request,
                            },
                        )
                        .await
                    {
                        Ok(AgentResponse::SessionControl(receipt)) => receipt,
                        Ok(_) => return Err(unexpected()),
                        Err(error) if error.code == ErrorCode::InvalidState => break,
                        Err(error)
                            if matches!(
                                error.code,
                                ErrorCode::Conflict
                                    | ErrorCode::InvalidRequest
                                    | ErrorCode::Forbidden
                                    | ErrorCode::QuotaExceeded
                            ) =>
                        {
                            SessionControlReceipt {
                                execution_id: id,
                                sequence,
                                state: SessionControlState::Unknown,
                                observed_at: Utc::now(),
                                error: Some(error),
                            }
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            };
            if receipt.execution_id != id
                || receipt.sequence != sequence
                || receipt.state == SessionControlState::Pending
            {
                return Err(unexpected());
            }
            self.store.observe_session_control(&receipt).await?;
        }
        Ok(())
    }
}
fn unexpected() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "unexpected session control response",
    )
}
