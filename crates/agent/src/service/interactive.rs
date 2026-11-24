use super::*;
use goldenhoop_core::{MAX_SESSION_TOTAL_INPUT_BYTES, validate_session_control};
use sha2::{Digest, Sha256};
use terminal::Pty;

pub(super) enum InputSink {
    Pipe(Option<tokio::process::ChildStdin>),
    Terminal(Pty),
}

#[derive(Default)]
pub(super) struct SessionInput {
    pub sink: Option<InputSink>,
    receipts: Vec<(String, SessionControlReceipt)>,
    used_bytes: usize,
    poisoned: bool,
}

impl Agent {
    pub(super) async fn control(
        &self,
        id: Uuid,
        control: SessionControl,
    ) -> Result<AgentResponse, ApiError> {
        let input_bytes = validate_session_control(&control)?;
        let digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&control).map_err(internal)?)
        );
        let job = self.job(id).await?;
        let controls = job.input.as_ref().ok_or_else(|| {
            ApiError::new(
                ErrorCode::InvalidState,
                "execution has no interactive input",
            )
        })?;
        let mut input = controls.lock().await;
        let index = (control.sequence - 1) as usize;
        if let Some((previous, receipt)) = input.receipts.get(index) {
            if previous != &digest {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "session control sequence has different content",
                ));
            }
            return Ok(AgentResponse::SessionControl(receipt.clone()));
        }
        if index != input.receipts.len() {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "session control sequence has a gap",
            ));
        }
        if job.record.lock().await.state != ExecutionState::Running || input.sink.is_none() {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "session is not accepting controls",
            ));
        }
        if input.used_bytes + input_bytes > MAX_SESSION_TOTAL_INPUT_BYTES {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "session input budget exceeds 1 MiB",
            ));
        }
        input.used_bytes += input_bytes;
        // Reserve identity before I/O. A timed-out/partial write is never retried.
        let mut receipt = SessionControlReceipt {
            execution_id: id,
            sequence: control.sequence,
            state: SessionControlState::Unknown,
            observed_at: Utc::now(),
            error: None,
        };
        input.receipts.push((digest, receipt.clone()));
        let applied = apply(&mut input, &control.action).await;
        match applied {
            Ok(()) => receipt.state = SessionControlState::Applied,
            Err((state, error)) => {
                receipt.state = state;
                receipt.error = Some(error);
            }
        }
        receipt.observed_at = Utc::now();
        input.receipts[index].1 = receipt.clone();
        Ok(AgentResponse::SessionControl(receipt))
    }

    pub(super) async fn control_status(
        &self,
        id: Uuid,
        sequence: u64,
    ) -> Result<AgentResponse, ApiError> {
        let job = self.job(id).await?;
        let input = job
            .input
            .as_ref()
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::InvalidState,
                    "execution has no interactive input",
                )
            })?
            .lock()
            .await;
        let receipt = sequence
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| input.receipts.get(index))
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "session control not found"))?;
        Ok(AgentResponse::SessionControl(receipt.1.clone()))
    }

    pub(super) async fn read_terminal(&self, job: &Job, pty: Pty, limit: u64) {
        let mut bytes = [0; 8192];
        loop {
            match pty.read(&mut bytes).await {
                Ok(0) => break,
                Ok(count) => {
                    self.output(job, EventKind::Stdout, &bytes[..count], limit)
                        .await
                }
                Err(_) => {
                    job.truncated.store(true, Ordering::Relaxed);
                    self.push(
                        job,
                        EventKind::Diagnostic,
                        json!({"reason":"terminal_read_error"}),
                    )
                    .await;
                    break;
                }
            }
        }
    }
}

async fn apply(
    input: &mut SessionInput,
    action: &SessionAction,
) -> Result<(), (SessionControlState, ApiError)> {
    let rejected = |message| {
        (
            SessionControlState::Rejected,
            ApiError::new(ErrorCode::UnsupportedCapability, message),
        )
    };
    match action {
        SessionAction::Write { data_base64 } => {
            if input.poisoned {
                return Err((
                    SessionControlState::Rejected,
                    ApiError::new(
                        ErrorCode::InvalidState,
                        "earlier input delivery was uncertain; further writes are refused",
                    ),
                ));
            }
            let bytes = STANDARD
                .decode(data_base64)
                .expect("validated session input");
            let write = async {
                match input.sink.as_mut().expect("active input") {
                    InputSink::Pipe(Some(pipe)) => pipe.write_all(&bytes).await,
                    InputSink::Pipe(None) => Err(std::io::ErrorKind::BrokenPipe.into()),
                    InputSink::Terminal(pty) => pty.write_all(&bytes).await,
                }
            };
            if !matches!(
                tokio::time::timeout(Duration::from_secs(5), write).await,
                Ok(Ok(()))
            ) {
                input.poisoned = true;
                return Err((
                    SessionControlState::Unknown,
                    ApiError::new(
                        ErrorCode::BackendUnavailable,
                        "session input delivery is uncertain; it will not be retried",
                    ),
                ));
            }
            Ok(())
        }
        SessionAction::CloseInput => match input.sink.as_mut().expect("active input") {
            InputSink::Pipe(pipe) => {
                pipe.take();
                Ok(())
            }
            InputSink::Terminal(_) => Err(rejected(
                "a PTY cannot half-close input; send terminal input or cancel the session",
            )),
        },
        SessionAction::Resize { size } => match input.sink.as_ref().expect("active input") {
            InputSink::Pipe(_) => Err(rejected("pipe sessions have no terminal size")),
            InputSink::Terminal(pty) => pty.resize(*size).map_err(|_| {
                (
                    SessionControlState::Unknown,
                    ApiError::new(
                        ErrorCode::BackendUnavailable,
                        "terminal resize could not be confirmed",
                    ),
                )
            }),
        },
    }
}
