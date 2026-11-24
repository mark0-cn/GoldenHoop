use goldenhoop_core::{validate_code_context, validate_code_run};
use goldenhoop_jupyter::peer::{Channel, Observation, Peer};
use std::collections::{HashMap, VecDeque};
use tokio::{process::Child, sync::mpsc, time::Instant};
use tokio_util::sync::CancellationToken;

use super::*;
mod kernel;

pub(super) struct Contexts {
    items: Mutex<HashMap<Uuid, Arc<Context>>>,
    slots: Mutex<[Option<Uuid>; 4]>,
    private: tempfile::TempDir,
    runs: AtomicUsize,
}
impl Contexts {
    pub(super) fn new() -> std::io::Result<Self> {
        let private = tempfile::Builder::new()
            .prefix("ghctx-")
            .tempdir_in("/tmp")?;
        // Traversal is allowed, but workloads cannot list or rename children.
        std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o711))?;
        Ok(Self {
            items: Mutex::new(HashMap::new()),
            slots: Mutex::new([None; 4]),
            private,
            runs: AtomicUsize::new(0),
        })
    }
}
struct ContextEvents {
    next: u64,
    items: VecDeque<(CodeContextEvent, usize)>,
}
pub(super) struct Context {
    id: Uuid,
    uid: u32,
    spec: Vec<u8>,
    pub(super) record: Mutex<CodeContext>,
    jobs: Mutex<HashMap<Uuid, Arc<CodeJob>>>,
    input: mpsc::Sender<Arc<CodeJob>>,
    close: CancellationToken,
    events: Mutex<ContextEvents>,
    background_bytes: AtomicU64,
    background_truncated: AtomicBool,
}
pub(super) struct CodeJob {
    spec: CodeRunSpec,
    encoded_spec: Vec<u8>,
    pub(super) record: Mutex<CodeRun>,
    output_bytes: AtomicU64,
    truncated: AtomicBool,
}

impl Agent {
    pub(super) async fn context(&self, id: Uuid) -> Result<Arc<Context>, ApiError> {
        self.contexts
            .items
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "code context not found"))
    }
    pub(super) async fn code_job(&self, context: Uuid, id: Uuid) -> Result<Arc<CodeJob>, ApiError> {
        self.context(context)
            .await?
            .jobs
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "code run not found"))
    }
    pub(super) async fn create_context(
        self: &Arc<Self>,
        id: Uuid,
        spec: CodeContextSpec,
    ) -> Result<AgentResponse, ApiError> {
        validate_code_context(&spec)?;
        if id.is_nil() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "context UUID must not be nil",
            ));
        }
        self.workspace.cwd_handle(&spec.cwd)?;
        let encoded = serde_json::to_vec(&spec).map_err(internal)?;
        let mut items = self.contexts.items.lock().await;
        if let Some(context) = items.get(&id) {
            if context.spec != encoded {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "context ID has different content",
                ));
            }
            return Ok(AgentResponse::CodeContext(
                context.record.lock().await.clone(),
            ));
        }
        if items.len() >= 16 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "context history limit reached",
            ));
        }
        let mut slots = self.contexts.slots.lock().await;
        let slot = slots.iter().position(Option::is_none).ok_or_else(|| {
            ApiError::new(
                ErrorCode::QuotaExceeded,
                "all four context identities remain reserved",
            )
        })?;
        slots[slot] = Some(id);
        drop(slots);
        let record = CodeContext {
            id,
            sandbox_id: Uuid::nil(),
            spec,
            state: CodeContextState::Starting,
            desired_state: CodeContextDesiredState::Open,
            cleanup: CleanupState::Pending,
            created_at: Utc::now(),
            ready_at: None,
            finished_at: None,
            kernel_info: None,
            reason: None,
        };
        let (input, receive) = mpsc::channel(8);
        let context = Arc::new(Context {
            id,
            uid: 20000 + slot as u32,
            spec: encoded,
            record: Mutex::new(record.clone()),
            jobs: Mutex::new(HashMap::new()),
            input,
            close: CancellationToken::new(),
            events: Mutex::new(ContextEvents {
                next: 1,
                items: VecDeque::new(),
            }),
            background_bytes: AtomicU64::new(0),
            background_truncated: AtomicBool::new(false),
        });
        items.insert(id, context.clone());
        let agent = self.clone();
        tokio::spawn(async move {
            agent.run_context(context, receive).await;
        });
        Ok(AgentResponse::CodeContext(record))
    }
    pub(super) async fn close_context(
        &self,
        id: Uuid,
        reason: &str,
    ) -> Result<AgentResponse, ApiError> {
        let context = self.context(id).await?;
        let mut record = context.record.lock().await;
        record.desired_state = CodeContextDesiredState::Closed;
        if matches!(
            record.state,
            CodeContextState::Starting | CodeContextState::Ready
        ) {
            record.state = CodeContextState::Closing;
            record.reason = Some(reason.to_owned());
        }
        context.close.cancel();
        Ok(AgentResponse::CodeContext(record.clone()))
    }
    pub(super) async fn start_code(
        &self,
        context_id: Uuid,
        id: Uuid,
        spec: CodeRunSpec,
    ) -> Result<AgentResponse, ApiError> {
        validate_code_run(&spec)?;
        if id.is_nil() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "code run UUID must not be nil",
            ));
        }
        let context = self.context(context_id).await?;
        let encoded_spec = serde_json::to_vec(&spec).map_err(internal)?;
        let mut jobs = context.jobs.lock().await;
        if let Some(job) = jobs.get(&id) {
            if job.encoded_spec != encoded_spec {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "code run ID has different content",
                ));
            }
            return Ok(AgentResponse::CodeRun(job.record.lock().await.clone()));
        }
        if context.close.is_cancelled()
            || !matches!(
                context.record.lock().await.state,
                CodeContextState::Starting | CodeContextState::Ready
            )
        {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "code context is not accepting runs",
            ));
        }
        if jobs.len() >= 64 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "context run history limit reached",
            ));
        }
        let permit = context.input.try_reserve().map_err(|_| {
            ApiError::new(ErrorCode::QuotaExceeded, "context queue is full or closed")
        })?;
        if !reserve(&self.contexts.runs, 1, 128) {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "sandbox code-run history limit reached",
            ));
        }
        let record = CodeRun {
            id,
            context_id,
            state: CodeRunState::Pending,
            created_at: Utc::now(),
            started_at: None,
            finished_at: None,
            output_truncated: false,
            kernel_status: None,
            reason: None,
        };
        let job = Arc::new(CodeJob {
            spec,
            encoded_spec,
            record: Mutex::new(record.clone()),
            output_bytes: AtomicU64::new(0),
            truncated: AtomicBool::new(false),
        });
        jobs.insert(id, job.clone());
        permit.send(job);
        Ok(AgentResponse::CodeRun(record))
    }
    pub(super) async fn context_events(
        &self,
        id: Uuid,
        after: u64,
    ) -> Result<AgentResponse, ApiError> {
        let context = self.context(id).await?;
        let mut events = context.events.lock().await;
        if after >= events.next {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "context event cursor is ahead of observations",
            ));
        }
        while events
            .items
            .front()
            .is_some_and(|(event, _)| event.sequence <= after)
        {
            if let Some((_, bytes)) = events.items.pop_front() {
                self.buffered.fetch_sub(bytes, Ordering::Relaxed);
            }
        }
        Ok(AgentResponse::CodeContextEvents(
            events
                .items
                .iter()
                .take(256)
                .map(|(event, _)| event.clone())
                .collect(),
        ))
    }
    async fn context_push(
        &self,
        context: &Context,
        run_id: Option<Uuid>,
        kind: CodeContextEventKind,
        data: serde_json::Value,
        essential: bool,
    ) -> bool {
        let size = data.to_string().len() + 256;
        let mut events = context.events.lock().await;
        if !essential {
            if events.items.len() >= 2048 || !reserve(&self.buffered, size, MAX_BUFFERED_EVENTS) {
                return false;
            }
        } else {
            self.buffered.fetch_add(size, Ordering::Relaxed);
        }
        let sequence = events.next;
        events.next += 1;
        events.items.push_back((
            CodeContextEvent {
                sequence,
                context_id: context.id,
                run_id,
                timestamp: Utc::now(),
                kind,
                data,
            },
            size,
        ));
        true
    }
    async fn finish_code(
        &self,
        context: &Context,
        job: &CodeJob,
        state: CodeRunState,
        kernel_status: Option<String>,
        reason: Option<String>,
    ) {
        let mut record = job.record.lock().await;
        if record.finished_at.is_some() {
            return;
        }
        let mut value = record.clone();
        value.state = state;
        value.finished_at = Some(Utc::now());
        value.output_truncated = job.truncated.load(Ordering::Relaxed);
        value.kernel_status = kernel_status;
        value.reason = reason;
        self.context_push(
            context,
            Some(value.id),
            CodeContextEventKind::RunCompleted,
            json!(value),
            true,
        )
        .await;
        *record = value;
    }
    async fn context_output(
        &self,
        context: &Context,
        next: &Observation,
        active: Option<&Arc<CodeJob>>,
    ) -> Result<(), String> {
        if next.channel != Channel::Output {
            return Ok(());
        }
        let message = &next.message;
        let kind = match message.message_type() {
            "stream" => match (
                message.content()["name"].as_str(),
                message.content()["text"].as_str(),
            ) {
                (Some("stdout"), Some(_)) => CodeContextEventKind::Stdout,
                (Some("stderr"), Some(_)) => CodeContextEventKind::Stderr,
                _ => return Err("kernel stream has an invalid name or text".into()),
            },
            "execute_result" => CodeContextEventKind::Result,
            "display_data" | "update_display_data" | "clear_output" => {
                CodeContextEventKind::Display
            }
            "error" => CodeContextEventKind::KernelError,
            _ => return Ok(()),
        };
        let parent_id = message.parent_id().and_then(|id| Uuid::parse_str(id).ok());
        let active = if let Some(job) = active {
            (Some(job.record.lock().await.id) == parent_id).then_some(job)
        } else {
            None
        };
        let run_id = if let Some(id) = parent_id {
            let job = context.jobs.lock().await.get(&id).cloned();
            if let Some(job) = job {
                job.record.lock().await.started_at.map(|_| id)
            } else {
                None
            }
        } else {
            None
        };
        let data = json!({"parent_id":message.parent_id(),"message_id":message.message_id(),"late":active.is_none(),"content":message.content()});
        let size = data.to_string().len() as u64;
        let (budget, limit, truncated) = match active {
            Some(job) => (&job.output_bytes, job.spec.max_output_bytes, &job.truncated),
            None => (
                &context.background_bytes,
                1024 * 1024,
                &context.background_truncated,
            ),
        };
        // One context actor is the only writer of each run/background budget.
        let old = budget.load(Ordering::Relaxed);
        budget.store(old.saturating_add(size).min(limit), Ordering::Relaxed);
        if old.saturating_add(size) <= limit
            && self.context_push(context, run_id, kind, data, false).await
        {
            return Ok(());
        }
        if !truncated.swap(true, Ordering::Relaxed) {
            self.context_push(context, run_id, CodeContextEventKind::OutputTruncated,
                json!({"scope":if active.is_some() {"run"} else {"context_background"},"reason":"serialized_event_or_spool_limit"}), true).await;
        }
        Ok(())
    }
    async fn observe_code(
        &self,
        context: &Context,
        job: &Arc<CodeJob>,
        peer: &mut Peer,
        child: &mut Child,
    ) -> Result<String, Stop> {
        let id = job.record.lock().await.id;
        let parent = id.to_string();
        let deadline = Instant::now() + Duration::from_secs(job.spec.timeout_seconds);
        let send = tokio::select! { biased;
            _ = context.close.cancelled() => return Err(Stop::closed()),
            value = tokio::time::timeout_at(deadline.min(Instant::now()+Duration::from_secs(5)), peer.execute(id, &job.spec.code)) => value,
        };
        match send {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return Err(Stop::failed(format!(
                    "kernel request delivery failed: {error}"
                )));
            }
            Err(_) if Instant::now() >= deadline => return Err(Stop::timed_out()),
            Err(_) => return Err(Stop::failed("kernel request delivery is unknown".into())),
        }
        let (mut reply, mut idle) = (None, false);
        loop {
            let next = tokio::select! { biased;
                _ = context.close.cancelled() => return Err(Stop::closed()),
                _ = tokio::time::sleep_until(deadline) => return Err(Stop::timed_out()),
                status = child.wait() => return Err(Stop::failed(format!("kernel exited during a run: {status:?}"))),
                next = peer.next() => next.map_err(|error| Stop::failed(format!("kernel conversation failed: {error}")))?,
            };
            self.context_output(context, &next, Some(job))
                .await
                .map_err(Stop::failed)?;
            if next.message.parent_id() != Some(parent.as_str()) {
                continue;
            }
            if next.channel == Channel::Shell && next.message.message_type() == "execute_reply" {
                let status = next.message.content()["status"]
                    .as_str()
                    .filter(|value| matches!(*value, "ok" | "error"))
                    .ok_or_else(|| Stop::failed("kernel execute status is invalid".into()))?
                    .to_owned();
                if reply.as_ref().is_some_and(|previous| *previous != status) {
                    return Err(Stop::failed(
                        "kernel sent conflicting execute replies".into(),
                    ));
                }
                reply = Some(status);
            }
            if next.channel == Channel::Output
                && next.message.message_type() == "status"
                && next.message.content()["execution_state"] == "idle"
            {
                idle = true;
            }
            if idle && let Some(reply) = reply {
                return Ok(reply);
            }
        }
    }
    async fn run_context(
        self: Arc<Self>,
        context: Arc<Context>,
        mut receive: mpsc::Receiver<Arc<CodeJob>>,
    ) {
        let directory = self
            .contexts
            .private
            .path()
            .join(context.id.simple().to_string());
        let mut child = None;
        let startup = tokio::select! { biased;
            _ = context.close.cancelled() => Err(Stop::closed()),
            value = tokio::time::timeout(Duration::from_secs(30), kernel::start(&self, &context, &directory, &mut child)) =>
                value.map_err(|_| Stop::failed("kernel startup timed out".into())).and_then(|value| value.map_err(Stop::failed)),
        };
        let mut active = None;
        let stop = match startup {
            Err(stop) => stop,
            Ok((mut peer, info)) => {
                {
                    let mut record = context.record.lock().await;
                    // A concurrent close intent cannot be undone by late readiness.
                    if !context.close.is_cancelled() {
                        record.state = CodeContextState::Ready;
                        record.ready_at = Some(Utc::now());
                        record.kernel_info = Some(info);
                        self.context_push(
                            &context,
                            None,
                            CodeContextEventKind::Ready,
                            json!(*record),
                            true,
                        )
                        .await;
                    }
                }
                loop {
                    let job = tokio::select! { biased;
                        _ = context.close.cancelled() => break Stop::closed(),
                        status = child.as_mut().expect("started kernel").wait() => break Stop::failed(format!("kernel exited unexpectedly: {status:?}")),
                        job = receive.recv() => match job { Some(job) => job, None => break Stop::failed("context queue ended".into()) },
                        next = peer.next() => {
                            match next {
                                Ok(next) => if let Err(error) = self.context_output(&context, &next, None).await { break Stop::failed(error); },
                                Err(error) => break Stop::failed(format!("idle kernel conversation failed: {error}")),
                            }
                            continue;
                        }
                    };
                    {
                        let mut record = job.record.lock().await;
                        record.state = CodeRunState::Running;
                        record.started_at = Some(Utc::now());
                        self.context_push(
                            &context,
                            Some(record.id),
                            CodeContextEventKind::RunStarted,
                            json!(*record),
                            true,
                        )
                        .await;
                    }
                    match self
                        .observe_code(
                            &context,
                            &job,
                            &mut peer,
                            child.as_mut().expect("started kernel"),
                        )
                        .await
                    {
                        Ok(status) => {
                            // Serialize result publication with close intent.
                            // A close already accepted by the agent wins over a late reply.
                            let context_record = context.record.lock().await;
                            if context.close.is_cancelled()
                                || context_record.state != CodeContextState::Ready
                            {
                                active = Some(job);
                                break Stop::closed();
                            }
                            let state = if status == "ok" {
                                CodeRunState::KernelSucceeded
                            } else {
                                CodeRunState::KernelFailed
                            };
                            self.finish_code(&context, &job, state, Some(status), None)
                                .await;
                            drop(context_record);
                        }
                        Err(stop) => {
                            active = Some(job);
                            break stop;
                        }
                    }
                }
            }
        };
        {
            let mut record = context.record.lock().await;
            record.state = CodeContextState::Closing;
            if record.reason.is_none() {
                record.reason = Some(stop.reason.clone());
            }
        }
        context.close.cancel();
        receive.close();
        let collected = collect_uid_processes(context.uid).await;
        let waited = if let Some(child) = &mut child {
            let _ = child.start_kill();
            matches!(
                tokio::time::timeout(Duration::from_secs(2), child.wait()).await,
                Ok(Ok(_))
            )
        } else {
            true
        };
        let files_removed = kernel::remove_private(&directory);
        let clean = collected && waited && files_removed;
        if let Some(job) = active {
            self.finish_code(
                &context,
                &job,
                if clean {
                    stop.run_state
                } else {
                    CodeRunState::Unknown
                },
                None,
                Some(if clean {
                    stop.reason.clone()
                } else {
                    "context cleanup is unconfirmed; worker must terminate sandbox".into()
                }),
            )
            .await;
        }
        let jobs = context
            .jobs
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for job in jobs {
            if job.record.lock().await.finished_at.is_none() {
                self.finish_code(
                    &context,
                    &job,
                    if clean {
                        CodeRunState::Cancelled
                    } else {
                        CodeRunState::Unknown
                    },
                    None,
                    Some("context ended before this queued run was dispatched".into()),
                )
                .await;
            }
        }
        let mut record = context.record.lock().await;
        record.state = if clean {
            stop.context_state
        } else {
            CodeContextState::Unknown
        };
        record.cleanup = if clean {
            CleanupState::Complete
        } else {
            CleanupState::Unknown
        };
        record.finished_at = Some(Utc::now());
        if !clean {
            record.reason =
                Some("context cleanup is unconfirmed; worker must terminate sandbox".into());
        }
        self.context_push(
            &context,
            None,
            CodeContextEventKind::Closed,
            json!(*record),
            true,
        )
        .await;
        if clean {
            let mut slots = self.contexts.slots.lock().await;
            let slot = (context.uid - 20000) as usize;
            if slots[slot] == Some(context.id) {
                slots[slot] = None;
            }
        }
    }
}

fn reserve(counter: &AtomicUsize, bytes: usize, limit: usize) -> bool {
    let mut used = counter.load(Ordering::Relaxed);
    loop {
        let Some(next) = used.checked_add(bytes).filter(|next| *next <= limit) else {
            return false;
        };
        match counter.compare_exchange_weak(used, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(observed) => used = observed,
        }
    }
}

struct Stop {
    context_state: CodeContextState,
    run_state: CodeRunState,
    reason: String,
}
impl Stop {
    fn closed() -> Self {
        Self {
            context_state: CodeContextState::Closed,
            run_state: CodeRunState::Cancelled,
            reason: "context close/cancel discards interpreter state".into(),
        }
    }
    fn timed_out() -> Self {
        Self {
            context_state: CodeContextState::Closed,
            run_state: CodeRunState::TimedOut,
            reason: "code deadline exceeded; entire context was collected".into(),
        }
    }
    fn failed(mut reason: String) -> Self {
        if reason.len() > 4096 {
            let mut end = 4096;
            while !reason.is_char_boundary(end) {
                end -= 1;
            }
            reason.truncate(end);
        }
        Self {
            context_state: CodeContextState::Failed,
            run_state: CodeRunState::Unknown,
            reason,
        }
    }
}
