use super::*;
mod events;
pub use events::CodeContextEventStream;

#[derive(Debug, serde::Serialize)]
pub struct CodeRunOutput {
    pub run: CodeRun,
    pub stdout: String,
    pub stderr: String,
    pub results: Vec<serde_json::Value>,
    pub displays: Vec<serde_json::Value>,
    pub errors: Vec<serde_json::Value>,
}

fn collected(context: &CodeContext) -> bool {
    context.cleanup == CleanupState::Complete
        && matches!(
            context.state,
            CodeContextState::Closed | CodeContextState::Failed
        )
        && context.finished_at.is_some()
}

impl Client {
    pub async fn create_code_context(
        &self,
        sandbox: Uuid,
        spec: &CodeContextSpec,
        key: &str,
    ) -> Result<CodeContext> {
        let value: CodeContext = Self::json(
            self.send(
                Method::POST,
                &format!("v1/sandboxes/{sandbox}/code-contexts"),
                Some(
                    serde_json::to_value(spec)
                        .map_err(|_| Error::Protocol("invalid context request"))?,
                ),
                Some(key),
            )
            .await?,
        )
        .await?;
        if value.id.is_nil()
            || value.sandbox_id != sandbox
            || serde_json::to_value(&value.spec).ok() != serde_json::to_value(spec).ok()
        {
            return Err(Error::Protocol("code-context creation identity mismatch"));
        }
        Ok(value)
    }
    pub async fn code_context(&self, id: Uuid) -> Result<CodeContext> {
        let value: CodeContext = self.get(&format!("v1/code-contexts/{id}")).await?;
        if value.id != id || value.sandbox_id.is_nil() {
            return Err(Error::Protocol("code-context identity mismatch"));
        }
        Ok(value)
    }
    pub async fn list_code_contexts(
        &self,
        sandbox: Option<Uuid>,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<CodeContextPage> {
        let mut path = format!("v1/code-contexts?limit={limit}");
        if let Some(id) = sandbox {
            path.push_str(&format!("&sandbox_id={id}"));
        }
        if let Some(id) = after {
            path.push_str(&format!("&after={id}"));
        }
        let page: CodeContextPage = self.get(&path).await?;
        if page
            .items
            .iter()
            .any(|item| item.id.is_nil() || sandbox.is_some_and(|id| item.sandbox_id != id))
        {
            return Err(Error::Protocol("context page identity mismatch"));
        }
        Ok(page)
    }
    /// Persist close intent. Wait for collection with wait_code_context_closed.
    pub async fn close_code_context(&self, id: Uuid, key: &str) -> Result<CodeContext> {
        let value: CodeContext = Self::json(
            self.send(
                Method::DELETE,
                &format!("v1/code-contexts/{id}"),
                None,
                Some(key),
            )
            .await?,
        )
        .await?;
        if value.id != id || value.desired_state != CodeContextDesiredState::Closed {
            return Err(Error::Protocol("context close was not accepted"));
        }
        Ok(value)
    }
    pub async fn wait_code_context_ready(
        &self,
        id: Uuid,
        timeout: Duration,
    ) -> Result<CodeContext> {
        let deadline = Instant::now() + timeout;
        loop {
            let value = tokio::time::timeout(
                deadline.saturating_duration_since(Instant::now()),
                self.code_context(id),
            )
            .await
            .map_err(|_| Error::Timeout(id))??;
            if value.desired_state != CodeContextDesiredState::Open
                || matches!(
                    value.state,
                    CodeContextState::Closing
                        | CodeContextState::Closed
                        | CodeContextState::Failed
                        | CodeContextState::Unknown
                )
            {
                return Err(Error::Api(ApiError::new(
                    ErrorCode::InvalidState,
                    value
                        .reason
                        .as_deref()
                        .unwrap_or("code context is not available"),
                )));
            }
            if value.state == CodeContextState::Ready
                && value.cleanup == CleanupState::Pending
                && value.ready_at.is_some()
            {
                return Ok(value);
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout(id));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    pub async fn wait_code_context_closed(
        &self,
        id: Uuid,
        timeout: Duration,
    ) -> Result<CodeContext> {
        let deadline = Instant::now() + timeout;
        loop {
            let value = tokio::time::timeout(
                deadline.saturating_duration_since(Instant::now()),
                self.code_context(id),
            )
            .await
            .map_err(|_| Error::Timeout(id))??;
            if collected(&value) {
                return Ok(value);
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout(id));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    pub async fn start_code(
        &self,
        context: Uuid,
        spec: &CodeRunSpec,
        key: &str,
    ) -> Result<CodeRun> {
        let value: CodeRun = Self::json(
            self.send(
                Method::POST,
                &format!("v1/code-contexts/{context}/runs"),
                Some(
                    serde_json::to_value(spec)
                        .map_err(|_| Error::Protocol("invalid code request"))?,
                ),
                Some(key),
            )
            .await?,
        )
        .await?;
        if value.id.is_nil() || value.context_id != context || value.events_after > i64::MAX as u64
        {
            return Err(Error::Protocol("code-run creation identity mismatch"));
        }
        Ok(value)
    }
    pub async fn code_run(&self, id: Uuid) -> Result<CodeRun> {
        let value: CodeRun = self.get(&format!("v1/code-runs/{id}")).await?;
        if value.id != id || value.context_id.is_nil() {
            return Err(Error::Protocol("code-run identity mismatch"));
        }
        Ok(value)
    }
    pub async fn list_code_runs(
        &self,
        context: Uuid,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<CodeRunPage> {
        let mut path = format!("v1/code-contexts/{context}/runs?limit={limit}");
        if let Some(id) = after {
            path.push_str(&format!("&after={id}"));
        }
        let page: CodeRunPage = self.get(&path).await?;
        if page
            .items
            .iter()
            .any(|item| item.id.is_nil() || item.context_id != context)
        {
            return Err(Error::Protocol("code-run page identity mismatch"));
        }
        Ok(page)
    }
    /// Cancels the entire interpreter context, including its queued runs.
    pub async fn cancel_code_run(&self, id: Uuid) -> Result<CodeRun> {
        let value: CodeRun = Self::json(
            self.send(
                Method::POST,
                &format!("v1/code-runs/{id}/cancel"),
                None,
                None,
            )
            .await?,
        )
        .await?;
        if value.id != id {
            return Err(Error::Protocol("code cancellation identity mismatch"));
        }
        Ok(value)
    }
    pub async fn run_code(&self, context: Uuid, spec: &CodeRunSpec) -> Result<CodeRunOutput> {
        self.run_code_with_key(context, spec, &Uuid::new_v4().to_string())
            .await
    }
    pub async fn run_code_with_key(
        &self,
        context: Uuid,
        spec: &CodeRunSpec,
        key: &str,
    ) -> Result<CodeRunOutput> {
        let accepted = match self.start_code(context, spec, key).await {
            Ok(value) => value,
            Err(Error::Transport) => return Err(Error::UncertainRequest(key.into())),
            Err(Error::Api(error)) if error.code == ErrorCode::BackendUnavailable => {
                return Err(Error::UncertainRequest(key.into()));
            }
            Err(error) => return Err(error),
        };
        tokio::time::timeout(
            Duration::from_secs(spec.timeout_seconds.saturating_add(60)),
            self.collect_code(&accepted, spec.max_output_bytes),
        )
        .await
        .map_err(|_| Error::Timeout(accepted.id))?
        .map_err(|error| Error::CodeObservation(accepted.id, Box::new(error)))
    }
    async fn collect_code(&self, accepted: &CodeRun, limit: u64) -> Result<CodeRunOutput> {
        if !(1..=16 * 1024 * 1024).contains(&limit) {
            return Err(Error::Protocol("invalid code output limit"));
        }
        let mut output = CodeRunOutput {
            run: accepted.clone(),
            stdout: String::new(),
            stderr: String::new(),
            results: Vec::new(),
            displays: Vec::new(),
            errors: Vec::new(),
        };
        // Use the acceptance cursor, including when replaying an old create key.
        let mut cursor = accepted.events_after;
        let mut used = 0u64;
        for _ in 0..3 {
            let mut stream = match self.code_context_events(accepted.context_id, cursor).await {
                Ok(value) => value,
                Err(Error::Transport) => continue,
                Err(error) => return Err(error),
            };
            while let Some(event) = stream.next().await {
                let event = match event {
                    Ok(value) => value,
                    Err(Error::Transport) => break,
                    Err(error) => return Err(error),
                };
                cursor = event.sequence;
                if event.run_id != Some(accepted.id) {
                    continue;
                }
                if matches!(
                    event.kind,
                    CodeContextEventKind::Stdout
                        | CodeContextEventKind::Stderr
                        | CodeContextEventKind::Result
                        | CodeContextEventKind::Display
                        | CodeContextEventKind::KernelError
                ) {
                    let late = event.data["late"]
                        .as_bool()
                        .ok_or(Error::Protocol("code output lacks provenance"))?;
                    if late {
                        continue;
                    }
                    let bytes = serde_json::to_vec(&event.data)
                        .map_err(|_| Error::Protocol("invalid code output"))?
                        .len() as u64;
                    used = used
                        .checked_add(bytes)
                        .filter(|used| *used <= limit)
                        .ok_or(Error::Protocol("code output exceeds requested budget"))?;
                    let content = &event.data["content"];
                    match event.kind {
                        CodeContextEventKind::Stdout => output.stdout.push_str(
                            content["text"]
                                .as_str()
                                .ok_or(Error::Protocol("invalid kernel stdout"))?,
                        ),
                        CodeContextEventKind::Stderr => output.stderr.push_str(
                            content["text"]
                                .as_str()
                                .ok_or(Error::Protocol("invalid kernel stderr"))?,
                        ),
                        CodeContextEventKind::Result => output.results.push(content.clone()),
                        CodeContextEventKind::Display => output.displays.push(content.clone()),
                        CodeContextEventKind::KernelError => output.errors.push(content.clone()),
                        _ => {}
                    }
                } else if event.kind == CodeContextEventKind::RunCompleted {
                    let run: CodeRun = serde_json::from_value(event.data)
                        .map_err(|_| Error::Protocol("invalid code completion"))?;
                    if run.id != accepted.id
                        || run.context_id != accepted.context_id
                        || run.events_after != accepted.events_after
                        || run.finished_at.is_none()
                    {
                        return Err(Error::Protocol("code completion identity mismatch"));
                    }
                    match run.state {
                        CodeRunState::KernelSucceeded | CodeRunState::KernelFailed => {
                            let expected = if run.state == CodeRunState::KernelSucceeded {
                                "ok"
                            } else {
                                "error"
                            };
                            if run.started_at.is_none()
                                || run.kernel_status.as_deref() != Some(expected)
                            {
                                return Err(Error::Protocol(
                                    "code completion lacks matching kernel observations",
                                ));
                            }
                        }
                        CodeRunState::Cancelled | CodeRunState::TimedOut => {
                            if run.kernel_status.is_some()
                                || !collected(&self.code_context(run.context_id).await?)
                            {
                                return Err(Error::Protocol(
                                    "code cancellation lacks context collection",
                                ));
                            }
                        }
                        CodeRunState::Rejected
                            if run.started_at.is_none() && run.kernel_status.is_none() => {}
                        CodeRunState::Unknown => {
                            return Err(Error::Protocol("kernel execution outcome is unknown"));
                        }
                        _ => {
                            return Err(Error::Protocol(
                                "code result is not an explicit completion",
                            ));
                        }
                    }
                    output.run = run;
                    return Ok(output);
                }
            }
        }
        Err(Error::Protocol(
            "context stream ended before a matching code result",
        ))
    }
}
