use std::collections::{HashMap, VecDeque};
use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
use std::path::Path;
use std::process::Stdio;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use goldenhoop_core::validate_command;
use goldenhoop_protocol::*;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::{Mutex, Semaphore, oneshot};
use uuid::Uuid;

use crate::filesystem::Workspace;

const MAX_FRAME: u64 = 24 * 1024 * 1024;
const MAX_BUFFERED_EVENTS: usize = 16 * 1024 * 1024;
const WORKLOAD_UID: u32 = 1000;

struct EventBuffer {
    next: u64,
    events: VecDeque<(ExecutionEvent, usize)>,
}
struct Job {
    spec: Vec<u8>,
    record: Mutex<Execution>,
    events: Mutex<EventBuffer>,
    cancel: Mutex<Option<oneshot::Sender<()>>>,
    output_used: AtomicU64,
    truncated: AtomicBool,
}
struct Agent {
    workspace: Workspace,
    jobs: Mutex<HashMap<Uuid, Arc<Job>>>,
    // Normal commands share a stable workload identity and execute sequentially.
    // This allows complete UID-based descendant collection, including setsid().
    commands: Arc<Semaphore>,
    buffered: AtomicUsize,
}

impl Agent {
    async fn push(&self, job: &Job, kind: EventKind, data: serde_json::Value) {
        let size = data.to_string().len() + 256;
        let mut buffer = job.events.lock().await;
        let id = job.record.lock().await.id;
        let event = ExecutionEvent {
            sequence: buffer.next,
            execution_id: id,
            timestamp: Utc::now(),
            kind,
            data,
        };
        buffer.next += 1;
        buffer.events.push_back((event, size));
        self.buffered.fetch_add(size, Ordering::Relaxed);
    }

    async fn output(&self, job: &Job, kind: EventKind, bytes: &[u8], limit: u64) {
        let mut taken = job.output_used.load(Ordering::Relaxed);
        loop {
            let next = taken.saturating_add(bytes.len() as u64).min(limit);
            match job.output_used.compare_exchange_weak(
                taken,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => taken = observed,
            }
        }
        let keep = (limit.saturating_sub(taken) as usize).min(bytes.len());
        let buffered_full = self.buffered.load(Ordering::Relaxed) >= MAX_BUFFERED_EVENTS;
        if keep > 0 && !buffered_full {
            self.push(
                job,
                kind,
                json!({"encoding":"base64","data":STANDARD.encode(&bytes[..keep])}),
            )
            .await;
        }
        if (keep < bytes.len() || buffered_full) && !job.truncated.swap(true, Ordering::Relaxed) {
            self.push(
                job,
                EventKind::OutputTruncated,
                json!({"reason":"output_or_buffer_limit"}),
            )
            .await;
        }
    }

    async fn finish(
        &self,
        job: &Job,
        state: ExecutionState,
        exit_code: Option<i32>,
        cleanup: CleanupState,
        reason: Option<String>,
    ) {
        let mut result = job.record.lock().await.clone();
        result.state = state;
        result.exit_code = exit_code;
        result.cleanup = cleanup;
        result.reason = reason;
        result.finished_at = Some(Utc::now());
        result.output_truncated = job.truncated.load(Ordering::Relaxed);
        self.push(job, EventKind::Completed, json!(result)).await;
        *job.record.lock().await = result;
    }

    async fn request(self: &Arc<Self>, request: AgentRequest) -> Result<AgentResponse, ApiError> {
        match request {
            AgentRequest::Ping => Ok(AgentResponse::Pong {
                version: env!("CARGO_PKG_VERSION").into(),
            }),
            AgentRequest::Start { id, command } => {
                validate_command(&command)?;
                // Resolve under the directory capability before any process is created.
                self.workspace.cwd_handle(&command.cwd)?;
                let spec = serde_json::to_vec(&command).map_err(internal)?;
                let mut jobs = self.jobs.lock().await;
                if let Some(job) = jobs.get(&id) {
                    if job.spec != spec {
                        return Err(ApiError::new(
                            ErrorCode::Conflict,
                            "execution ID has different command content",
                        ));
                    }
                    return Ok(AgentResponse::Execution(job.record.lock().await.clone()));
                }
                if jobs.len() >= 256 {
                    return Err(ApiError::new(
                        ErrorCode::QuotaExceeded,
                        "sandbox execution history limit reached",
                    ));
                }
                let record = Execution {
                    id,
                    sandbox_id: Uuid::nil(),
                    state: ExecutionState::Pending,
                    exit_code: None,
                    created_at: Utc::now(),
                    started_at: None,
                    finished_at: None,
                    output_truncated: false,
                    cleanup: CleanupState::NotRequired,
                    reason: None,
                };
                let (send, receive) = oneshot::channel();
                let job = Arc::new(Job {
                    spec,
                    record: Mutex::new(record.clone()),
                    events: Mutex::new(EventBuffer {
                        next: 1,
                        events: VecDeque::new(),
                    }),
                    cancel: Mutex::new(Some(send)),
                    output_used: AtomicU64::new(0),
                    truncated: AtomicBool::new(false),
                });
                jobs.insert(id, job.clone());
                let agent = self.clone();
                tokio::spawn(async move {
                    agent.run(job, command, receive).await;
                });
                Ok(AgentResponse::Execution(record))
            }
            AgentRequest::Inspect { id } => Ok(AgentResponse::Execution(
                self.job(id).await?.record.lock().await.clone(),
            )),
            AgentRequest::Cancel { id } => {
                let job = self.job(id).await?;
                if let Some(send) = job.cancel.lock().await.take() {
                    let _ = send.send(());
                }
                let record = job.record.lock().await.clone();
                Ok(AgentResponse::Execution(record))
            }
            AgentRequest::Events { id, after } => {
                let job = self.job(id).await?;
                let mut buffer = job.events.lock().await;
                // An internal worker cursor acknowledges events already persisted outside
                // the sandbox. Public replay is served from the control-plane event store.
                while buffer
                    .events
                    .front()
                    .is_some_and(|(e, _)| e.sequence <= after)
                {
                    if let Some((_, size)) = buffer.events.pop_front() {
                        self.buffered.fetch_sub(size, Ordering::Relaxed);
                    }
                }
                Ok(AgentResponse::Events(
                    buffer
                        .events
                        .iter()
                        .take(256)
                        .map(|(e, _)| e.clone())
                        .collect(),
                ))
            }
            AgentRequest::WriteFile { path, data_base64 } => {
                self.workspace.write(&path, &data_base64)?;
                Ok(AgentResponse::Ok)
            }
            AgentRequest::ReadFile { path, max_bytes } => Ok(AgentResponse::File {
                data_base64: self.workspace.read(&path, max_bytes)?,
            }),
            AgentRequest::ListFiles { path } => {
                Ok(AgentResponse::Files(self.workspace.list(&path)?))
            }
            AgentRequest::RemoveFile { path } => {
                self.workspace.remove(&path)?;
                Ok(AgentResponse::Ok)
            }
        }
    }

    async fn job(&self, id: Uuid) -> Result<Arc<Job>, ApiError> {
        self.jobs
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "execution not found"))
    }

    async fn read_output<R: AsyncRead + Unpin>(
        &self,
        job: &Job,
        mut reader: R,
        kind: EventKind,
        limit: u64,
    ) {
        let mut bytes = [0; 8192];
        loop {
            match reader.read(&mut bytes).await {
                Ok(0) => break,
                Ok(n) => self.output(job, kind, &bytes[..n], limit).await,
                Err(_) => {
                    self.push(
                        job,
                        EventKind::Diagnostic,
                        json!({"reason":"output_read_error"}),
                    )
                    .await;
                    break;
                }
            }
        }
    }

    async fn run(
        self: Arc<Self>,
        job: Arc<Job>,
        spec: CommandSpec,
        mut cancel: oneshot::Receiver<()>,
    ) {
        let _permit = tokio::select! {
            permit = self.commands.clone().acquire_owned() => match permit {
                Ok(value) => value,
                Err(_) => return,
            },
            _ = &mut cancel => {
                self.finish(&job, ExecutionState::Cancelled, None, CleanupState::Complete, None).await;
                return;
            }
        };
        let cwd = match self.workspace.cwd_handle(&spec.cwd) {
            Ok(value) => value,
            Err(error) => {
                self.finish(
                    &job,
                    ExecutionState::Failed,
                    None,
                    CleanupState::Complete,
                    Some(error.message),
                )
                .await;
                return;
            }
        };
        let mut command = Command::new(&spec.argv[0]);
        command
            .args(&spec.argv[1..])
            .current_dir(format!("/proc/self/fd/{}", cwd.as_raw_fd()))
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", "/workspace")
            .env("LANG", "C.UTF-8")
            .envs(&spec.env)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // SAFETY: the child hook only calls async-signal-safe libc functions.
        unsafe {
            command.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgid(WORKLOAD_UID) != 0 || libc::setuid(WORKLOAD_UID) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::umask(0o002);
                Ok(())
            });
        }
        let mut child = match command.spawn() {
            Ok(value) => value,
            Err(error) => {
                self.finish(
                    &job,
                    ExecutionState::Failed,
                    None,
                    CleanupState::Complete,
                    Some(format!("process launch failed: {error}")),
                )
                .await;
                return;
            }
        };
        drop(cwd);
        {
            let mut record = job.record.lock().await;
            record.state = ExecutionState::Running;
            record.started_at = Some(Utc::now());
            record.cleanup = CleanupState::Pending;
        }
        self.push(&job, EventKind::Started, json!({})).await;
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let out_agent = self.clone();
        let out_job = job.clone();
        let limit = spec.max_output_bytes;
        let out_task = tokio::spawn(async move {
            out_agent
                .read_output(&out_job, stdout, EventKind::Stdout, limit)
                .await;
        });
        let err_agent = self.clone();
        let err_job = job.clone();
        let err_task = tokio::spawn(async move {
            err_agent
                .read_output(&err_job, stderr, EventKind::Stderr, limit)
                .await;
        });
        let (state, code, reason) = tokio::select! {
            status = child.wait() => match status {
                Ok(status) if status.success() => (ExecutionState::Succeeded, status.code(), None),
                Ok(status) => (ExecutionState::Failed, status.code(), Some("process exited unsuccessfully".into())),
                Err(error) => (ExecutionState::Unknown, None, Some(format!("process wait failed: {error}"))),
            },
            _ = &mut cancel => (ExecutionState::Cancelled, None, None),
            _ = tokio::time::sleep(Duration::from_secs(spec.timeout_seconds)) =>
                (ExecutionState::TimedOut, None, Some("command deadline exceeded".into())),
        };
        // Workload descendants cannot change their real UID: setuid privilege and
        // privilege-gaining execs are disabled by the worker's container policy.
        let clean = collect_workload_processes().await;
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        for mut reader in [out_task, err_task] {
            if tokio::time::timeout(Duration::from_secs(2), &mut reader)
                .await
                .is_err()
            {
                reader.abort();
            }
        }
        if clean {
            self.finish(&job, state, code, CleanupState::Complete, reason)
                .await;
        } else {
            self.finish(
                &job,
                ExecutionState::Unknown,
                code,
                CleanupState::Unknown,
                Some("descendant cleanup unconfirmed; worker must terminate sandbox".into()),
            )
            .await;
        }
    }
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorCode::Internal, error.to_string())
}

async fn collect_workload_processes() -> bool {
    for _ in 0..40 {
        let entries = match std::fs::read_dir("/proc") {
            Ok(value) => value,
            Err(_) => return false,
        };
        let mut alive = false;
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
                continue;
            };
            let own_uid = status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u32>().ok());
            let zombie = status
                .lines()
                .find_map(|line| line.strip_prefix("State:"))
                .is_some_and(|v| matches!(v.trim_start().chars().next(), Some('Z' | 'X')));
            if own_uid == Some(WORKLOAD_UID) && !zombie {
                alive = true;
                // SAFETY: pid belongs to the fixed workload UID in this private PID namespace.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        if !alive {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn read_frame<R: AsyncRead + Unpin>(reader: R) -> Result<Vec<u8>, ApiError> {
    let mut bytes = Vec::new();
    BufReader::new(reader)
        .take(MAX_FRAME + 1)
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(internal)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_FRAME {
        return Err(ApiError::new(
            ErrorCode::QuotaExceeded,
            "invalid or oversized agent frame",
        ));
    }
    Ok(bytes)
}

pub async fn serve(socket: &Path, workspace: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // SAFETY: querying the effective UID has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(
            "agent supervisor must run as container root and drop workload identity".into(),
        );
    }
    std::fs::create_dir_all(workspace)?;
    let workspace_fd = std::fs::File::open(workspace)?;
    // SAFETY: fd is an owned directory descriptor; this is the dedicated sandbox workspace.
    if unsafe { libc::fchown(workspace_fd.as_raw_fd(), WORKLOAD_UID, WORKLOAD_UID) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    workspace_fd.set_permissions(std::fs::Permissions::from_mode(0o2770))?;
    let parent = socket.parent().ok_or("socket needs a parent")?;
    std::fs::create_dir_all(parent)?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    let listener = UnixListener::bind(socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    let agent = Arc::new(Agent {
        workspace: Workspace::open(workspace, Some((WORKLOAD_UID, WORKLOAD_UID)))?,
        jobs: Mutex::new(HashMap::new()),
        commands: Arc::new(Semaphore::new(1)),
        buffered: AtomicUsize::new(0),
    });
    loop {
        let (mut stream, _) = listener.accept().await?;
        let agent = agent.clone();
        tokio::spawn(async move {
            let outcome = match read_frame(&mut stream).await {
                Ok(bytes) => match serde_json::from_slice::<AgentRequest>(&bytes) {
                    Ok(request) => agent.request(request).await,
                    Err(_) => Err(ApiError::new(
                        ErrorCode::InvalidRequest,
                        "invalid agent request",
                    )),
                },
                Err(error) => Err(error),
            };
            let reply = match outcome {
                Ok(value) => AgentReply::Success(value),
                Err(error) => AgentReply::Error(error),
            };
            if let Ok(mut bytes) = serde_json::to_vec(&reply) {
                bytes.push(b'\n');
                let _ = stream.write_all(&bytes).await;
                let _ = stream.shutdown().await;
            }
        });
    }
}

pub async fn rpc_stdio(socket: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let request = read_frame(tokio::io::stdin()).await?;
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(&request).await?;
    if request.last() != Some(&b'\n') {
        stream.write_all(b"\n").await?;
    }
    let reply = read_frame(stream).await?;
    let mut stdout = tokio::io::stdout();
    stdout.write_all(&reply).await?;
    stdout.flush().await?;
    Ok(())
}
