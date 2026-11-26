use super::{AgentRequest, ApiError, DockerDriver, RuntimeHandle};
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Test-only observations of transport failure; never execution authority.
/// Payloads, paths, commands, code, replies and error text are not retained.
pub(super) struct BridgeDiagnostics {
    pub(super) phase: &'static str,
    pub(super) exec_id: Option<String>,
    pub(super) output_eof_observed: bool,
    pub(super) stderr_observed: bool,
    pub(super) terminal_running: Option<bool>,
    pub(super) terminal_exit_code: Option<i64>,
    started: Instant,
    request_kind: &'static str,
    reply_bytes: usize,
    reply_line_terminated: bool,
    first_reply_milliseconds: Option<u128>,
}

impl BridgeDiagnostics {
    pub(super) fn new(request: &AgentRequest) -> Self {
        let request_kind = match request {
            AgentRequest::Ping => "ping",
            AgentRequest::Start { .. } => "command_start",
            AgentRequest::StartSession { .. } => "session_start",
            AgentRequest::SessionControl { .. } => "session_control",
            AgentRequest::SessionControlStatus { .. } => "session_control_status",
            AgentRequest::Inspect { .. } => "command_inspect",
            AgentRequest::Events { .. } => "command_events",
            AgentRequest::Cancel { .. } => "command_cancel",
            AgentRequest::CodeContextCreate { .. } => "code_context_create",
            AgentRequest::CodeContextGet { .. } => "code_context_get",
            AgentRequest::CodeContextClose { .. } => "code_context_close",
            AgentRequest::CodeContextEvents { .. } => "code_context_events",
            AgentRequest::CodeRunStart { .. } => "code_run_start",
            AgentRequest::CodeRunGet { .. } => "code_run_get",
            AgentRequest::CodeRunCancel { .. } => "code_run_cancel",
            AgentRequest::WriteFile { .. } => "write_file",
            AgentRequest::ReadFile { .. } => "read_file",
            AgentRequest::ListFiles { .. } => "list_files",
            AgentRequest::RemoveFile { .. } => "remove_file",
        };
        Self {
            phase: "create_exec",
            exec_id: None,
            output_eof_observed: false,
            stderr_observed: false,
            terminal_running: None,
            terminal_exit_code: None,
            started: Instant::now(),
            request_kind,
            reply_bytes: 0,
            reply_line_terminated: false,
            first_reply_milliseconds: None,
        }
    }

    pub(super) fn observe_reply(&mut self, reply: &[u8]) {
        self.reply_bytes = reply.len();
        self.reply_line_terminated = reply.last() == Some(&b'\n');
        if !reply.is_empty() && self.first_reply_milliseconds.is_none() {
            self.first_reply_milliseconds = Some(self.started.elapsed().as_millis());
        }
    }

    pub(super) fn report(self, driver: &DockerDriver, handle: &RuntimeHandle, error: &ApiError) {
        if std::env::var("GOLDENHOOP_TEST_BACKEND_DIAGNOSTICS").as_deref() != Ok("1") {
            return;
        }
        let budget = &driver.bridge_diagnostic_budget;
        let mut remaining = budget.load(Ordering::Relaxed);
        loop {
            let Some(next) = remaining.checked_sub(1) else {
                return;
            };
            match budget.compare_exchange_weak(
                remaining,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => remaining = actual,
            }
        }
        // One driver instance, including its clones, emits at most sixteen
        // failure records. No extra I/O or changed timeout precedes the result.
        eprintln!(
            "{}",
            serde_json::json!({
                "event":"agent_bridge_failure_window",
                "installation_id":driver.config.installation_id,
                "sandbox_id":handle.sandbox_id,
                "exec_id":self.exec_id,
                "request_kind":self.request_kind,
                "phase":self.phase,
                "elapsed_milliseconds":self.started.elapsed().as_millis(),
                "reply_bytes":self.reply_bytes,
                "reply_line_terminated":self.reply_line_terminated,
                "first_reply_milliseconds":self.first_reply_milliseconds,
                "output_eof_observed":self.output_eof_observed,
                "stderr_observed":self.stderr_observed,
                "terminal_running":self.terminal_running,
                "terminal_exit_code":self.terminal_exit_code,
                "error_code":error.code,
            })
        );
    }
}
