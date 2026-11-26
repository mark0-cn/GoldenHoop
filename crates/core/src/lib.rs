//! Runtime-independent orchestration invariants.
use chrono::{DateTime, Utc};
use goldenhoop_protocol::*;
use sha2::{Digest, Sha256};
pub mod resolver;

pub fn validate_create(profile: &RuntimeProfile, request: &CreateSandbox) -> Result<(), ApiError> {
    if profile.id != request.profile {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "profile does not match request",
        ));
    }
    if profile.availability != Availability::Available {
        return Err(ApiError::new(
            ErrorCode::BackendUnavailable,
            profile
                .reason
                .as_deref()
                .unwrap_or("runtime profile is not available"),
        ));
    }
    if request.image.trim().is_empty() || request.image.contains('\0') {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "image is required",
        ));
    }
    if request.image.len() > 1024
        || request.metadata.len() > 64
        || request
            .metadata
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>()
            > 16 * 1024
    {
        return Err(ApiError::new(
            ErrorCode::QuotaExceeded,
            "image reference or metadata exceeds request limits",
        ));
    }
    if request.ttl_seconds == 0 || request.ttl_seconds > profile.max_ttl_seconds {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "TTL exceeds profile limits",
        ));
    }
    let limits = &allocation_envelope(&request.resources, request.child_budget.as_ref())?;
    let max = &profile.max_resources;
    if limits.cpu_millis == 0 || limits.memory_bytes == 0 || limits.pids == 0 {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "resource limits must be positive",
        ));
    }
    if limits.cpu_millis > max.cpu_millis
        || limits.memory_bytes > max.memory_bytes
        || limits.pids > max.pids
    {
        return Err(ApiError::new(
            ErrorCode::QuotaExceeded,
            "resource limits exceed profile maximum",
        ));
    }
    for required in &request.required_capabilities {
        require_feature(profile, request.feature_limit.as_ref(), *required)?;
    }
    if request.child_budget.is_some() || request.feature_limit.is_some() {
        // No production profile advertises this until hierarchy accounting,
        // enforcement and the actual isolated-session gate are integrated.
        require_capability(profile, Capability::IsolatedSessions)?;
    }
    require_capability(profile, Capability::NetworkIsolation)?;
    if request.network != NetworkPolicy::default() {
        require_feature(
            profile,
            request.feature_limit.as_ref(),
            Capability::NetworkPolicy,
        )?;
    }
    // Syntax validation is separate from enforcement. A compiled policy never
    // grants NetworkPolicy; an actual backend capability is still mandatory.
    goldenhoop_policy::Policy::compile(&request.network)?;
    Ok(())
}

pub fn allocation_envelope(
    workload: &ResourceLimits,
    children: Option<&ResourceLimits>,
) -> Result<ResourceLimits, ApiError> {
    let invalid = || {
        ApiError::new(
            ErrorCode::InvalidRequest,
            "workload and child resource limits must be positive",
        )
    };
    if workload.cpu_millis == 0 || workload.memory_bytes == 0 || workload.pids == 0 {
        return Err(invalid());
    }
    let Some(children) = children else {
        return Ok(workload.clone());
    };
    if children.cpu_millis == 0 || children.memory_bytes == 0 || children.pids == 0 {
        return Err(invalid());
    }
    let overflow = || {
        ApiError::new(
            ErrorCode::QuotaExceeded,
            "resource reservation exceeds numeric limits",
        )
    };
    Ok(ResourceLimits {
        cpu_millis: workload
            .cpu_millis
            .checked_add(children.cpu_millis)
            .ok_or_else(overflow)?,
        memory_bytes: workload
            .memory_bytes
            .checked_add(children.memory_bytes)
            .ok_or_else(overflow)?,
        pids: workload
            .pids
            .checked_add(children.pids)
            .ok_or_else(overflow)?,
    })
}

pub fn require_feature(
    profile: &RuntimeProfile,
    ceiling: Option<&std::collections::BTreeSet<Capability>>,
    capability: Capability,
) -> Result<(), ApiError> {
    require_capability(profile, capability)?;
    if ceiling.is_some_and(|allowed| !allowed.contains(&capability)) {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            format!("{capability:?} is outside the sandbox feature ceiling"),
        ));
    }
    Ok(())
}

pub fn require_capability(
    profile: &RuntimeProfile,
    capability: Capability,
) -> Result<(), ApiError> {
    if profile.capabilities.contains(&capability) {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::UnsupportedCapability,
            format!("{capability:?} is not supported by profile {}", profile.id),
        ))
    }
}

pub fn transition(current: SandboxState, next: SandboxState) -> Result<SandboxState, ApiError> {
    use SandboxState::*;
    let allowed = match current {
        Pending => matches!(next, Starting | Stopping | Failed),
        Starting => matches!(next, Running | Stopping | Failed | Unknown),
        Running => matches!(next, Pausing | Stopping | Failed | Unknown),
        Pausing => matches!(next, Paused | Stopping | Failed | Unknown),
        Paused => matches!(next, Resuming | Stopping | Failed | Unknown),
        Resuming => matches!(next, Running | Stopping | Failed | Unknown),
        Stopping => matches!(next, Terminated | Failed | Unknown),
        Unknown => matches!(
            next,
            Starting | Running | Paused | Stopping | Terminated | Failed
        ),
        Terminated | Failed => false,
    };
    if allowed {
        Ok(next)
    } else {
        Err(ApiError::new(
            ErrorCode::InvalidState,
            format!("cannot transition {current:?} to {next:?}"),
        ))
    }
}

pub fn expired(sandbox: &Sandbox, now: DateTime<Utc>) -> bool {
    now >= sandbox.expires_at
}

pub fn validate_command(command: &CommandSpec) -> Result<(), ApiError> {
    if command.argv.len() > 1024
        || command.env.len() > 128
        || command.cwd.len() > 4096
        || command.argv.iter().map(String::len).sum::<usize>() > 128 * 1024
        || command
            .env
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>()
            > 64 * 1024
    {
        return Err(ApiError::new(
            ErrorCode::QuotaExceeded,
            "command arguments or environment exceed request limits",
        ));
    }
    if command.argv.is_empty()
        || command.argv[0].is_empty()
        || command.argv.iter().any(|s| s.contains('\0'))
    {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "a nonempty executable and NUL-free argv are required",
        ));
    }
    if command.cwd.is_empty() || command.cwd.contains('\0') {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "working directory is required",
        ));
    }
    if command.timeout_seconds == 0 || command.timeout_seconds > 86_400 {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "command timeout must be 1..86400 seconds",
        ));
    }
    if command.max_output_bytes == 0 || command.max_output_bytes > 64 * 1024 * 1024 {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "output limit must be 1..67108864 bytes",
        ));
    }
    if command
        .env
        .iter()
        .any(|(k, v)| k.is_empty() || k.contains(['=', '\0']) || v.contains('\0'))
    {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "invalid environment key or value",
        ));
    }
    Ok(())
}

pub fn request_fingerprint(request: &CreateSandbox) -> Result<String, ApiError> {
    let bytes = serde_json::to_vec(request)
        .map_err(|_| ApiError::new(ErrorCode::Internal, "could not fingerprint request"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn validate_idempotency_key(key: &str) -> Result<(), ApiError> {
    if key.is_empty() || key.len() > 128 || !key.bytes().all(|b| (33..=126).contains(&b)) {
        Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "idempotency key must contain 1..128 visible ASCII bytes",
        ))
    } else {
        Ok(())
    }
}

pub fn validate_artifact(request: &CreateArtifact) -> Result<(), ApiError> {
    if request.path.is_empty()
        || request.path.len() > 4096
        || request.path.contains('\0')
        || request.name.is_empty()
        || request.name.len() > 255
        || matches!(request.name.as_str(), "." | "..")
        || request
            .name
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
    {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "artifact requires a bounded source path and a single display filename",
        ));
    }
    Ok(())
}

pub const MAX_SESSION_CONTROLS: u64 = 1024;
pub const MAX_SESSION_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_SESSION_TOTAL_INPUT_BYTES: usize = 1024 * 1024;

pub fn validate_terminal(size: TerminalSize) -> Result<(), ApiError> {
    if !(1..=1000).contains(&size.rows) || !(1..=1000).contains(&size.columns) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "terminal dimensions must be 1..1000",
        ));
    }
    Ok(())
}

pub fn validate_session(session: &SessionSpec) -> Result<(), ApiError> {
    validate_command(&session.command)?;
    if let Some(size) = session.terminal {
        validate_terminal(size)?;
    }
    Ok(())
}

pub fn validate_code_context(spec: &CodeContextSpec) -> Result<(), ApiError> {
    if spec.cwd.is_empty() || spec.cwd.len() > 4096 || spec.cwd.contains(['\0', '\\']) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "invalid kernel working directory",
        ));
    }
    Ok(())
}

pub fn require_code_language(
    profile: &RuntimeProfile,
    language: CodeLanguage,
) -> Result<(), ApiError> {
    if profile.availability != Availability::Available {
        return Err(ApiError::new(
            ErrorCode::BackendUnavailable,
            "code runtime has no current successful probe",
        ));
    }
    require_capability(profile, Capability::CodeContexts)?;
    if !profile.code_languages.contains(&language) {
        return Err(ApiError::new(
            ErrorCode::UnsupportedCapability,
            "requested language has not passed the runtime kernel probe",
        ));
    }
    Ok(())
}

pub fn validate_code_run(spec: &CodeRunSpec) -> Result<(), ApiError> {
    if spec.code.is_empty() || spec.code.len() > 64 * 1024 || spec.code.contains('\0') {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "code must contain 1..65536 bytes without NUL",
        ));
    }
    if !(1..=3600).contains(&spec.timeout_seconds)
        || !(1..=16 * 1024 * 1024).contains(&spec.max_output_bytes)
    {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "code deadline/output budget exceeds limits",
        ));
    }
    Ok(())
}

/// Returns the charged decoded input size. A control receipt never proves code success.
pub fn validate_session_control(control: &SessionControl) -> Result<usize, ApiError> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    if !(1..=MAX_SESSION_CONTROLS).contains(&control.sequence) {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "session control sequence must be 1..1024",
        ));
    }
    match &control.action {
        SessionAction::Write { data_base64 } => {
            if data_base64.len() > MAX_SESSION_INPUT_BYTES.div_ceil(3) * 4 {
                return Err(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "session input exceeds 64 KiB",
                ));
            }
            let bytes = STANDARD.decode(data_base64).map_err(|_| {
                ApiError::new(ErrorCode::InvalidRequest, "invalid session input encoding")
            })?;
            if bytes.len() > MAX_SESSION_INPUT_BYTES {
                return Err(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "session input exceeds 64 KiB",
                ));
            }
            Ok(bytes.len())
        }
        SessionAction::Resize { size } => {
            validate_terminal(*size)?;
            Ok(0)
        }
        SessionAction::CloseInput => Ok(0),
    }
}
