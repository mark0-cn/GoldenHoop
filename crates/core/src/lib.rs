//! Runtime-independent orchestration invariants.
use chrono::{DateTime, Utc};
use goldenhoop_protocol::*;
use sha2::{Digest, Sha256};

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
    let limits = &request.resources;
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
        require_capability(profile, *required)?;
    }
    require_capability(profile, Capability::NetworkIsolation)?;
    if request.network != NetworkPolicy::default() {
        require_capability(profile, Capability::NetworkPolicy)?;
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
