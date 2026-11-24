use chrono::{Duration, Utc};
use goldenhoop_core::*;
use goldenhoop_protocol::*;
use std::collections::BTreeSet;

fn profile() -> RuntimeProfile {
    RuntimeProfile {
        id: "docker-gvisor".into(),
        placement: Placement::Local,
        isolation: Isolation::Gvisor,
        availability: Availability::Available,
        capabilities: BTreeSet::from([
            Capability::Commands,
            Capability::Files,
            Capability::NetworkIsolation,
        ]),
        max_resources: ResourceLimits::default(),
        max_ttl_seconds: 86_400,
        reason: None,
    }
}
fn request() -> CreateSandbox {
    serde_json::from_str(r#"{"profile":"docker-gvisor","image":"test@sha256:abc"}"#).unwrap()
}

#[test]
fn no_runtime_fallback_for_unavailable_or_unverified_profiles() {
    for state in [Availability::Unavailable, Availability::Unverified] {
        let mut p = profile();
        p.availability = state;
        assert_eq!(
            validate_create(&p, &request()).unwrap_err().code,
            ErrorCode::BackendUnavailable
        );
    }
}
#[test]
fn denied_network_is_required_and_allow_rules_need_real_policy_support() {
    let mut p = profile();
    let mut r = request();
    assert!(validate_create(&p, &r).is_ok());
    r.network.default_action = NetworkAction::Allow;
    assert_eq!(
        validate_create(&p, &r).unwrap_err().code,
        ErrorCode::UnsupportedCapability
    );
    r.network = NetworkPolicy::default();
    p.capabilities.remove(&Capability::NetworkIsolation);
    assert_eq!(
        validate_create(&p, &r).unwrap_err().code,
        ErrorCode::UnsupportedCapability
    );
}
#[test]
fn unsupported_memory_snapshot_is_rejected_before_provisioning() {
    let mut r = request();
    r.required_capabilities.insert(Capability::MemorySnapshot);
    assert_eq!(
        validate_create(&profile(), &r).unwrap_err().code,
        ErrorCode::UnsupportedCapability
    );
}
#[test]
fn resource_and_ttl_limits_are_enforced() {
    let p = profile();
    let mut r = request();
    r.resources.memory_bytes += 1;
    assert_eq!(
        validate_create(&p, &r).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    r = request();
    r.resources.cpu_millis = 0;
    assert_eq!(
        validate_create(&p, &r).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    r = request();
    r.ttl_seconds = 0;
    assert!(validate_create(&p, &r).is_err());
    r.ttl_seconds = p.max_ttl_seconds + 1;
    assert!(validate_create(&p, &r).is_err());
}
#[test]
fn terminal_sandboxes_cannot_silently_resume_and_pause_has_explicit_states() {
    use SandboxState::*;
    assert_eq!(transition(Running, Pausing).unwrap(), Pausing);
    assert_eq!(transition(Pausing, Paused).unwrap(), Paused);
    assert!(transition(Paused, Running).is_err());
    assert_eq!(transition(Paused, Resuming).unwrap(), Resuming);
    assert_eq!(transition(Resuming, Running).unwrap(), Running);
    assert!(transition(Terminated, Running).is_err());
    assert!(transition(Failed, Resuming).is_err());
    assert!(transition(Stopping, Running).is_err());
}
#[test]
fn paused_and_unknown_sandboxes_still_expire_at_absolute_deadline() {
    let now = Utc::now();
    for state in [SandboxState::Paused, SandboxState::Unknown] {
        let s = Sandbox {
            id: uuid_placeholder(),
            profile: "docker-gvisor".into(),
            image: "image".into(),
            state,
            desired_state: DesiredState::Running,
            cleanup: CleanupState::Unknown,
            created_at: now - Duration::seconds(30),
            expires_at: now,
            observed_at: None,
            resources: ResourceLimits::default(),
            metadata: Default::default(),
            reason: None,
        };
        assert!(expired(&s, now));
        assert!(!expired(&s, now - Duration::milliseconds(1)));
        assert_ne!(s.cleanup, CleanupState::Complete);
    }
}
fn uuid_placeholder() -> uuid::Uuid {
    uuid::Uuid::nil()
}

#[test]
fn oversized_control_requests_are_rejected_before_runtime_or_storage() {
    let mut create = request();
    create
        .metadata
        .insert("large".into(), "x".repeat(16 * 1024 + 1));
    assert_eq!(
        validate_create(&profile(), &create).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    let command =
        serde_json::from_value(serde_json::json!({"argv":["printf", "x".repeat(128 * 1024 + 1)]}))
            .unwrap();
    assert_eq!(
        validate_command(&command).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
}
#[test]
fn idempotency_distinguishes_resources_and_has_bounded_keys() {
    let r = request();
    let mut changed = r.clone();
    changed.resources.pids -= 1;
    assert_ne!(
        request_fingerprint(&r).unwrap(),
        request_fingerprint(&changed).unwrap()
    );
    assert_eq!(
        request_fingerprint(&r).unwrap(),
        request_fingerprint(&r.clone()).unwrap()
    );
    for invalid in ["", "space here", "newline\n", "密钥"] {
        assert!(validate_idempotency_key(invalid).is_err());
    }
    assert!(validate_idempotency_key(&"a".repeat(129)).is_err());
    assert!(validate_idempotency_key("task-1:attempt-1").is_ok());
}
#[test]
fn malformed_commands_are_rejected_without_invoking_a_shell() {
    let mut c: CommandSpec = serde_json::from_str(r#"{"argv":["echo",""]}"#).unwrap();
    assert!(validate_command(&c).is_ok());
    c.argv = vec![];
    assert!(validate_command(&c).is_err());
    c.argv = vec!["echo".into()];
    c.env.insert("BAD=KEY".into(), "value".into());
    assert!(validate_command(&c).is_err());
}
#[test]
fn interactive_validation_bounds_input_sequence_and_terminal() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut session = SessionSpec::shell();
    validate_session(&session).unwrap();
    session.terminal = Some(TerminalSize {
        rows: 0,
        columns: 80,
    });
    assert_eq!(
        validate_session(&session).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    session.terminal = Some(TerminalSize {
        rows: 1000,
        columns: 1000,
    });
    validate_session(&session).unwrap();
    let mut control = SessionControl {
        sequence: 1,
        action: SessionAction::Write {
            data_base64: STANDARD.encode(vec![0; MAX_SESSION_INPUT_BYTES]),
        },
    };
    assert_eq!(
        validate_session_control(&control).unwrap(),
        MAX_SESSION_INPUT_BYTES
    );
    control.action = SessionAction::Write {
        data_base64: STANDARD.encode(vec![0; MAX_SESSION_INPUT_BYTES + 1]),
    };
    assert_eq!(
        validate_session_control(&control).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    control.action = SessionAction::Write {
        data_base64: "?".into(),
    };
    assert_eq!(
        validate_session_control(&control).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    control.sequence = 0;
    control.action = SessionAction::CloseInput;
    assert_eq!(
        validate_session_control(&control).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    control.sequence = MAX_SESSION_CONTROLS + 1;
    assert_eq!(
        validate_session_control(&control).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
}
