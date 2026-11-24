use goldenhoop_protocol::*;

#[test]
fn creation_defaults_deny_network_and_bound_resources() {
    let request: CreateSandbox =
        serde_json::from_str(r#"{"profile":"docker-gvisor","image":"python:3.12-slim"}"#).unwrap();
    assert_eq!(request.network, NetworkPolicy::default());
    assert_eq!(request.resources, ResourceLimits::default());
    assert_eq!(request.ttl_seconds, 1_800);
    assert!(
        serde_json::from_str::<CreateSandbox>(r#"{"profile":"x","image":"y","privileged":true}"#)
            .is_err()
    );
}

#[test]
fn command_uses_literal_argv_and_no_implicit_shell() {
    let command: CommandSpec =
        serde_json::from_str(r#"{"argv":["echo","$(touch /tmp/not-executed)",""]}"#).unwrap();
    assert_eq!(command.argv[1], "$(touch /tmp/not-executed)");
    assert_eq!(command.argv[2], "");
    assert_eq!(command.cwd, "/workspace");
    assert_eq!(command.timeout_seconds, 300);
    assert!(command.env.is_empty());
}

#[test]
fn unknown_is_not_a_terminal_execution_result() {
    assert!(!ExecutionState::Unknown.is_terminal());
    assert!(!ExecutionState::Pending.is_terminal());
    assert!(!ExecutionState::Running.is_terminal());
    for state in [
        ExecutionState::Succeeded,
        ExecutionState::Failed,
        ExecutionState::Cancelled,
        ExecutionState::TimedOut,
    ] {
        assert!(state.is_terminal());
    }
}

#[test]
fn error_wire_format_is_stable_and_redacted_by_design() {
    let value = serde_json::to_value(ApiError::new(
        ErrorCode::UnsupportedCapability,
        "memory_snapshot is unavailable",
    ))
    .unwrap();
    assert_eq!(value["code"], "unsupported_capability");
    assert_eq!(value["retryable"], false);
    assert_eq!(value.as_object().unwrap().len(), 4);
}

#[test]
fn snapshot_kinds_do_not_conflate_memory_with_filesystem() {
    assert_eq!(
        serde_json::to_string(&SnapshotKind::Rootfs).unwrap(),
        r#""rootfs""#
    );
    assert_ne!(SnapshotKind::Rootfs, SnapshotKind::MemoryAndDisk);
}

#[test]
fn code_context_contract_does_not_accept_host_identities_or_claim_process_exit() {
    let spec: CodeContextSpec = serde_json::from_str("{}").unwrap();
    assert_eq!(spec.language, CodeLanguage::Python);
    assert_eq!(spec.cwd, "/workspace");
    for value in [
        r#"{"uid":0}"#,
        r#"{"language":"python","connection_url":"tcp://host"}"#,
    ] {
        assert!(serde_json::from_str::<CodeContextSpec>(value).is_err());
    }
    assert!(serde_json::from_str::<ExecutionState>(r#""kernel_succeeded""#).is_err());
    assert!(!CodeRunState::Unknown.is_terminal());
    assert!(CodeRunState::KernelFailed.is_terminal());
}
