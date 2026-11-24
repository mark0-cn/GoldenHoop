use chrono::{Duration, Utc};
use goldenhoop_core::*;
use goldenhoop_protocol::*;
use std::collections::BTreeSet;

#[test]
fn code_inputs_and_deadlines_are_bounded_before_delivery() {
    validate_code_context(&CodeContextSpec::default()).unwrap();
    let context = CodeContextSpec {
        cwd: "x\0y".into(),
        ..Default::default()
    };
    assert!(validate_code_context(&context).is_err());
    let mut run = CodeRunSpec::new("x".repeat(64 * 1024));
    validate_code_run(&run).unwrap();
    run.code.push('x');
    assert!(validate_code_run(&run).is_err());
    run.code = "print(42)".into();
    run.timeout_seconds = 0;
    assert!(validate_code_run(&run).is_err());
    run.timeout_seconds = 3600;
    run.max_output_bytes = 16 * 1024 * 1024;
    validate_code_run(&run).unwrap();
    run.max_output_bytes += 1;
    assert!(validate_code_run(&run).is_err());
}

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
        code_languages: Default::default(),
        max_resources: ResourceLimits::default(),
        max_ttl_seconds: 86_400,
        reason: None,
    }
}

#[test]
fn policy_syntax_never_grants_a_backend_capability_and_is_validated_before_admission() {
    let mut observed = profile();
    let mut request = CreateSandbox::new(&observed.id, "cached:test");
    validate_create(&observed, &request).unwrap();
    request.network = NetworkPolicy {
        default_action: NetworkAction::Deny,
        rules: vec![NetworkRule {
            destination: "192.0.2.0/24".into(),
            ports: vec![443],
            action: NetworkAction::Allow,
        }],
    };
    assert_eq!(
        validate_create(&observed, &request).unwrap_err().code,
        ErrorCode::UnsupportedCapability
    );
    // This is an explicitly available model fixture, not a production probe.
    observed.capabilities.insert(Capability::NetworkPolicy);
    validate_create(&observed, &request).unwrap();
    request.network.rules[0].destination = "https://user:private-secret@example.test/path".into();
    let error = validate_create(&observed, &request).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidRequest);
    assert!(!error.message.contains("private-secret"));
    request.network.rules[0].destination = "192.0.2.0/24".into();
    request.network.rules[0].ports = vec![0];
    assert_eq!(
        validate_create(&observed, &request).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
}

#[test]
fn language_names_do_not_grant_unprobed_adapters() {
    assert_eq!(
        serde_json::to_value(CodeLanguage::ALL).unwrap(),
        serde_json::json!(["python", "java", "go", "typescript", "bash", "javascript"])
    );
    assert_eq!(
        serde_json::to_string(&CodeContextSpec::default()).unwrap(),
        r#"{"language":"python","cwd":"/workspace"}"#
    );
    let mut observed = profile();
    assert!(require_code_language(&observed, CodeLanguage::Python).is_err());
    observed.capabilities.insert(Capability::CodeContexts);
    assert_eq!(
        require_code_language(&observed, CodeLanguage::Python)
            .unwrap_err()
            .code,
        ErrorCode::UnsupportedCapability
    );
    observed.code_languages.insert(CodeLanguage::Python);
    require_code_language(&observed, CodeLanguage::Python).unwrap();
    for language in CodeLanguage::ALL
        .into_iter()
        .filter(|language| *language != CodeLanguage::Python)
    {
        assert_eq!(
            require_code_language(&observed, language).unwrap_err().code,
            ErrorCode::UnsupportedCapability
        );
        validate_code_context(&CodeContextSpec {
            language,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(serde_json::to_value(language).unwrap(), language.as_str());
    }
    let mut old = serde_json::to_value(&observed).unwrap();
    old.as_object_mut().unwrap().remove("code_languages");
    let unknown: RuntimeProfile = serde_json::from_value(old).unwrap();
    assert!(unknown.code_languages.is_empty());
    assert!(require_code_language(&unknown, CodeLanguage::Python).is_err());
    observed.availability = Availability::Unverified;
    assert_eq!(
        require_code_language(&observed, CodeLanguage::Python)
            .unwrap_err()
            .code,
        ErrorCode::BackendUnavailable
    );
}
fn request() -> CreateSandbox {
    serde_json::from_str(r#"{"profile":"docker-gvisor","image":"test@sha256:abc"}"#).unwrap()
}

#[test]
fn absent_child_controls_preserve_existing_create_fingerprints() {
    let legacy = r#"{"profile":"docker-gvisor","image":"test@sha256:abc","resources":{"cpu_millis":1000,"memory_bytes":1073741824,"pids":256},"ttl_seconds":1800,"required_capabilities":[],"network":{"default_action":"deny","rules":[]},"metadata":{}}"#;
    let decoded: CreateSandbox = serde_json::from_str(legacy).unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), legacy);
    assert!(decoded.child_budget.is_none() && decoded.feature_limit.is_none());
    assert_eq!(
        request_fingerprint(&decoded).unwrap(),
        request_fingerprint(&request()).unwrap()
    );
}

#[test]
fn child_reservations_require_capability_and_charge_the_complete_envelope() {
    let mut p = profile();
    p.max_resources = ResourceLimits {
        cpu_millis: 4000,
        memory_bytes: 4 * 1024 * 1024 * 1024,
        pids: 1024,
    };
    let mut r = request();
    r.child_budget = Some(ResourceLimits::default());
    assert_eq!(
        validate_create(&p, &r).unwrap_err().code,
        ErrorCode::UnsupportedCapability
    );
    p.capabilities.insert(Capability::IsolatedSessions);
    validate_create(&p, &r).unwrap();
    assert_eq!(
        allocation_envelope(&r.resources, r.child_budget.as_ref()).unwrap(),
        ResourceLimits {
            cpu_millis: 2000,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            pids: 512
        }
    );
    r.child_budget.as_mut().unwrap().cpu_millis = 4000;
    assert_eq!(
        validate_create(&p, &r).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    r.child_budget.as_mut().unwrap().cpu_millis = 0;
    assert_eq!(
        validate_create(&p, &r).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    for (own, child) in [
        (
            ResourceLimits {
                cpu_millis: u32::MAX,
                memory_bytes: 1,
                pids: 1,
            },
            ResourceLimits {
                cpu_millis: 1,
                memory_bytes: 1,
                pids: 1,
            },
        ),
        (
            ResourceLimits {
                cpu_millis: 1,
                memory_bytes: u64::MAX,
                pids: 1,
            },
            ResourceLimits {
                cpu_millis: 1,
                memory_bytes: 1,
                pids: 1,
            },
        ),
        (
            ResourceLimits {
                cpu_millis: 1,
                memory_bytes: 1,
                pids: u32::MAX,
            },
            ResourceLimits {
                cpu_millis: 1,
                memory_bytes: 1,
                pids: 1,
            },
        ),
    ] {
        assert_eq!(
            allocation_envelope(&own, Some(&child)).unwrap_err().code,
            ErrorCode::QuotaExceeded
        );
    }
}

#[test]
fn feature_ceiling_does_not_grant_unsupported_features_or_remove_network_isolation() {
    let mut p = profile();
    p.capabilities.insert(Capability::IsolatedSessions);
    let mut r = request();
    r.feature_limit = Some(BTreeSet::from([Capability::Files]));
    r.required_capabilities.insert(Capability::Commands);
    assert_eq!(
        validate_create(&p, &r).unwrap_err().code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        require_feature(&p, r.feature_limit.as_ref(), Capability::MemorySnapshot)
            .unwrap_err()
            .code,
        ErrorCode::UnsupportedCapability
    );
    r.required_capabilities.clear();
    validate_create(&p, &r).unwrap();
    p.capabilities.remove(&Capability::NetworkIsolation);
    assert_eq!(
        validate_create(&p, &r).unwrap_err().code,
        ErrorCode::UnsupportedCapability
    );
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
