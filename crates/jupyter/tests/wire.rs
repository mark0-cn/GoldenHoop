use goldenhoop_jupyter::*;
use serde_json::json;
use uuid::Uuid;

fn codec() -> Codec {
    Codec::new(b"0123456789abcdefghijklmnopqrstuv".to_vec(), Uuid::new_v4()).unwrap()
}
fn independent_fixture() -> Vec<Vec<u8>> {
    // Signature generated independently using Python stdlib hmac/SHA-256.
    vec![b"topic".to_vec(),DELIMITER.to_vec(),b"38cb4066553aecf6cafdea27684e11bced92bf35704760e4ed600bf67a4a41d1".to_vec(),
        br#"{ "msg_id": "msg_17", "session":"kernel_epoch", "msg_type":"execute_reply", "version":"5.3" }"#.to_vec(),
        br#"{"msg_id":"request-1"}"#.to_vec(),b"{}".to_vec(),br#"{"status":"ok", "execution_count":1}"#.to_vec()]
}
#[test]
fn original_frame_authentication_matches_independent_vector_and_preserves_ids() {
    let message = codec().decode(&independent_fixture()).unwrap();
    assert_eq!(message.message_type(), "execute_reply");
    assert_eq!(message.message_id(), "msg_17");
    assert_eq!(message.kernel_session(), "kernel_epoch");
    assert_eq!(message.parent_id(), Some("request-1"));
    assert_eq!(message.content()["status"], "ok");
}
#[test]
fn tampered_unsigned_and_wrong_key_messages_are_refused_without_payload_errors() {
    let mut frames = independent_fixture();
    frames[6] = br#"{"status":"error"}"#.to_vec();
    assert_eq!(codec().decode(&frames).unwrap_err(), Error::Authentication);
    frames = independent_fixture();
    frames[2].clear();
    assert_eq!(codec().decode(&frames).unwrap_err(), Error::Authentication);
    let wrong = Codec::new(vec![42; 32], Uuid::new_v4()).unwrap();
    assert_eq!(
        wrong.decode(&independent_fixture()).unwrap_err(),
        Error::Authentication
    );
    assert!(!Error::Authentication.to_string().contains("status"));
}
#[test]
fn request_limits_and_signature_scope_are_explicit() {
    let codec = codec();
    let frames = codec
        .request(Uuid::new_v4(), "kernel_info_request", json!({}))
        .unwrap();
    assert_eq!(
        codec.decode(&frames).unwrap().message_type(),
        "kernel_info_request"
    );
    assert!(matches!(
        codec.request(Uuid::nil(), "execute_request", json!({})),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        codec.request(
            Uuid::new_v4(),
            "execute_request",
            json!({"code":"x".repeat(MAX_JSON_BYTES)})
        ),
        Err(Error::Limits)
    ));
    assert_eq!(
        codec.decode(&vec![vec![]; MAX_FRAMES + 1]).unwrap_err(),
        Error::Limits
    );
    assert_eq!(
        codec.decode(&[vec![0; MAX_MESSAGE_BYTES + 1]]).unwrap_err(),
        Error::Limits
    );
    let mut routed = independent_fixture();
    routed[0] = b"other routing identity".to_vec();
    routed.push(b"unsigned binary buffer".to_vec());
    assert_eq!(
        codec.decode(&routed).unwrap().buffers(),
        [b"unsigned binary buffer".to_vec()]
    );
    assert!(matches!(
        Codec::new(vec![], Uuid::new_v4()),
        Err(Error::Malformed)
    ));
}

fn legacy_starting(omitted: bool) -> Vec<Vec<u8>> {
    // Independent Python stdlib HMAC/SHA-256 vectors for the old Java
    // Message(null, PublishStatus.STARTING) envelope, not a readiness reply.
    let (header, signature) = if omitted {
        (
            r#"{"msg_id":"startup-message","username":"kernel","msg_type":"status","version":"5.3"}"#,
            "1864796ff1c21baa4ac4b52e86c3989a49d956c98a1444621a328f89c8fed098",
        )
    } else {
        (
            r#"{"msg_id":"startup-message","username":"kernel","msg_type":"status","version":"5.3","session":null}"#,
            "62627c025511cb4df2e1b2708b693aa3067d19a9803b7991f3a11773b5907020",
        )
    };
    vec![
        b"kernel.status".to_vec(),
        DELIMITER.to_vec(),
        signature.as_bytes().to_vec(),
        header.as_bytes().to_vec(),
        b"{}".to_vec(),
        b"{}".to_vec(),
        br#"{"execution_state":"starting"}"#.to_vec(),
    ]
}

fn resign(frames: &mut [Vec<u8>]) {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac =
        Hmac::<sha2_11::Sha256>::new_from_slice(b"0123456789abcdefghijklmnopqrstuv").unwrap();
    for frame in &frames[3..7] {
        mac.update(frame);
    }
    frames[2] = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .into_bytes();
}

#[test]
fn authenticated_legacy_startup_is_a_notice_only_and_never_an_identity_or_reply() {
    for omitted in [false, true] {
        let frames = legacy_starting(omitted);
        assert_eq!(
            codec().decode(&frames).unwrap_err(),
            Error::Header("session")
        );
        assert!(codec().decode_startup(&frames).unwrap().is_none());
    }
    let message = codec()
        .decode_startup(&independent_fixture())
        .unwrap()
        .unwrap();
    assert_eq!(message.kernel_session(), "kernel_epoch");
    assert_eq!(message.parent_id(), Some("request-1"));
}

#[test]
fn startup_notice_compatibility_keeps_authentication_and_framing_requirements() {
    let mut frames = legacy_starting(false);
    frames[2][0] ^= 1;
    assert_eq!(
        codec().decode_startup(&frames).unwrap_err(),
        Error::Authentication
    );
    let mut frames = legacy_starting(false);
    frames.push(b"unsigned buffer".to_vec());
    assert!(codec().decode_startup(&frames).is_err());
    let mut frames = legacy_starting(false);
    frames[4] = b"null".to_vec();
    resign(&mut frames);
    assert_eq!(
        codec().decode_startup(&frames).unwrap_err(),
        Error::Malformed
    );
}

#[test]
fn unscoped_correlated_other_state_and_other_protocol_messages_are_not_ignored() {
    for state in ["idle", "busy", "unknown"] {
        let mut frames = legacy_starting(false);
        frames[6] = serde_json::to_vec(&json!({"execution_state":state})).unwrap();
        resign(&mut frames);
        assert!(codec().decode_startup(&frames).is_err());
    }
    for (field, value) in [
        ("version", json!("5.4")),
        ("msg_type", json!("execute_reply")),
        ("session", json!("")),
        ("username", json!("other")),
        ("msg_id", json!("")),
    ] {
        let mut frames = legacy_starting(false);
        let mut header: serde_json::Value = serde_json::from_slice(&frames[3]).unwrap();
        header[field] = value;
        frames[3] = serde_json::to_vec(&header).unwrap();
        resign(&mut frames);
        assert!(codec().decode_startup(&frames).is_err(), "{field}");
    }
    for (index, value) in [
        (4, json!({"msg_id":"request-1"})),
        (5, json!({"extra":true})),
        (6, json!({"execution_state":"starting","extra":true})),
    ] {
        let mut frames = legacy_starting(false);
        frames[index] = serde_json::to_vec(&value).unwrap();
        resign(&mut frames);
        assert!(codec().decode_startup(&frames).is_err());
    }
}
