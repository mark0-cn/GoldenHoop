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
