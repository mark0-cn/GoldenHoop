#![cfg(target_os = "linux")]
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn invoke(bytes: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_goldenhoop-egress"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn incomplete_or_oversized_control_is_terminal_and_invalid_json_is_redacted() {
    for bytes in [
        b"{\"id\":1,\"command\":{\"operation\":\"inspect\"}}".to_vec(),
        vec![b'x'; 256 * 1024 + 1],
    ] {
        let result = invoke(&bytes);
        assert!(!result.status.success());
        let response: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(response["id"], serde_json::Value::Null);
        assert_eq!(response["error"]["code"], "invalid_request");
        assert!(result.stdout.len() < 1024);
    }
    let result=invoke(b"{\"id\":1,\"untrusted-input-must-not-be-echoed\":true}\n{\"id\":2,\"command\":{\"operation\":\"inspect\"}}\n");
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(!text.contains("untrusted-input-must-not-be-echoed"));
    let replies = text
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0]["error"]["code"], "invalid_request");
    assert_eq!(replies[1]["id"], 2);
    assert_eq!(replies[1]["error"]["code"], "invalid_state");
}
