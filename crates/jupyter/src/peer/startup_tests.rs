//! Independent small ZMTP server: exercise the production handshake's channels,
//! correlation, epoch and post-readiness boundary deterministically.
use super::*;
use hmac::{Hmac, KeyInit, Mac};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

const KEY: &[u8] = b"0123456789abcdefghijklmnopqrstuv";

async fn frame(stream: &mut UnixStream, flags: u8, bytes: &[u8]) {
    if bytes.len() > 255 {
        stream.write_all(&[flags | 2]).await.unwrap();
        stream
            .write_all(&(bytes.len() as u64).to_be_bytes())
            .await
            .unwrap();
    } else {
        stream.write_all(&[flags, bytes.len() as u8]).await.unwrap();
    }
    stream.write_all(bytes).await.unwrap();
}

async fn read_frame(stream: &mut UnixStream) -> (u8, Vec<u8>) {
    let flags = stream.read_u8().await.unwrap();
    let length = if flags & 2 == 0 {
        u64::from(stream.read_u8().await.unwrap())
    } else {
        stream.read_u64().await.unwrap()
    };
    assert!(length <= 65536);
    let mut bytes = vec![0; length as usize];
    stream.read_exact(&mut bytes).await.unwrap();
    (flags, bytes)
}

async fn accept(listener: UnixListener, role: &[u8]) -> UnixStream {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut greeting = [0u8; 64];
    stream.read_exact(&mut greeting).await.unwrap();
    greeting.fill(0);
    greeting[0] = 0xff;
    greeting[9] = 0x7f;
    greeting[10] = 3;
    greeting[12..16].copy_from_slice(b"NULL");
    stream.write_all(&greeting).await.unwrap();
    let (flags, command) = read_frame(&mut stream).await;
    assert_eq!(flags, 4);
    assert!(command.starts_with(b"\x05READY"));
    let mut reply = b"\x05READY\x0bSocket-Type".to_vec();
    reply.extend_from_slice(&(role.len() as u32).to_be_bytes());
    reply.extend_from_slice(role);
    frame(&mut stream, 4, &reply).await;
    if role == b"PUB" {
        let (flags, subscription) = read_frame(&mut stream).await;
        assert_eq!((flags, subscription), (0, vec![1]));
    }
    stream
}

async fn connected() -> (tempfile::TempDir, Peer, UnixStream, UnixStream) {
    let directory = tempfile::tempdir().unwrap();
    let prefix = directory.path().join("kernel");
    let output = UnixListener::bind(IpcNaming::Dash.path(&prefix, 2)).unwrap();
    let shell = UnixListener::bind(IpcNaming::Dash.path(&prefix, 1)).unwrap();
    let output = tokio::spawn(accept(output, b"PUB"));
    let shell = tokio::spawn(accept(shell, b"ROUTER"));
    // SAFETY: getuid has no pointers or mutation; this test owns both listeners.
    let uid = unsafe { libc::getuid() };
    let peer = tokio::time::timeout(
        Duration::from_secs(2),
        Peer::connect(&prefix, uid, KEY.to_vec()),
    )
    .await
    .unwrap()
    .unwrap();
    (directory, peer, shell.await.unwrap(), output.await.unwrap())
}

async fn write_message(stream: &mut UnixStream, parts: &[Vec<u8>]) {
    for (index, part) in parts.iter().enumerate() {
        frame(stream, u8::from(index + 1 < parts.len()), part).await;
    }
}

fn startup() -> Vec<Vec<u8>> {
    // Independently signed old Java startup publication (Python stdlib HMAC).
    vec![b"kernel.status".to_vec(),crate::DELIMITER.to_vec(),
        b"62627c025511cb4df2e1b2708b693aa3067d19a9803b7991f3a11773b5907020".to_vec(),
        br#"{"msg_id":"startup-message","username":"kernel","msg_type":"status","version":"5.3","session":null}"#.to_vec(),
        b"{}".to_vec(),b"{}".to_vec(),br#"{"execution_state":"starting"}"#.to_vec()]
}

async fn request_id(stream: &mut UnixStream) -> String {
    let mut parts = Vec::new();
    loop {
        let (flags, part) = read_frame(stream).await;
        assert_eq!(flags & 4, 0);
        parts.push(part);
        if flags & 1 == 0 {
            break;
        }
        assert!(parts.len() < 16);
    }
    let header: Value = serde_json::from_slice(&parts[2]).unwrap();
    assert_eq!(header["msg_type"], "kernel_info_request");
    header["msg_id"].as_str().unwrap().to_owned()
}

fn response(epoch: Uuid, parent: &str, kind: &str, content: Value) -> Vec<Vec<u8>> {
    let values = [
        json!({"msg_id":Uuid::new_v4(),"session":epoch,"msg_type":kind,"version":"5.3"}),
        json!({"msg_id":parent}),
        json!({}),
        content,
    ];
    let parts: Vec<Vec<u8>> = values
        .iter()
        .map(|value| serde_json::to_vec(value).unwrap())
        .collect();
    let mut mac = Hmac::<sha2_11::Sha256>::new_from_slice(KEY).unwrap();
    for part in &parts {
        mac.update(part);
    }
    let signature = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    [
        vec![crate::DELIMITER.to_vec(), signature.into_bytes()],
        parts,
    ]
    .concat()
}

#[tokio::test]
async fn startup_neither_establishes_readiness_nor_epoch_and_is_strict_after_readiness() {
    let (directory, mut peer, mut shell, mut output) = connected().await;
    let task = tokio::spawn(async move {
        let result = peer.ready().await;
        (peer, result)
    });
    let parent = request_id(&mut shell).await;
    write_message(&mut output, &startup()).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!task.is_finished(), "a startup notice is not readiness");
    let epoch = Uuid::new_v4();
    write_message(
        &mut shell,
        &response(
            epoch,
            &parent,
            "kernel_info_reply",
            json!({"protocol_version":"5.3","status":"ok"}),
        ),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !task.is_finished(),
        "shell info still needs matching output idle"
    );
    write_message(
        &mut output,
        &response(epoch, &parent, "status", json!({"execution_state":"idle"})),
    )
    .await;
    let (mut peer, info) = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(info.unwrap()["protocol_version"], "5.3");
    assert_eq!(peer.epoch.as_deref(), Some(epoch.to_string().as_str()));
    write_message(&mut output, &startup()).await;
    let error = tokio::time::timeout(Duration::from_secs(1), peer.next())
        .await
        .unwrap()
        .err()
        .unwrap();
    assert!(error.to_string().contains("header field session"));
    drop((peer, shell, output));
    directory.close().unwrap();
}

#[tokio::test]
async fn startup_publications_are_bounded_and_never_accepted_on_the_shell_channel() {
    for on_shell in [false, true] {
        let (directory, mut peer, mut shell, mut output) = connected().await;
        let task = tokio::spawn(async move {
            let result = peer.ready().await;
            (peer, result)
        });
        let _ = request_id(&mut shell).await;
        if on_shell {
            write_message(&mut shell, &startup()).await;
        } else {
            for _ in 0..9 {
                write_message(&mut output, &startup()).await;
            }
        }
        let (peer, result) = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        let error = result.unwrap_err().to_string();
        assert!(error.contains(if on_shell {
            "header field session"
        } else {
            "too many unscoped"
        }));
        assert!(
            peer.epoch.is_none(),
            "unscoped notices must not bind an epoch"
        );
        drop((peer, shell, output));
        directory.close().unwrap();
    }
}
