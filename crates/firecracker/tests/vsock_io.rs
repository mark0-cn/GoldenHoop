//! Actual nonblocking sockets validate the generic fd/framing component; real
//! AF_VSOCK guest/host authority still requires the jailed microVM gate.
#![cfg(target_os = "linux")]

use goldenhoop_firecracker::vsock::*;
use std::{io, os::fd::OwnedFd, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

fn pair() -> (SocketStream, SocketStream) {
    let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
    a.set_nonblocking(true).unwrap();
    b.set_nonblocking(true).unwrap();
    (
        SocketStream::new(OwnedFd::from(a)).unwrap(),
        SocketStream::new(OwnedFd::from(b)).unwrap(),
    )
}

#[test]
fn acknowledgement_is_canonical_assigned_host_port_not_requested_guest_port() {
    assert_eq!(parse_connect_ack(b"OK 1073741824\n").unwrap(), 1073741824);
    for bytes in [
        b"OK 0\n".as_slice(),
        b"OK 01\n",
        b"OK +52\n",
        b"OK 52\r\n",
        b"OK 4294967295\n",
        b"OK 4294967296\n",
        b"FAIL 52\n",
        b"OK 52",
        b"OK 52\nextra",
    ] {
        assert!(parse_connect_ack(bytes).is_err(), "{bytes:?}");
    }
}

#[tokio::test]
async fn readiness_handles_split_frames_and_full_duplex_without_losing_buffered_bytes() {
    let (mut a, b) = pair();
    let mut b = BufReader::new(b);
    let writing = tokio::spawn(async move {
        a.write_all(b"OK 10").await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        a.write_all(b"73741824\n{\"status\":\"success\"}\n")
            .await
            .unwrap();
        let mut reply = [0; 4];
        a.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ack\n");
    });
    let ack = read_frame(&mut b, 32).await.unwrap();
    assert_eq!(parse_connect_ack(&ack).unwrap(), 1073741824);
    assert_eq!(
        read_frame(&mut b, 64).await.unwrap(),
        b"{\"status\":\"success\"}\n"
    );
    b.get_mut().write_all(b"ack\n").await.unwrap();
    writing.await.unwrap();
}

#[tokio::test]
async fn incomplete_eof_and_oversize_never_become_control_replies() {
    for (bytes, limit, kind) in [
        (b"unterminated".as_slice(), 32, io::ErrorKind::UnexpectedEof),
        (b"12345\n".as_slice(), 5, io::ErrorKind::InvalidData),
    ] {
        let (mut a, b) = pair();
        a.write_all(bytes).await.unwrap();
        a.shutdown().await.unwrap();
        assert_eq!(
            read_frame(&mut BufReader::new(b), limit)
                .await
                .unwrap_err()
                .kind(),
            kind
        );
    }
    let (a, mut b) = pair();
    drop(a);
    assert!(b.write_all(b"closed peer").await.is_err());
}

#[tokio::test]
async fn blocking_and_non_socket_fds_are_rejected_without_replacing_the_transport() {
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    assert!(SocketStream::new(OwnedFd::from(a)).is_err());
    let file = std::fs::File::open("/dev/null").unwrap();
    assert!(SocketStream::new(OwnedFd::from(file)).is_err());
    let (_a, b) = pair();
    let mut reader = BufReader::new(b);
    assert_eq!(
        read_frame(&mut reader, usize::MAX)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(GuestControlListener::bind(0).is_err());
    assert!(GuestControlListener::bind(1024).is_err());
}
