use super::*;
use std::{
    io::{Read, Seek, Write},
    os::unix::fs::MetadataExt,
};

fn references(metadata: &std::fs::Metadata) -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| std::fs::metadata(entry.ok()?.path()).ok())
        .filter(|value| value.dev() == metadata.dev() && value.ino() == metadata.ino())
        .count()
}
fn send_many(stream: &UnixStream, file: &File, count: usize, tag: u8) {
    let mut tag = tag;
    let mut vector = libc::iovec {
        iov_base: (&mut tag as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 32];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen =
        unsafe { libc::CMSG_SPACE((count * mem::size_of::<RawFd>()) as u32) } as usize;
    assert!(message.msg_controllen <= mem::size_of_val(&control));
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN((count * mem::size_of::<RawFd>()) as u32) as usize;
        for index in 0..count {
            libc::CMSG_DATA(header)
                .cast::<RawFd>()
                .add(index)
                .write_unaligned(file.as_raw_fd());
        }
        assert_eq!(
            libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
            1
        );
    }
}

#[tokio::test]
async fn actual_rights_transfer_keeps_the_file_and_atomically_sets_cloexec() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let mut source = tempfile::tempfile().unwrap();
    source
        .write_all(b"independent kernel file authority")
        .unwrap();
    source.rewind().unwrap();
    let metadata = source.metadata().unwrap();
    send(&sender, &source).await.unwrap();
    let mut received = receive(&receiver).await.unwrap();
    assert_eq!(
        unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        libc::FD_CLOEXEC
    );
    drop(source);
    let mut bytes = Vec::new();
    received.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"independent kernel file authority");
    assert_eq!(references(&metadata), 1);
    drop(received);
    assert_eq!(references(&metadata), 0);
}

#[tokio::test]
async fn actual_extra_truncated_or_bad_tag_rights_are_all_closed() {
    let source = tempfile::tempfile().unwrap();
    let metadata = source.metadata().unwrap();
    for (count, tag) in [(2, TAG), (32, TAG), (1, 0x12)] {
        let (sender, receiver) = UnixStream::pair().unwrap();
        send_many(&sender, &source, count, tag);
        assert_eq!(
            receive(&receiver).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            references(&metadata),
            1,
            "received rights leaked: {count}/{tag}"
        );
    }
}

#[tokio::test]
async fn byte_without_rights_or_eof_is_not_a_descriptor_handoff() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    sender.writable().await.unwrap();
    assert_eq!(sender.try_write(&[TAG]).unwrap(), 1);
    assert_eq!(
        receive(&receiver).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    drop(sender);
    assert_eq!(
        receive(&receiver).await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}
