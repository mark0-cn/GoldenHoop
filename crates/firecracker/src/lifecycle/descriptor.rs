//! Exactly one descriptor in a private, already authenticated Unix exchange.
//! Callers finish the JSON acknowledgement before sending this byte, so an
//! ordinary buffered read cannot consume and discard its ancillary data.
use std::{
    fs::File,
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};
use tokio::{io::Interest, net::UnixStream};

const TAG: u8 = 0x47;
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "expected one complete private image descriptor",
    )
}
fn send_once(socket: RawFd, file: RawFd) -> io::Result<()> {
    let mut byte = TAG;
    let mut vector = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
    // SAFETY: the aligned control array has room for this header and one FD;
    // the borrowed source descriptor remains live throughout sendmsg.
    let written = unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as usize;
        libc::CMSG_DATA(header)
            .cast::<RawFd>()
            .write_unaligned(file);
        libc::sendmsg(socket, &message, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
    };
    match written {
        1 => Ok(()),
        -1 => Err(io::Error::last_os_error()),
        _ => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "private descriptor byte was not sent",
        )),
    }
}

fn receive_once(socket: RawFd) -> io::Result<File> {
    let mut byte = 0u8;
    let mut vector = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = mem::size_of_val(&control);
    // MSG_CMSG_CLOEXEC installs received descriptors atomically with CLOEXEC.
    let count = unsafe {
        libc::recvmsg(
            socket,
            &mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut files = Vec::<OwnedFd>::new();
    let mut malformed = message.msg_controllen > mem::size_of_val(&control);
    // Even on truncation or a bad tag, adopt and drop every FD delivered by the
    // kernel. Linux closes SCM_RIGHTS entries that did not fit the control area.
    let end = control.as_ptr() as usize + message.msg_controllen.min(mem::size_of_val(&control));
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let start = header as usize;
        let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
        if start < control.as_ptr() as usize || start.checked_add(minimum).is_none_or(|n| n > end) {
            malformed = true;
            break;
        }
        let size = unsafe { (*header).cmsg_len };
        if size < minimum || start.checked_add(size).is_none_or(|n| n > end) {
            malformed = true;
            break;
        }
        let accepted = unsafe {
            (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS
        };
        if accepted {
            let length = size - minimum;
            malformed |= !length.is_multiple_of(mem::size_of::<RawFd>());
            for index in 0..length / mem::size_of::<RawFd>() {
                // SAFETY: these entries fit the kernel-returned aligned control
                // buffer; each SCM_RIGHTS entry is a newly installed owned FD.
                let descriptor = unsafe {
                    libc::CMSG_DATA(header)
                        .cast::<RawFd>()
                        .add(index)
                        .read_unaligned()
                };
                if descriptor < 0 {
                    malformed = true;
                } else {
                    files.push(unsafe { OwnedFd::from_raw_fd(descriptor) });
                }
            }
        } else {
            malformed = true;
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    if count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "private image peer closed",
        ));
    }
    if malformed
        || count != 1
        || byte != TAG
        || files.len() != 1
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
    {
        return Err(invalid());
    }
    Ok(File::from(files.pop().expect("one received descriptor")))
}

pub(super) async fn send(stream: &UnixStream, file: &File) -> io::Result<()> {
    loop {
        match stream
            .async_io(Interest::WRITABLE, || {
                send_once(stream.as_raw_fd(), file.as_raw_fd())
            })
            .await
        {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            result => return result,
        }
    }
}
pub(super) async fn receive(stream: &UnixStream) -> io::Result<File> {
    loop {
        match stream
            .async_io(Interest::READABLE, || receive_once(stream.as_raw_fd()))
            .await
        {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests;
