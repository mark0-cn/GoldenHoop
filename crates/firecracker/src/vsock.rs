//! Linux virtio-vsock primitives. A guest control listener accepts only host CID2.
//! There is no TCP/Unix replacement for an unavailable AF_VSOCK device.
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    pin::Pin,
    task::{Context, Poll, ready},
};

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf, unix::AsyncFd,
};

pub const HOST_CID: u32 = 2;
pub const MAX_AGENT_FRAME: usize = 24 * 1024 * 1024;

/// A nonblocking stream socket. The caller authenticates its domain/peer before
/// handing it to the protocol; the fd is closed on cancellation and drop.
pub struct SocketStream(AsyncFd<OwnedFd>);

impl SocketStream {
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        let mut kind = 0 as libc::c_int;
        let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
        // SAFETY: the output pointer and length describe the initialized integer.
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut libc::c_int).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if length as usize != std::mem::size_of_val(&kind) || kind != libc::SOCK_STREAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control fd must be a stream socket",
            ));
        }
        // SAFETY: F_GETFL takes a zero value and the borrowed fd remains valid.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL, 0) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_NONBLOCK == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control socket must be nonblocking",
            ));
        }
        // SAFETY: this private wrapper exclusively owns the fd and never exposes
        // a mutable/replacing access; it closes only after AsyncFd deregisters.
        Ok(Self(unsafe { AsyncFd::register(fd) }?))
    }
}

impl AsyncRead for SocketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;
            let outcome = guard.try_io(|fd| {
                let bytes = buffer.initialize_unfilled();
                // SAFETY: the initialized slice is writable for exactly its length.
                let count = unsafe {
                    libc::recv(
                        fd.get_ref().as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        0,
                    )
                };
                if count < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            });
            match outcome {
                Ok(Ok(count)) => {
                    buffer.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => continue,
            }
        }
    }
}

impl AsyncWrite for SocketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            let mut guard = ready!(self.0.poll_write_ready(cx))?;
            match guard.try_io(|fd| {
                // SAFETY: the slice remains readable for the call. Suppress a
                // disconnected peer's SIGPIPE instead of terminating guest init.
                let count = unsafe {
                    libc::send(
                        fd.get_ref().as_raw_fd(),
                        bytes.as_ptr().cast(),
                        bytes.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                if count < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            }) {
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(value) => return Poll::Ready(value),
                Err(_) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // SAFETY: shutdown operates on this owned socket and has no pointer argument.
        let result = unsafe { libc::shutdown(self.0.get_ref().as_raw_fd(), libc::SHUT_WR) };
        if result == 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(io::Error::last_os_error()))
        }
    }
}

pub struct GuestControlListener(AsyncFd<OwnedFd>);

impl GuestControlListener {
    pub fn bind(port: u32) -> io::Result<Self> {
        if port == 0 || port >= 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "guest control requires a reserved port",
            ));
        }
        // SAFETY: these are a valid Linux stream socket domain/type/protocol.
        let raw = unsafe {
            libc::socket(
                libc::AF_VSOCK,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket returned a new descriptor owned only by this scope.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: all-zero padding is valid for sockaddr_vm; set all meaningful fields.
        let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        address.svm_cid = libc::VMADDR_CID_ANY;
        address.svm_port = port;
        // SAFETY: address is initialized and its exact size is supplied.
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_vm).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is an owned bound stream socket.
        if unsafe { libc::listen(fd.as_raw_fd(), 16) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the listener exclusively owns a stable fd until deregistration.
        Ok(Self(unsafe { AsyncFd::register(fd) }?))
    }

    pub async fn accept_host(&self) -> io::Result<SocketStream> {
        loop {
            let mut guard = self.0.readable().await?;
            let accepted = guard.try_io(|listener| {
                // SAFETY: zero padding is valid; accept fills a bounded initialized address.
                let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
                let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
                // SAFETY: pointers refer to writable address/length with the exact capacity.
                let raw = unsafe {
                    libc::accept4(
                        listener.get_ref().as_raw_fd(),
                        (&mut address as *mut libc::sockaddr_vm).cast(),
                        &mut length,
                        libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    )
                };
                if raw < 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: accept4 returned a fresh owned descriptor.
                let fd = unsafe { OwnedFd::from_raw_fd(raw) };
                if length as usize != std::mem::size_of_val(&address)
                    || address.svm_family != libc::AF_VSOCK as libc::sa_family_t
                    || address.svm_cid != HOST_CID
                {
                    return Ok(None);
                }
                SocketStream::new(fd).map(Some)
            });
            match accepted {
                Ok(Ok(Some(stream))) => return Ok(stream),
                Ok(Ok(None)) | Err(_) => continue,
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(error),
            }
        }
    }
}

/// Exactly one LF-terminated frame. A closed/truncated channel is never a reply.
pub async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Vec<u8>> {
    if limit == 0 || limit > MAX_AGENT_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid control frame limit",
        ));
    }
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_until(b'\n', &mut bytes)
        .await?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame exceeds limit",
        ));
    }
    if bytes.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "control frame was not completed",
        ));
    }
    Ok(bytes)
}

pub fn parse_connect_ack(bytes: &[u8]) -> io::Result<u32> {
    let digits = bytes
        .strip_prefix(b"OK ")
        .and_then(|bytes| bytes.strip_suffix(b"\n"))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid vsock acknowledgement")
        })?;
    let text = std::str::from_utf8(digits)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid vsock port"))?;
    let port = text
        .parse::<u32>()
        .ok()
        .filter(|port| *port > 0 && *port != u32::MAX && port.to_string() == text)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid vsock port"))?;
    // This is the assigned HOST port, not an echo of the requested guest port.
    Ok(port)
}
