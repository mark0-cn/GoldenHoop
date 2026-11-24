use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    sync::Arc,
};

use goldenhoop_protocol::TerminalSize;
use tokio::io::unix::AsyncFd;

#[derive(Clone)]
pub(super) struct Pty(Arc<AsyncFd<File>>);

impl Pty {
    pub fn open(size: TerminalSize) -> io::Result<(Self, File)> {
        let (mut master, mut slave) = (-1, -1);
        let size = winsize(size);
        // SAFETY: output descriptors and winsize point to valid storage. No name buffer.
        if unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &size,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openpty returned two new, exclusively owned descriptors.
        let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        for file in [&master, &slave] {
            // SAFETY: valid owned descriptor; fcntl does not borrow any pointer.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: the valid master descriptor is made nonblocking before reactor registration.
        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        if flags == -1
            || unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                == -1
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the owned File stays inside this private Arc until deregistration.
        // Its descriptor is never closed, replaced or exposed to external callers.
        let master = unsafe { AsyncFd::register(master) }.map_err(io::Error::from)?;
        Ok((Self(Arc::new(master)), slave))
    }

    pub async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.0.readable().await?;
            match ready.try_io(|fd| {
                let mut file = fd.get_ref();
                file.read(bytes)
            }) {
                // Linux PTY masters report EIO when every slave is closed.
                Ok(Err(error)) if error.raw_os_error() == Some(libc::EIO) => return Ok(0),
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }

    pub async fn write_all(&self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let mut ready = self.0.writable().await?;
            match ready.try_io(|fd| {
                let mut file = fd.get_ref();
                file.write(bytes)
            }) {
                Ok(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(Ok(count)) => bytes = &bytes[count..],
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(error),
                Err(_) => continue,
            }
        }
        Ok(())
    }

    pub fn resize(&self, size: TerminalSize) -> io::Result<()> {
        let size = winsize(size);
        // SAFETY: valid PTY descriptor and pointer to a fully initialized winsize.
        if unsafe { libc::ioctl(self.0.get_ref().as_raw_fd(), libc::TIOCSWINSZ, &size) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn winsize(size: TerminalSize) -> libc::winsize {
    libc::winsize {
        ws_row: size.rows,
        ws_col: size.columns,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}
