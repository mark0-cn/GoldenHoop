use std::{io, process::Stdio};

use goldenhoop_protocol::TerminalSize;
use tokio::process::{Child, Command};

use super::{WORKLOAD_UID, terminal::Pty};

pub(super) fn spawn(
    command: &mut Command,
    terminal: Option<TerminalSize>,
    interactive: bool,
) -> io::Result<(Child, Option<Pty>)> {
    let pty = if let Some(size) = terminal {
        let (master, slave) = Pty::open(size)?;
        command
            .stdin(slave.try_clone()?)
            .stdout(slave.try_clone()?)
            .stderr(slave);
        command.env("TERM", "xterm-256color");
        Some(master)
    } else {
        command.stdin(if interactive {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        None
    };
    let has_terminal = pty.is_some();
    // SAFETY: the child hook calls only async-signal-safe libc functions, without allocation.
    unsafe {
        command.pre_exec(move || {
            if has_terminal && (libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1) {
                return Err(io::Error::last_os_error());
            }
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgid(WORKLOAD_UID) != 0 || libc::setuid(WORKLOAD_UID) != 0 {
                return Err(io::Error::last_os_error());
            }
            libc::umask(0o002);
            Ok(())
        });
    }
    Ok((command.spawn()?, pty))
}
