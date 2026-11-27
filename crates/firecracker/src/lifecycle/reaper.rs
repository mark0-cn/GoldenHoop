//! Descriptor-bound waits never consume a different child after PID reuse.
use super::*;

pub(crate) struct Target {
    pid: u32,
    start: u64,
    fd: OwnedFd,
}
fn stat(pid: u32) -> io::Result<(u32, u64)> {
    let text = std::fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat"))?;
    let fields: Vec<_> = text
        .rsplit_once(')')
        .ok_or_else(|| invalid("invalid process stat"))?
        .1
        .split_whitespace()
        .collect();
    Ok((
        fields
            .get(1)
            .ok_or_else(|| invalid("missing process parent"))?
            .parse()
            .map_err(|_| invalid("invalid process parent"))?,
        fields
            .get(19)
            .ok_or_else(|| invalid("missing process start"))?
            .parse()
            .map_err(|_| invalid("invalid process start"))?,
    ))
}
/// Read-only absence of the original identity, including PID reuse. Unlike a
/// pidfd signal/reap target this never grants authority over the replacement.
pub(crate) fn process_absent(expected: &ProcessIdentity) -> Result<bool> {
    if expected.pid <= 1 || expected.pid > i32::MAX as u32 || expected.start_ticks == 0 {
        return Err(invalid("invalid original process identity").into());
    }
    if expected.boot_id != boot_id()? {
        return Ok(true);
    }
    match stat(expected.pid) {
        Ok((_, ticks)) => Ok(ticks != expected.start_ticks),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}
fn open(pid: u32) -> io::Result<Option<OwnedFd>> {
    if pid <= 1 || pid > i32::MAX as u32 {
        return Err(invalid("invalid reaping PID"));
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(None);
        }
        return Err(error);
    }
    Ok(Some(unsafe { OwnedFd::from_raw_fd(fd as i32) }))
}
pub(crate) fn recorded(expected: &ProcessIdentity) -> Result<Option<Target>> {
    if expected.boot_id != boot_id()? {
        return Ok(None);
    }
    let Some(fd) = open(expected.pid)? else {
        return Ok(None);
    };
    let (_, start) = match stat(expected.pid) {
        Ok(value) => value,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if start != expected.start_ticks {
        return Err(invalid("recorded reaping identity changed").into());
    }
    if !pidfd_exited(&fd)? && process_identity(expected.pid)? != *expected {
        return Err(invalid("live reaping identity mismatch").into());
    }
    Ok(Some(Target {
        pid: expected.pid,
        start,
        fd,
    }))
}
pub(crate) fn group_child(
    pid: u32,
    group: Option<&Path>,
    direct_child: bool,
) -> Result<Option<Target>> {
    let Some(fd) = open(pid)? else {
        return Ok(None);
    };
    let (parent, start) = match stat(pid) {
        Ok(value) => value,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let member = if let Some(group) = group {
        let expected = format!(
            "0::/{}",
            group
                .file_name()
                .ok_or_else(|| invalid("missing owned cgroup name"))?
                .to_string_lossy()
        );
        std::fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("cgroup"))?
            .lines()
            .any(|line| line == expected)
    } else {
        false
    };
    if !member && !(direct_child && parent == std::process::id()) {
        return Err(invalid("reaping candidate is outside owned generation").into());
    }
    if stat(pid)?.1 != start {
        return Err(invalid("reaping process changed during observation").into());
    }
    Ok(Some(Target { pid, start, fd }))
}
impl Target {
    pub(crate) fn collected(&self) -> io::Result<bool> {
        let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.fd.as_raw_fd() as libc::id_t,
                &mut information,
                libc::WEXITED | libc::WNOHANG,
            )
        };
        if result == 0 && unsafe { information.si_pid() } != 0 {
            return Ok(true);
        }
        if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ECHILD) {
            return Err(io::Error::last_os_error());
        }
        if !pidfd_exited(&self.fd)? {
            return Ok(false);
        }
        // An exited nonchild can still be an unreaped zombie. Its actual
        // parent must reap it before process absence is accepted.
        match stat(self.pid) {
            Ok((_, start)) => Ok(start != self.start),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(e) => Err(e),
        }
    }
}
