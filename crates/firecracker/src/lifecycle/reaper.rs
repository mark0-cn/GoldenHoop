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
    // This grants only a descriptor-bound wait, never live RPC or signal
    // authority. An exiting task can release /proc/exe before pidfd readiness;
    // requiring executable metadata here would turn normal exit into failure.
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
    pub(crate) fn exited(&self) -> io::Result<bool> {
        pidfd_exited(&self.fd)
    }
    pub(crate) fn authenticated_live(&self, expected: &ProcessIdentity) -> Result<bool> {
        if self.pid != expected.pid || self.start != expected.start_ticks {
            return Err(invalid("live process differs from its wait target").into());
        }
        if self.exited()? {
            return Ok(false);
        }
        let observed = process_identity(expected.pid);
        if self.exited()? {
            return Ok(false);
        }
        if observed? != *expected {
            return Err(invalid("live reaping identity mismatch").into());
        }
        Ok(true)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn actual_exit_during_recorded_observation_preserves_the_original_reap_target() {
        for _ in 0..128 {
            let mut child = Child(
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap(),
            );
            let identity = process_identity(child.0.id()).unwrap();
            child.0.kill().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            let target = loop {
                let target = recorded(&identity)
                    .expect("the original exit is not a failed metadata authentication")
                    .expect("this owned child is not reaped yet");
                if target.exited().unwrap() {
                    break target;
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::yield_now();
            };
            assert!(
                !process_absent(&identity).unwrap(),
                "a zombie must not be reported physically absent"
            );
            child.0.wait().unwrap();
            assert!(target.collected().unwrap());
            assert!(process_absent(&identity).unwrap());
        }
    }

    #[test]
    fn live_foreign_identity_never_grants_process_authority() {
        let mut child = Child(
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap(),
        );
        let identity = process_identity(child.0.id()).unwrap();
        let target = recorded(&identity).unwrap().unwrap();
        assert!(!target.exited().unwrap());
        assert!(target.authenticated_live(&identity).unwrap());
        for foreign in [
            ProcessIdentity {
                start_ticks: identity.start_ticks + 1,
                ..identity.clone()
            },
            ProcessIdentity {
                executable_sha256: "0".repeat(64),
                ..identity.clone()
            },
            ProcessIdentity {
                uid: identity.uid + 1,
                ..identity.clone()
            },
        ] {
            assert!(
                recorded(&foreign)
                    .and_then(|target| target.unwrap().authenticated_live(&foreign))
                    .is_err()
            );
            assert!(child.0.try_wait().unwrap().is_none());
        }
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(process_absent(&identity).unwrap());
        assert!(recorded(&identity).unwrap().is_none());
    }
}
