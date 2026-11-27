//! Host-only cgroup v2 observations. A Docker configuration or guest virtual
//! cgroup is not resource-enforcement evidence. No workload receives these
//! host paths, descriptors or daemon access.
use crate::hex_id;
use goldenhoop_image_builder::BuilderLimits;
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
use uuid::Uuid;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostObservation {
    pub pid: u32,
    pub start_ticks: u64,
    pub boot_id: Uuid,
    pub process_cgroup: String,
    pub owned_cgroup: String,
    pub limits: BuilderLimits,
}

pub struct HostGuard {
    pub observation: HostObservation,
    pidfd: OwnedFd,
}

fn text(mut file: impl Read) -> io::Result<String> {
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(invalid("host observation exceeds limit"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("non-UTF8 host observation"))
}
fn boot_id() -> io::Result<Uuid> {
    Uuid::parse_str(text(File::open("/proc/sys/kernel/random/boot_id")?)?.trim())
        .map_err(|_| invalid("invalid host boot identity"))
}
fn ticks(pid: u32, require_live: bool) -> io::Result<u64> {
    if pid <= 1 || pid > i32::MAX as u32 {
        return Err(invalid("invalid host builder PID"));
    }
    let raw = text(File::open(format!("/proc/{pid}/stat"))?)?;
    if !raw.starts_with(&format!("{pid} (")) {
        return Err(invalid("host PID identity differs"));
    }
    let fields: Vec<_> = raw
        .rsplit_once(')')
        .ok_or_else(|| invalid("invalid process stat"))?
        .1
        .split_whitespace()
        .collect();
    if fields.len() < 20 || (require_live && ["Z", "X", "x"].contains(&fields[0])) {
        return Err(invalid("builder process is not live"));
    }
    fields[19]
        .parse()
        .map_err(|_| invalid("invalid process start time"))
}
fn placement(pid: u32) -> io::Result<String> {
    let raw = text(File::open(format!("/proc/{pid}/cgroup"))?)?;
    let mut lines = raw.lines();
    let value = lines
        .next()
        .and_then(|v| v.strip_prefix("0::"))
        .ok_or_else(|| invalid("unified host cgroup placement required"))?;
    if lines.next().is_some() {
        return Err(invalid("mixed host cgroup hierarchy"));
    }
    Ok(value.into())
}
fn components<'a>(path: &'a str, id: &str) -> io::Result<(Vec<&'a str>, usize)> {
    if !hex_id(id) {
        return Err(invalid("invalid immutable container ID"));
    }
    let parts: Vec<_> = path
        .strip_prefix('/')
        .ok_or_else(|| invalid("invalid host cgroup path"))?
        .split('/')
        .collect();
    if parts.is_empty()
        || parts.len() > 32
        || parts.iter().any(|v| {
            v.is_empty()
                || *v == "."
                || *v == ".."
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
    {
        return Err(invalid("noncanonical host cgroup path"));
    }
    let scoped = format!("docker-{id}.scope");
    let named = format!("docker-{id}");
    let owned = parts
        .iter()
        .position(|v| *v == id || *v == scoped || *v == named)
        .ok_or_else(|| invalid("builder PID is outside its immutable container cgroup"))?;
    Ok((parts, owned))
}
fn trusted(file: &File, directory: bool) -> io::Result<()> {
    let m = file.metadata()?;
    if m.uid() != 0
        || m.mode() & 0o022 != 0
        || (directory && !m.is_dir())
        || (!directory && !m.is_file())
    {
        return Err(invalid("host cgroup ownership or file type differs"));
    }
    Ok(())
}
fn child(parent: &File, name: &str, directory: bool) -> io::Result<File> {
    let name = CString::new(name).map_err(|_| invalid("invalid cgroup component"))?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | if directory { libc::O_DIRECTORY } else { 0 },
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(raw) };
    trusted(&file, directory)?;
    Ok(file)
}
fn optional(parent: &File, name: &str) -> io::Result<Option<String>> {
    match child(parent, name, false) {
        Ok(f) => text(f).map(Some),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
fn number(value: &str) -> io::Result<Option<u64>> {
    if value.trim() == "max" {
        Ok(None)
    } else {
        value
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| invalid("invalid host cgroup limit"))
    }
}
fn minimum(target: &mut Option<u64>, value: Option<u64>) {
    if let Some(value) = value {
        *target = Some(target.map_or(value, |old| old.min(value)));
    }
}
fn limits(parts: &[&str]) -> io::Result<BuilderLimits> {
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/sys/fs/cgroup")?;
    trusted(&directory, true)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if i128::from(stat.f_type) != i128::from(libc::CGROUP2_SUPER_MAGIC) {
        return Err(invalid("host enforcement is not cgroup v2"));
    }
    let (mut memory, mut swap, mut pids, mut cpu) = (None, None, None, None::<(u64, u64)>);
    // Nested sentry cgroups can inherit enforcement from a container ancestor.
    // Keep the tightest finite value through the complete trusted hierarchy.
    for part in parts {
        directory = child(&directory, part, true)?;
        for (name, target) in [
            ("memory.max", &mut memory),
            ("memory.swap.max", &mut swap),
            ("pids.max", &mut pids),
        ] {
            if let Some(value) = optional(&directory, name)? {
                minimum(target, number(&value)?);
            }
        }
        if let Some(raw) = optional(&directory, "cpu.max")? {
            let fields: Vec<_> = raw.split_whitespace().collect();
            if fields.len() != 2 {
                return Err(invalid("invalid host CPU limit"));
            }
            let period = fields[1]
                .parse::<u64>()
                .map_err(|_| invalid("invalid host CPU period"))?;
            if period == 0 {
                return Err(invalid("zero host CPU period"));
            }
            if let Some(quota) = number(fields[0])?
                && cpu.is_none_or(|(q, p)| {
                    u128::from(quota) * u128::from(p) < u128::from(q) * u128::from(period)
                })
            {
                cpu = Some((quota, period));
            }
        }
    }
    let (cpu_quota, cpu_period) = cpu.ok_or_else(|| invalid("host CPU is unbounded"))?;
    let result = BuilderLimits {
        memory_max: memory.ok_or_else(|| invalid("host memory is unbounded"))?,
        swap_max: swap.ok_or_else(|| invalid("host swap is unbounded"))?,
        pids_max: pids.ok_or_else(|| invalid("host tasks are unbounded"))?,
        cpu_quota,
        cpu_period,
    };
    result.validate()?;
    Ok(result)
}
impl HostGuard {
    pub fn observe(container_id: &str, pid: u32, maximum: &BuilderLimits) -> io::Result<Self> {
        maximum.validate()?;
        let start_ticks = ticks(pid, true)?;
        let boot_id = boot_id()?;
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let process_cgroup = placement(pid)?;
        let (parts, owned) = components(&process_cgroup, container_id)?;
        let limits = limits(&parts)?;
        if limits.memory_max > maximum.memory_max
            || limits.swap_max > maximum.swap_max
            || limits.pids_max > maximum.pids_max
            || u128::from(limits.cpu_quota) * u128::from(maximum.cpu_period)
                > u128::from(maximum.cpu_quota) * u128::from(limits.cpu_period)
        {
            return Err(invalid("actual host limits exceed the pinned build budget"));
        }
        let owned_cgroup = format!("/{}", parts[..=owned].join("/"));
        let guard = Self {
            observation: HostObservation {
                pid,
                start_ticks,
                boot_id,
                process_cgroup,
                owned_cgroup,
                limits,
            },
            pidfd,
        };
        guard.still_live()?;
        Ok(guard)
    }
    pub fn still_live(&self) -> io::Result<()> {
        let value = &self.observation;
        let mut event = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let polled = unsafe { libc::poll(&mut event, 1, 0) };
        if polled < 0 {
            return Err(io::Error::last_os_error());
        }
        if polled != 0
            || boot_id()? != value.boot_id
            || ticks(value.pid, true)? != value.start_ticks
            || placement(value.pid)? != value.process_cgroup
        {
            return Err(invalid(
                "host builder identity changed before authorization",
            ));
        }
        Ok(())
    }
}
impl HostObservation {
    /// Exit notification alone is insufficient: the old PID (including a
    /// zombie) and the complete immutable container cgroup must be absent.
    pub fn collected(&self, container_id: &str) -> io::Result<bool> {
        let (parts, owned) = components(&self.process_cgroup, container_id)?;
        if self.owned_cgroup != format!("/{}", parts[..=owned].join("/"))
            || boot_id()? != self.boot_id
        {
            return Err(invalid("host cleanup identity differs"));
        }
        let old_absent = match ticks(self.pid, false) {
            Ok(value) => value != self.start_ticks,
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(e) => return Err(e),
        };
        let group = Path::new("/sys/fs/cgroup").join(self.owned_cgroup.trim_start_matches('/'));
        let group_absent = match fs::symlink_metadata(group) {
            Ok(_) => false,
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(e) => return Err(e),
        };
        Ok(old_absent && group_absent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cgroup_paths_cannot_authorize_foreign_partial_or_escaping_container_ids() {
        let id = "a".repeat(64);
        assert_eq!(
            components(&format!("/system.slice/docker-{id}.scope/sentry"), &id)
                .unwrap()
                .1,
            1
        );
        for path in [
            format!("/other/{id}x"),
            format!("/../{id}"),
            format!("/{id}//child"),
            format!("/{id}/./child"),
            format!("/prefix-{id}/child"),
            format!("/{id}/x\n"),
        ] {
            assert!(components(&path, &id).is_err(), "{path}");
        }
        assert!(components(&format!("/{id}"), "short").is_err());
    }
}
