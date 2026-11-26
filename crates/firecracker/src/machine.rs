//! Owned, jailed hardware bootstrap. This private gate is deliberately separate
//! from public driver capability registration and snapshot/restore acceptance.
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use goldenhoop_protocol::{
    AgentRequest, AgentResponse, CleanupState, CommandSpec, EventKind, ExecutionState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncReadExt, process::Child, task::JoinHandle};
use uuid::Uuid;

use crate::{
    agent::AgentClient,
    api::{ApiClient, PeerIdentity},
    kvm::{KvmState, probe_kvm},
    lifecycle::{DriverConfig, MIB, VmJournal, atomic_json},
    models::*,
};

const VMM_UID: u32 = 10000;
const MAX_LOG: usize = 64 * 1024;
const BOOT_ARGS: &str =
    "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/sbin/goldenhoop-init";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootInput {
    pub firecracker: Artifact,
    pub jailer: Artifact,
    pub kernel: Artifact,
    pub rootfs: Artifact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessObservation {
    pub pid: u32,
    pub start_ticks: u64,
    pub boot_id: String,
    pub executable_sha256: String,
    pub uid: u32,
    pub namespace_pid: u32,
    pub namespace_isolated: bool,
    pub network_namespace_isolated: bool,
    pub no_new_privileges: bool,
    pub effective_capabilities: String,
    pub seccomp_mode: u32,
}

#[derive(Debug, Serialize)]
pub struct GuestReport {
    pub generation: Uuid,
    pub passed: bool,
    pub guest_started: bool,
    pub checks: Vec<String>,
    pub process: Option<ProcessObservation>,
    pub cleanup: CleanupState,
    pub root_absent: bool,
    pub cgroup_absent: bool,
    pub vmm_reaped: bool,
    pub error: Option<String>,
    pub console: String,
    pub console_truncated: bool,
    pub runtime_profile_published: bool,
}

impl GuestReport {
    pub(crate) fn empty(generation: Uuid) -> Self {
        Self {
            generation,
            passed: false,
            guest_started: false,
            checks: Vec::new(),
            process: None,
            cleanup: CleanupState::Unknown,
            root_absent: false,
            cgroup_absent: false,
            vmm_reaped: false,
            error: None,
            console: String::new(),
            console_truncated: false,
            runtime_profile_published: false,
        }
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type ConsoleTask = JoinHandle<io::Result<(Vec<u8>, bool)>>;

pub(crate) fn trusted_file(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid("artifact path is not absolute"));
    }
    // Every ancestor is trusted as well: O_NOFOLLOW on the final component alone
    // cannot protect against an unprivileged replacement of an ancestor.
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(invalid(
                "artifact ancestor is not root-owned and private from writers",
            ));
        }
        ancestor = directory.parent();
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(invalid("artifact is not a trusted regular file"));
    }
    Ok(file)
}

pub(crate) fn digest(mut input: impl Read) -> io::Result<(String, u64)> {
    let mut hash = Sha256::new();
    let mut count = 0;
    let mut buffer = [0; 65536];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        count += read as u64;
    }
    Ok((format!("{:x}", hash.finalize()), count))
}

fn copy_artifact(artifact: &Artifact, destination: &Path, mode: u32) -> io::Result<()> {
    if artifact.sha256.len() != 64
        || !artifact
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || artifact.size == 0
        || artifact.size > 16 * 1024 * 1024 * 1024
    {
        return Err(invalid("invalid artifact digest or length"));
    }
    let mut input = trusted_file(&artifact.path)?;
    if input.metadata()?.len() != artifact.size {
        return Err(invalid("artifact length mismatch"));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(destination)?;
    let mut hash = Sha256::new();
    let mut count = 0;
    let mut buffer = [0; 65536];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > artifact.size {
            return Err(invalid("artifact changed while copying"));
        }
        hash.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    if count != artifact.size || format!("{:x}", hash.finalize()) != artifact.sha256 {
        return Err(invalid("artifact digest mismatch"));
    }
    output.sync_all()?;
    if digest(File::open(destination)?)? != (artifact.sha256.clone(), artifact.size) {
        return Err(invalid("copied artifact digest mismatch"));
    }
    Ok(())
}

pub(crate) struct Machine {
    pub(crate) generation: Uuid,
    pub(crate) root: PathBuf,
    pub(crate) jail: PathBuf,
    cgroup: PathBuf,
    owned_root: bool,
    owned_cgroup: bool,
    launcher: Option<Child>,
    launcher_pid: Option<u32>,
    pidfd: Option<OwnedFd>,
    candidate_pid: Option<u32>,
    pub(crate) process: Option<ProcessObservation>,
    console: Option<ConsoleTask>,
    persistent: Option<(PathBuf, VmJournal)>,
    resources: goldenhoop_protocol::ResourceLimits,
    recovered: bool,
}

impl Machine {
    fn new() -> Self {
        let generation = Uuid::new_v4();
        let name = format!("ghv-{}", &generation.simple().to_string()[..8]);
        // Guest disks belong on persistent host storage, not the small /run tmpfs.
        let root = Path::new("/var/lib").join(&name);
        let jail = root
            .join("j/firecracker")
            .join(generation.to_string())
            .join("root");
        Self {
            generation,
            jail,
            root,
            cgroup: Path::new("/sys/fs/cgroup").join(name),
            owned_root: false,
            owned_cgroup: false,
            launcher: None,
            launcher_pid: None,
            pidfd: None,
            candidate_pid: None,
            process: None,
            console: None,
            persistent: None,
            resources: goldenhoop_protocol::ResourceLimits {
                cpu_millis: 1000,
                memory_bytes: 256 * MIB,
                pids: 256,
            },
            recovered: false,
        }
    }

    pub(crate) fn persistent(cfg: &DriverConfig, journal: VmJournal) -> Result<Self> {
        let paths = cfg.paths(journal.owner.generation)?;
        let mut machine = Self::new();
        machine.generation = journal.owner.generation;
        machine.root = paths.root;
        machine.jail = paths.jail;
        machine.cgroup = paths.vm_cgroup;
        machine.resources = journal.resources.clone();
        machine.persistent = Some((cfg.record_path(journal.owner.sandbox_id), journal));
        Ok(machine)
    }

    pub(crate) fn record(&self) -> &VmJournal {
        &self.persistent.as_ref().expect("persistent machine").1
    }
    pub(crate) fn record_error(&mut self, message: String) -> Result<()> {
        let (_, record) = self.persistent.as_mut().expect("persistent machine");
        record.error = Some(message);
        self.set_phase("unknown")
    }

    pub(crate) fn record_console(&mut self, text: &str) -> Result<()> {
        let (_, record) = self.persistent.as_mut().expect("persistent machine");
        let mut start = text.len().saturating_sub(16 * 1024);
        while !text.is_char_boundary(start) {
            start += 1;
        }
        record.console_tail = text[start..].into();
        let phase = record.phase.clone();
        self.set_phase(&phase)
    }

    pub(crate) fn recover(cfg: &DriverConfig, journal: VmJournal) -> Result<Self> {
        let mut machine = Self::persistent(cfg, journal)?;
        machine.recovered = true;
        if machine.root.try_exists()? {
            let metadata = std::fs::symlink_metadata(&machine.root)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
                return Err(invalid("recovered VM root ownership mismatch").into());
            }
            let marker: serde_json::Value =
                crate::lifecycle::read_json(&machine.root.join("intent.json"))?;
            if marker["generation"] != machine.generation.to_string()
                || marker["owner"] != serde_json::to_value(&machine.record().owner)?
            {
                return Err(invalid("recovered VM marker mismatch").into());
            }
            machine.owned_root = true;
        }
        if machine.cgroup.try_exists()? {
            if machine.record().owner.host_boot_id != crate::lifecycle::boot_id()? {
                return Err(invalid("stale host boot cannot authorize cgroup collection").into());
            }
            let metadata = std::fs::symlink_metadata(&machine.cgroup)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(invalid("recovered cgroup ownership mismatch").into());
            }
            machine.owned_cgroup = true;
        }
        let pid = if let Some(process) = &machine.record().process {
            Some(process.pid)
        } else if machine.owned_root && machine.jail.join("firecracker.pid").try_exists()? {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(machine.jail.join("firecracker.pid"))?;
            if !file.metadata()?.is_file() || file.metadata()?.len() > 16 {
                return Err(invalid("invalid recovered VMM PID file").into());
            }
            let mut text = String::new();
            file.take(17).read_to_string(&mut text)?;
            if text.is_empty() {
                None
            } else {
                Some(text.parse::<u32>()?)
            }
        } else {
            None
        };
        if let Some(pid) = pid {
            if Path::new("/proc").join(pid.to_string()).try_exists()?
                && machine.record().owner.host_boot_id == crate::lifecycle::boot_id()?
            {
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
                if fd < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                let descriptor = unsafe { OwnedFd::from_raw_fd(fd as i32) };
                let observed =
                    machine.observe(pid, &machine.record().artifacts.firecracker.sha256)?;
                machine.process = Some(observed);
                machine.pidfd = Some(descriptor);
                machine.candidate_pid = Some(pid);
            } else if machine.owned_cgroup
                && !std::fs::read_to_string(machine.cgroup.join("cgroup.events"))?
                    .lines()
                    .any(|line| line == "populated 0")
            {
                return Err(invalid("missing recorded VMM with populated cgroup").into());
            }
        }
        Ok(machine)
    }

    pub(crate) fn api(&self) -> Result<ApiClient> {
        let process = self
            .process
            .as_ref()
            .ok_or_else(|| invalid("VMM process not tracked"))?;
        if self.exited()? {
            return Err(invalid("VMM has exited").into());
        }
        self.observe(process.pid, &self.record().artifacts.firecracker.sha256)?;
        Ok(ApiClient::new(
            self.jail.join("api.sock"),
            PeerIdentity {
                pid: process.pid,
                uid: VMM_UID,
                instance: self.generation,
            },
            Duration::from_secs(3),
        )?)
    }

    pub(crate) fn agent(&self) -> Result<AgentClient> {
        Ok(AgentClient::new(
            self.api()?,
            self.jail.join("vsock.sock"),
            52,
            Duration::from_secs(3),
        )?)
    }

    pub(crate) fn set_phase(&mut self, phase: &str) -> Result<()> {
        let input = self.record().artifacts.clone();
        self.journal(&input, phase)
    }

    pub(crate) fn check_expiry(&self) -> Result<()> {
        if let Some((_, record)) = &self.persistent
            && record.expired()?
        {
            return Err(invalid("native sandbox absolute deadline elapsed").into());
        }
        Ok(())
    }

    fn journal(&mut self, input: &BootInput, phase: &str) -> Result<()> {
        if let Some((path, record)) = &mut self.persistent {
            record.phase = phase.into();
            record.process = self.process.clone();
            record.ever_ready |= phase == "running";
            return atomic_json(path, record);
        }
        let bytes = serde_json::to_vec(
            &serde_json::json!({"format":1,"generation":self.generation,"phase":phase,"artifacts":input,"process":self.process,"cgroup":self.cgroup}),
        )?;
        let pending = self.root.join("intent.pending");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(pending, self.root.join("intent.json"))?;
        Ok(File::open(&self.root)?.sync_all()?)
    }

    fn prepare(&mut self, input: &BootInput) -> Result<()> {
        self.check_expiry()?;
        if unsafe { libc::geteuid() } != 0 || !cfg!(target_arch = "x86_64") {
            return Err(invalid("jailed hardware boot requires Linux x86_64 root").into());
        }
        if probe_kvm().state != KvmState::Ready {
            return Err(invalid("actual KVM prerequisite is unavailable").into());
        }
        let run = std::fs::symlink_metadata("/var/lib")?;
        if !run.is_dir() || run.uid() != 0 || run.mode() & 0o022 != 0 {
            return Err(invalid("untrusted runtime parent").into());
        }
        // Process-local: collect the VMM orphaned when --new-pid-ns jailer exits.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        std::fs::DirBuilder::new().mode(0o700).create(&self.root)?;
        self.owned_root = true;
        self.journal(input, "preparing")?;
        if let Some((_, record)) = &self.persistent {
            atomic_json(
                &self.root.join("intent.json"),
                &serde_json::json!({"generation":self.generation,"owner":record.owner}),
            )?;
        }
        std::fs::create_dir_all(&self.jail)?;
        std::fs::create_dir(self.root.join("bin"))?;
        copy_artifact(
            &input.firecracker,
            &self.root.join("bin/firecracker"),
            0o500,
        )?;
        copy_artifact(&input.jailer, &self.root.join("bin/jailer"), 0o500)?;
        copy_artifact(&input.kernel, &self.jail.join("kernel"), 0o444)?;
        copy_artifact(&input.rootfs, &self.jail.join("rootfs.ext4"), 0o600)?;
        self.check_expiry()?;
        let rootfs = File::open(self.jail.join("rootfs.ext4"))?;
        if unsafe { libc::fchown(rootfs.as_raw_fd(), VMM_UID, VMM_UID) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        std::fs::create_dir(&self.cgroup)?;
        self.owned_cgroup = true;
        let controllers = std::fs::read_to_string(self.cgroup.join("cgroup.controllers"))?;
        for required in ["cpu", "memory", "pids"] {
            if !controllers
                .split_whitespace()
                .any(|value| value == required)
            {
                return Err(invalid(format!("missing delegated {required} controller")).into());
            }
        }
        for (file, value) in [
            (
                "cpu.max",
                format!("{} 100000", u64::from(self.resources.cpu_millis) * 100),
            ),
            (
                "memory.max",
                self.resources
                    .memory_bytes
                    .checked_add(128 * MIB)
                    .ok_or_else(|| invalid("VMM memory envelope overflow"))?
                    .to_string(),
            ),
            ("memory.swap.max", "0".into()),
            ("pids.max", "64".into()),
        ] {
            std::fs::write(self.cgroup.join(file), &value)?;
            if std::fs::read_to_string(self.cgroup.join(file))?.trim() != value {
                return Err(invalid("VMM resource limit readback mismatch").into());
            }
        }
        self.journal(input, "launch_intent")?;
        Ok(())
    }

    async fn launch(&mut self, input: &BootInput) -> Result<ApiClient> {
        self.check_expiry()?;
        let tasks = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.cgroup.join("cgroup.procs"))?;
        let tasks_fd = tasks.as_raw_fd();
        let mut command = tokio::process::Command::new(self.root.join("bin/jailer"));
        command
            .args(["--id", &self.generation.to_string(), "--exec-file"])
            .arg(self.root.join("bin/firecracker"))
            .args([
                "--uid",
                "10000",
                "--gid",
                "10000",
                "--cgroup-version",
                "2",
                "--parent-cgroup",
            ])
            .arg(
                self.cgroup
                    .file_name()
                    .ok_or_else(|| invalid("missing cgroup name"))?,
            )
            .arg("--chroot-base-dir")
            .arg(self.root.join("j"))
            .args([
                "--new-pid-ns",
                "--resource-limit",
                "no-file=256",
                "--resource-limit",
                "fsize=17179869184",
                "--",
                "--api-sock",
                "/api.sock",
            ])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C.UTF-8")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // SAFETY: this Linux syscall changes only the pre-exec child and does
        // not allocate or mutate the multithreaded parent's namespaces.
        unsafe {
            command.pre_exec(move || {
                if libc::write(tasks_fd, b"0".as_ptr().cast(), 1) != 1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::unshare(libc::CLONE_NEWNET) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        self.launcher_pid = child.id();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| invalid("missing VMM console"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| invalid("missing jailer diagnostics"))?;
        self.console = Some(tokio::spawn(async move {
            async fn collect(
                mut input: impl tokio::io::AsyncRead + Unpin,
            ) -> io::Result<(Vec<u8>, bool)> {
                let mut bytes = Vec::new();
                let mut truncated = false;
                let mut buffer = [0; 4096];
                loop {
                    let read = input.read(&mut buffer).await?;
                    if read == 0 {
                        break;
                    }
                    let retain = read.min(MAX_LOG.saturating_sub(bytes.len()));
                    bytes.extend_from_slice(&buffer[..retain]);
                    truncated |= retain < read;
                }
                Ok((bytes, truncated))
            }
            let (a, b) = tokio::try_join!(collect(stdout), collect(stderr))?;
            let mut bytes = a.0;
            bytes.extend_from_slice(&b.0);
            Ok((bytes, a.1 || b.1))
        }));
        self.launcher = Some(child);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            self.check_expiry()?;
            if tokio::time::Instant::now() >= deadline {
                return Err(invalid("jailed VMM identity/readiness deadline").into());
            }
            if let Some(child) = self.launcher.as_mut()
                && let Some(status) = child.try_wait()?
                && !status.success()
            {
                return Err(invalid(format!("jailer exited {status}")).into());
            }
            if self.pidfd.is_none() && self.jail.join("firecracker.pid").try_exists()? {
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(self.jail.join("firecracker.pid"))?;
                let metadata = file.metadata()?;
                if !metadata.is_file() || metadata.len() > 16 {
                    return Err(invalid("invalid jailed PID file").into());
                }
                let mut text = String::new();
                file.take(17).read_to_string(&mut text)?;
                if text.is_empty() {
                    // create_new precedes the jailer's write of its child PID.
                    // An empty observation grants no authority and no new budget.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
                let pid: u32 = text.parse()?;
                if pid <= 1 || pid > i32::MAX as u32 {
                    return Err(invalid("invalid VMM PID").into());
                }
                self.candidate_pid = Some(pid);
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
                if fd < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                let descriptor = unsafe { OwnedFd::from_raw_fd(fd as i32) };
                // PID-file creation precedes the child's credential drop/exec.
                // Never acquire signaling authority from an unauthenticated PID.
                if let Ok(observation) = self.observe(pid, &input.firecracker.sha256) {
                    self.pidfd = Some(descriptor);
                    self.process = Some(observation);
                    self.journal(input, "tracked")?;
                }
            }
            if let Some(process) = &self.process {
                let api = ApiClient::new(
                    self.jail.join("api.sock"),
                    PeerIdentity {
                        pid: process.pid,
                        uid: VMM_UID,
                        instance: self.generation,
                    },
                    Duration::from_secs(3),
                )?;
                if let Ok(info) = api.instance_info().await {
                    if info.state != InstanceState::NotStarted {
                        return Err(invalid("VMM started before configuration").into());
                    }
                    return Ok(api);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(invalid("jailed VMM identity/readiness deadline").into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn observe(&self, pid: u32, expected_digest: &str) -> Result<ProcessObservation> {
        let prefix = Path::new("/proc").join(pid.to_string());
        let stat = std::fs::read_to_string(prefix.join("stat"))?;
        let (_, fields) = stat
            .rsplit_once(')')
            .ok_or_else(|| invalid("invalid process stat"))?;
        let fields: Vec<_> = fields.split_whitespace().collect();
        let start_ticks = fields
            .get(19)
            .ok_or_else(|| invalid("missing process start time"))?
            .parse()?;
        let parent: u32 = fields
            .get(1)
            .ok_or_else(|| invalid("missing process parent"))?
            .parse()?;
        if !self.recovered && parent != std::process::id() && Some(parent) != self.launcher_pid {
            return Err(invalid("foreign VMM parent").into());
        }
        let executable_sha256 = digest(File::open(prefix.join("exe"))?)?.0;
        if executable_sha256 != expected_digest {
            return Err(invalid("VMM executable digest mismatch").into());
        }
        let status = std::fs::read_to_string(prefix.join("status"))?;
        let field = |name: &str| -> Result<&str> {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
                .ok_or_else(|| invalid("missing process status field").into())
        };
        let uids: Vec<_> = field("Uid:")?.split_whitespace().collect();
        if uids != ["10000", "10000", "10000", "10000"] {
            return Err(invalid("VMM did not drop all host UIDs").into());
        }
        let namespace_pid = field("NSpid:")?
            .split_whitespace()
            .last()
            .ok_or_else(|| invalid("missing namespace PID"))?
            .parse()?;
        let namespace_isolated =
            std::fs::read_link(prefix.join("ns/pid"))? != std::fs::read_link("/proc/self/ns/pid")?;
        if namespace_pid != 1 || !namespace_isolated {
            return Err(invalid("VMM lacks its own PID1 namespace").into());
        }
        let network_namespace_isolated =
            std::fs::read_link(prefix.join("ns/net"))? != std::fs::read_link("/proc/self/ns/net")?;
        if !network_namespace_isolated {
            return Err(invalid("VMM lacks a private network namespace").into());
        }
        let command = std::fs::read(prefix.join("cmdline"))?;
        let args: Vec<_> = command.split(|b| *b == 0).collect();
        let id = self.generation.to_string();
        if !args
            .windows(2)
            .any(|pair| pair[0] == b"--id" && pair[1] == id.as_bytes())
        {
            return Err(invalid("VMM process generation mismatch").into());
        }
        let cgroup = std::fs::read_to_string(prefix.join("cgroup"))?;
        let expected = format!(
            "0::/{}",
            self.cgroup
                .file_name()
                .ok_or_else(|| invalid("missing cgroup"))?
                .to_string_lossy()
        );
        if !cgroup.lines().any(|line| line == expected) {
            return Err(invalid("VMM escaped its owned cgroup").into());
        }
        let result = ProcessObservation {
            pid,
            start_ticks,
            boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .to_owned(),
            executable_sha256,
            uid: VMM_UID,
            namespace_pid,
            namespace_isolated,
            network_namespace_isolated,
            no_new_privileges: field("NoNewPrivs:")? == "1",
            effective_capabilities: field("CapEff:")?.to_owned(),
            seccomp_mode: field("Seccomp:")?.parse()?,
        };
        if let Some((_, journal)) = &self.persistent {
            if result.boot_id != journal.owner.host_boot_id {
                return Err(invalid("VMM host boot identity mismatch").into());
            }
            if let Some(expected) = &journal.process
                && (expected.pid != result.pid
                    || expected.start_ticks != result.start_ticks
                    || expected.executable_sha256 != result.executable_sha256)
            {
                return Err(invalid("VMM durable process identity mismatch").into());
            }
        }
        let after = std::fs::read_to_string(prefix.join("stat"))?;
        if after
            .rsplit_once(')')
            .and_then(|(_, v)| v.split_whitespace().nth(19))
            .and_then(|v| v.parse::<u64>().ok())
            != Some(start_ticks)
        {
            return Err(invalid("VMM process changed during authentication").into());
        }
        Ok(result)
    }

    pub(crate) async fn start(&mut self, input: &BootInput) -> Result<AgentClient> {
        self.prepare(input)?;
        let api = self.launch(input).await?;
        api.configure_machine(&MachineConfiguration::new(
            self.resources.cpu_millis.div_ceil(1000) as u8,
            self.resources.memory_bytes / MIB,
        )?)
        .await?;
        let args = if self.persistent.is_some() {
            format!(
                "{BOOT_ARGS} goldenhoop.pids={} goldenhoop.generation={}",
                self.resources.pids, self.generation
            )
        } else {
            BOOT_ARGS.into()
        };
        api.configure_boot(&BootSource::new("/kernel".into(), args)?)
            .await?;
        api.configure_root(&RootDrive::new("/rootfs.ext4".into(), false)?)
            .await?;
        api.configure_vsock(&Vsock::new(3, "/vsock.sock".into())?)
            .await?;
        api.start().await?;
        let agent = AgentClient::new(
            api.clone(),
            self.jail.join("vsock.sock"),
            52,
            Duration::from_secs(3),
        )?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            self.check_expiry()?;
            if let Ok(reply) = agent.rpc_reply(&AgentRequest::Ping).await {
                if matches!(reply.into_result()?, AgentResponse::Pong{version} if version==env!("CARGO_PKG_VERSION"))
                    && (self.persistent.is_none()
                        || agent
                            .control_info()
                            .await
                            .is_ok_and(|info| info.pids == self.resources.pids))
                {
                    break;
                }
                return Err(invalid("guest version mismatch").into());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(invalid("actual guest agent boot deadline").into());
            }
            if self.exited()? {
                return Err(invalid("VMM exited before guest readiness").into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let pid = self
            .process
            .as_ref()
            .ok_or_else(|| invalid("missing tracked process"))?
            .pid;
        let observation = self.observe(pid, &input.firecracker.sha256)?;
        if !observation.no_new_privileges
            || observation.effective_capabilities != "0000000000000000"
            || observation.seccomp_mode != 2
        {
            return Err(invalid("VMM host privilege/seccomp constraints are absent").into());
        }
        self.process = Some(observation);
        self.journal(
            input,
            if self.persistent.is_some() {
                "running"
            } else {
                "guest_ready"
            },
        )?;
        Ok(agent)
    }

    async fn run(&mut self, input: &BootInput, report: &mut GuestReport) -> Result<()> {
        let agent = self.start(input).await?;
        report.guest_started = true;
        report.checks.extend([
            "bounded_digest_verified_artifact_copies".into(),
            "actual_guest_ping_over_authenticated_vsock".into(),
        ]);
        report
            .checks
            .push("jailed_uid_pid_namespace_cgroup_seccomp_observed".into());
        let nonce = Uuid::new_v4().to_string();
        let data = STANDARD.encode(nonce.as_bytes());
        rpc(
            &agent,
            AgentRequest::WriteFile {
                path: "m4-roundtrip.txt".into(),
                data_base64: data.clone(),
            },
        )
        .await?;
        if !matches!(rpc(&agent,AgentRequest::ReadFile { path:"m4-roundtrip.txt".into(),max_bytes:1024 }).await?,AgentResponse::File{data_base64} if data_base64==data)
        {
            return Err(invalid("guest file roundtrip mismatch").into());
        }
        rpc(
            &agent,
            AgentRequest::RemoveFile {
                path: "m4-roundtrip.txt".into(),
            },
        )
        .await?;
        report
            .checks
            .push("guest_file_write_read_remove_nonce".into());
        let id = Uuid::new_v4();
        let script = format!(
            "import os,json,socket\ns=open('/proc/self/status').read()\nassert os.getuid()==1000 and os.getgid()==1000\nassert next(x.split(':',1)[1].strip() for x in s.splitlines() if x.startswith('NoNewPrivs:'))=='1'\nassert next(x.split(':',1)[1].strip() for x in s.splitlines() if x.startswith('CapEff:'))=='0000000000000000'\nassert open('/sys/fs/cgroup/goldenhoop/pids.max').read().strip()=='256'\nassert sorted(os.listdir('/sys/class/net'))==['lo']\nassert not any(k in os.environ for k in ['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','GITHUB_TOKEN','GH_TOKEN'])\nassert not os.path.exists('/var/run/docker.sock')\ntry:\n x=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM); x.bind((socket.VMADDR_CID_ANY,53))\nexcept PermissionError: pass\nelse: raise AssertionError('unprivileged reserved vsock bind')\nprint({nonce:?},flush=True)\n"
        );
        let mut command = CommandSpec::new(["python3", "-c", &script]);
        command.timeout_seconds = 15;
        command.max_output_bytes = 4096;
        if !matches!(rpc(&agent,AgentRequest::Start{id,command}).await?,AgentResponse::Execution(value) if value.id==id)
        {
            return Err(invalid("guest execution acknowledgement mismatch").into());
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        loop {
            let AgentResponse::Execution(execution) =
                rpc(&agent, AgentRequest::Inspect { id }).await?
            else {
                return Err(invalid("guest execution inspect shape").into());
            };
            if execution.state.is_terminal() {
                if execution.state != ExecutionState::Succeeded
                    || execution.exit_code != Some(0)
                    || execution.cleanup != CleanupState::Complete
                {
                    return Err(invalid(format!(
                        "guest command or descendant cleanup failed: {:?}",
                        execution
                    ))
                    .into());
                }
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(invalid("guest execution deadline").into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let AgentResponse::Events(events) =
            rpc(&agent, AgentRequest::Events { id, after: 0 }).await?
        else {
            return Err(invalid("guest event shape").into());
        };
        let mut stdout = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.kind == EventKind::Stdout)
        {
            if event.execution_id != id || event.data["encoding"] != "base64" {
                return Err(invalid("guest stdout identity or encoding mismatch").into());
            }
            stdout.extend(
                STANDARD.decode(
                    event.data["data"]
                        .as_str()
                        .ok_or_else(|| invalid("missing guest stdout bytes"))?,
                )?,
            );
        }
        if String::from_utf8(stdout)?.trim() != nonce {
            return Err(invalid("guest command nonce absent from stdout").into());
        }
        report
            .checks
            .push("actual_uid1000_command_nnp_caps_pids_no_nic_and_no_host_authority".into());
        self.journal(input, "validated")?;
        Ok(())
    }

    pub(crate) fn exited(&self) -> io::Result<bool> {
        let Some(fd) = &self.pidfd else {
            return Ok(false);
        };
        let mut descriptor = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result > 0 && descriptor.revents & libc::POLLIN != 0)
    }

    pub(crate) async fn collect(&mut self, report: &mut GuestReport) -> Result<()> {
        let mut pids = BTreeSet::new();
        // waitpid is limited to this process's children. This untrusted candidate
        // is only reaped, never signaled outside the authenticated owned cgroup.
        if let Some(pid) = self.candidate_pid {
            pids.insert(pid as i32);
        }
        if let Some(process) = &self.process {
            pids.insert(process.pid as i32);
        }
        if self.owned_cgroup {
            for pid in std::fs::read_to_string(self.cgroup.join("cgroup.procs"))?.split_whitespace()
            {
                pids.insert(pid.parse::<i32>()?);
            }
            std::fs::write(self.cgroup.join("cgroup.kill"), b"1")?;
        }
        if let Some(fd) = &self.pidfd {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                return Err(io::Error::last_os_error().into());
            }
        }
        if let Some(child) = self.launcher.as_mut() {
            if child.try_wait()?.is_none() {
                child.start_kill()?;
            }
            tokio::time::timeout(Duration::from_secs(10), child.wait()).await??;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            pids.retain(|pid| {
                let mut status = 0;
                let result = unsafe { libc::waitpid(*pid, &mut status, libc::WNOHANG) };
                result == 0
                    || (result < 0
                        && (io::Error::last_os_error().raw_os_error() != Some(libc::ECHILD)
                            || Path::new("/proc").join(pid.to_string()).exists()))
            });
            let empty = !self.owned_cgroup
                || std::fs::read_to_string(self.cgroup.join("cgroup.events"))?
                    .lines()
                    .any(|line| line == "populated 0");
            if pids.is_empty() && empty && (self.pidfd.is_none() || self.exited()?) {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(invalid("owned VMM/cgroup collection could not be confirmed").into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        report.vmm_reaped = true;
        if let Some(console) = self.console.take() {
            let (bytes, truncated) =
                tokio::time::timeout(Duration::from_secs(5), console).await???;
            report.console = String::from_utf8_lossy(&bytes).into_owned();
            report.console_truncated = truncated;
        }
        if self.owned_cgroup {
            std::fs::remove_dir(&self.cgroup)?;
            self.owned_cgroup = false;
        }
        if self.owned_root {
            let marker = std::fs::read(self.root.join("intent.json"));
            let value: serde_json::Value = match marker {
                Ok(bytes) => serde_json::from_slice(&bytes)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound && !self.recovered => {
                    // This live owner created the private root and failed before
                    // its first marker write; no recovered path is authorized here.
                    if self.persistent.is_some() {
                        serde_json::json!({"generation":self.generation,"owner":self.record().owner})
                    } else {
                        serde_json::json!({"generation":self.generation})
                    }
                }
                Err(error) => return Err(error.into()),
            };
            if value["generation"] != self.generation.to_string() {
                return Err(invalid("owned root generation mismatch; retained").into());
            }
            if let Some((_, record)) = &self.persistent
                && value["owner"] != serde_json::to_value(&record.owner)?
            {
                return Err(invalid("owned VM marker mismatch; retained").into());
            }
            std::fs::remove_dir_all(&self.root)?;
            self.owned_root = false;
        }
        report.root_absent = !self.root.try_exists()?;
        report.cgroup_absent = !self.cgroup.try_exists()?;
        if !report.root_absent || !report.cgroup_absent {
            return Err(invalid("owned filesystem collection unconfirmed").into());
        }
        if self.persistent.is_some() {
            self.set_phase("vm_collected")?;
        }
        Ok(())
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        // Best effort fencing is not evidence of collection. Explicit collect
        // above alone may set CleanupState::Complete.
        if self.owned_cgroup && (self.persistent.is_none() || !self.recovered) {
            let _ = std::fs::write(self.cgroup.join("cgroup.kill"), b"1");
        }
    }
}

async fn rpc(agent: &AgentClient, request: AgentRequest) -> Result<AgentResponse> {
    Ok(agent.rpc_reply(&request).await?.into_result()?)
}

/// Real hardware gate, with failure-path collection and a report even on error.
/// The caller must provide trusted, immutable image artifacts; no fallback exists.
pub async fn validate_guest(input: BootInput) -> GuestReport {
    let mut machine = Machine::new();
    let mut report = GuestReport {
        generation: machine.generation,
        passed: false,
        guest_started: false,
        checks: Vec::new(),
        process: None,
        cleanup: CleanupState::Unknown,
        root_absent: false,
        cgroup_absent: false,
        vmm_reaped: false,
        error: None,
        console: String::new(),
        console_truncated: false,
        runtime_profile_published: false,
    };
    let result = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut terminate) => tokio::select! {
            result=machine.run(&input, &mut report)=>result,
            _=terminate.recv()=>Err(invalid("guest operation interrupted; collecting owned generation").into()),
        },
        Err(error) => Err(error.into()),
    };
    report.process = machine.process.clone();
    let cleanup = machine.collect(&mut report).await;
    if cleanup.is_ok() {
        report.cleanup = CleanupState::Complete;
    }
    report.passed = result.is_ok() && cleanup.is_ok();
    report.error = match (result, cleanup) {
        (Ok(()), Ok(())) => None,
        (Err(error), Ok(())) => Some(error.to_string()),
        (result, Err(error)) => Some(format!(
            "operation={:?}; cleanup={error}",
            result.err().map(|error| error.to_string())
        )),
    };
    report
}
