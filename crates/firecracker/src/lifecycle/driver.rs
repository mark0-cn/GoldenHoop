use super::*;
use crate::{
    api::{PeerIdentity, authenticated_socket},
    kvm::{KvmState, probe_kvm},
    machine::{GuestReport, Machine},
    vsock::read_frame,
};
use async_trait::async_trait;
use goldenhoop_runtime::*;
use std::{os::unix::fs::MetadataExt, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    sync::{Mutex, RwLock},
};

struct Inner {
    cfg: DriverConfig,
    _installation_lock: File,
    operations: Mutex<()>,
    vm_locks: Mutex<std::collections::HashMap<Uuid, std::sync::Weak<Mutex<()>>>>,
    profile: RwLock<RuntimeProfile>,
    children: std::sync::Mutex<std::collections::HashMap<Uuid, OwnedChild>>,
    recovered: std::collections::BTreeSet<Uuid>,
}
struct OwnedChild {
    pid: u32,
    child: tokio::process::Child,
    status: Option<String>,
}
enum ChildState {
    NotOwned,
    Running,
    Exited(String),
}
fn inventory(cfg: &DriverConfig) -> Result<Vec<VmJournal>> {
    let mut records = Vec::new();
    for entry in std::fs::read_dir(cfg.data_root.join("records"))? {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| invalid("invalid native record filename"))?;
        let id = Uuid::parse_str(stem)?;
        if id.to_string() != stem {
            return Err(invalid("noncanonical native record filename").into());
        }
        let record: VmJournal = read_json(&cfg.record_path(id))?;
        record.validate(cfg, id)?;
        records.push(record);
    }
    Ok(records)
}
#[derive(Clone)]
pub(super) struct NativeEngine {
    inner: Arc<Inner>,
}

fn unavailable(error: impl std::fmt::Display) -> ApiError {
    let _ = error;
    let mut error = ApiError::new(
        ErrorCode::BackendUnavailable,
        "native operation is unconfirmed; reconcile the owned generation",
    );
    error.retryable = false;
    error
}
pub(super) fn profile(cfg: &DriverConfig) -> RuntimeProfile {
    RuntimeProfile {
        id: PROFILE.into(),
        placement: Placement::Local,
        isolation: Isolation::Firecracker,
        availability: Availability::Unverified,
        capabilities: Default::default(),
        code_languages: Default::default(),
        max_resources: cfg.max_resources.clone(),
        max_ttl_seconds: cfg.max_ttl_seconds,
        reason: Some("actual native lifecycle probe has not completed".into()),
    }
}

impl NativeEngine {
    pub fn connect(cfg: DriverConfig, lock: File) -> Result<Self> {
        cfg.validate()?;
        if unsafe { libc::geteuid() } != 0 {
            return Err(invalid("native driver requires Linux root").into());
        }
        for name in ["vm", "records"] {
            private_directory(&cfg.data_root.join(name))?;
        }
        // Verify the actual helper before granting it root lifecycle authority.
        if digest(trusted_file(&cfg.supervisor.path)?)?
            != (cfg.supervisor.sha256.clone(), cfg.supervisor.size)
        {
            return Err(invalid("native supervisor artifact mismatch").into());
        }
        let recovered = inventory(&cfg)?
            .into_iter()
            .filter(|record| record.phase != "collected")
            .map(|record| record.owner.sandbox_id)
            .collect();
        let observed = profile(&cfg);
        Ok(Self {
            inner: Arc::new(Inner {
                cfg,
                _installation_lock: lock,
                operations: Mutex::new(()),
                vm_locks: Mutex::new(Default::default()),
                profile: RwLock::new(observed),
                children: std::sync::Mutex::new(Default::default()),
                recovered,
            }),
        })
    }
    pub(super) fn recovered_count(&self) -> usize {
        self.inner.recovered.len()
    }

    /// Authenticate acknowledged live generations independently. An uncertain
    /// or unresponsive generation retains its reservation and journal rather
    /// than preventing unrelated installation operations from becoming ready.
    pub(super) async fn observe_recovery(
        &self,
    ) -> Result<Vec<super::recovery::GenerationRecovery>> {
        let records: Vec<_> = self
            .records()?
            .into_iter()
            .filter(|record| record.phase != "collected")
            .collect();
        if records.len() > self.inner.cfg.capacity.max_vms as usize {
            return Err(invalid("native recovery inventory exceeds configured capacity").into());
        }
        let permits = Arc::new(tokio::sync::Semaphore::new(8));
        let mut tasks = tokio::task::JoinSet::new();
        for record in records {
            let actor = self.clone();
            let permits = permits.clone();
            tasks.spawn(async move {
                let _permit = permits
                    .acquire_owned()
                    .await
                    .map_err(|_| invalid("native recovery observation closed"))?;
                let mut observed = super::recovery::GenerationRecovery {
                    sandbox_id: record.owner.sandbox_id,
                    generation: record.owner.generation,
                    previous_phase: record.phase.clone(),
                    previous_error_sha256: record
                        .error
                        .as_ref()
                        .map(|text| format!("{:x}", Sha256::digest(text.as_bytes()))),
                    observed_state: ObservedState::Unknown,
                    authenticated: false,
                };
                let check = async {
                    let cfg = &actor.inner.cfg;
                    if !record.ever_ready
                        || !["running", "paused"].contains(&record.phase.as_str())
                        || record.expired()?
                        || record.process.is_none()
                        || record.artifacts != cfg.artifacts
                        || record.supervisor_artifact != cfg.supervisor
                    {
                        return Err(
                            invalid("native generation requires further reconciliation").into()
                        );
                    }
                    let state = actor
                        .supervisor_call(&record, SupervisorOperation::Status)
                        .await?;
                    if ![ObservedState::Running, ObservedState::Paused].contains(&state) {
                        return Err(
                            invalid("native VMM observation is not running or paused").into()
                        );
                    }
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state)
                };
                if let Ok(Ok(state)) = tokio::time::timeout(Duration::from_secs(3), check).await {
                    observed.observed_state = state;
                    observed.authenticated = true;
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
            });
        }
        let mut result = Vec::new();
        while let Some(observed) = tasks.join_next().await {
            result.push(observed.map_err(|_| invalid("native recovery observer failed"))??);
        }
        result.sort_by_key(|record| record.sandbox_id);
        Ok(result)
    }

    async fn vm_lock(&self, id: Uuid) -> Arc<Mutex<()>> {
        let mut locks = self.inner.vm_locks.lock().await;
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&id).and_then(std::sync::Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(id, Arc::downgrade(&lock));
        lock
    }

    fn load(&self, id: Uuid) -> Result<VmJournal> {
        let record: VmJournal = read_json(&self.inner.cfg.record_path(id))?;
        record.validate(&self.inner.cfg, id)?;
        Ok(record)
    }
    fn child_state(&self, id: Uuid, expected: Option<&ProcessIdentity>) -> Result<ChildState> {
        let mut children = self
            .inner
            .children
            .lock()
            .map_err(|_| invalid("native child registry poisoned"))?;
        let Some(owned) = children.get_mut(&id) else {
            return Ok(ChildState::NotOwned);
        };
        if expected.is_some_and(|identity| identity.pid != owned.pid) {
            return Err(invalid("recorded supervisor differs from actual owned child").into());
        }
        if owned.status.is_none()
            && let Some(status) = owned.child.try_wait()?
        {
            owned.status = Some(status.to_string());
        }
        Ok(match &owned.status {
            Some(status) => ChildState::Exited(status.clone()),
            None => ChildState::Running,
        })
    }
    pub(super) fn reap_children(&self) -> Result<()> {
        let mut children = self
            .inner
            .children
            .lock()
            .map_err(|_| invalid("native child registry poisoned"))?;
        for owned in children.values_mut() {
            if owned.status.is_none()
                && let Some(status) = owned.child.try_wait()?
            {
                owned.status = Some(status.to_string());
            }
        }
        Ok(())
    }

    pub(super) fn children_collected(&self) -> Result<bool> {
        self.reap_children()?;
        Ok(self
            .inner
            .children
            .lock()
            .map_err(|_| invalid("native child registry poisoned"))?
            .values()
            .all(|owned| owned.status.is_some()))
    }

    fn handle(&self, record: &VmJournal) -> RuntimeHandle {
        RuntimeHandle {
            sandbox_id: record.owner.sandbox_id,
            profile: PROFILE.into(),
            backend_ref: format!(
                "fc1:{}:{}",
                record.owner.installation_id, record.owner.generation
            ),
        }
    }
    fn for_handle(&self, handle: &RuntimeHandle) -> Result<VmJournal> {
        let record = self.load(handle.sandbox_id)?;
        if handle.profile != PROFILE || self.handle(&record).backend_ref != handle.backend_ref {
            return Err(invalid("native handle generation or installation mismatch").into());
        }
        Ok(record)
    }
    fn records(&self) -> Result<Vec<VmJournal>> {
        inventory(&self.inner.cfg)
    }

    fn admit(&self, resources: &ResourceLimits) -> Result<()> {
        let mut cpu = u64::from(resources.cpu_millis);
        let mut memory = resources
            .memory_bytes
            .checked_add(256 * MIB + super::manager::MANAGER_MEMORY)
            .ok_or_else(|| invalid("native reservation overflow"))?;
        let mut count = 1u32;
        for record in self.records()? {
            if record.phase != "collected" {
                cpu = cpu
                    .checked_add(u64::from(record.resources.cpu_millis))
                    .ok_or_else(|| invalid("native CPU reservation overflow"))?;
                memory = memory
                    .checked_add(record.resources.memory_bytes)
                    .and_then(|n| n.checked_add(256 * MIB))
                    .ok_or_else(|| invalid("native memory reservation overflow"))?;
                count = count
                    .checked_add(1)
                    .ok_or_else(|| invalid("native VM reservation overflow"))?;
            }
        }
        if cpu > u64::from(self.inner.cfg.capacity.cpu_millis)
            || memory > self.inner.cfg.capacity.memory_bytes
            || count > self.inner.cfg.capacity.max_vms
        {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "native installation capacity is reserved",
            )
            .into());
        }
        Ok(())
    }

    fn prepare_supervisor_group(&self, record: &VmJournal) -> Result<()> {
        let group = self
            .inner
            .cfg
            .paths(record.owner.generation)?
            .supervisor_cgroup;
        std::fs::create_dir(&group)?;
        // Group ownership follows the durable full installation/generation intent.
        for (file, value) in [
            ("cpu.max", "100000 100000"),
            ("memory.max", "134217728"),
            ("memory.swap.max", "0"),
            ("pids.max", "8"),
        ] {
            std::fs::write(group.join(file), value)?;
            if std::fs::read_to_string(group.join(file))?.trim() != value {
                return Err(invalid("supervisor cgroup budget readback mismatch").into());
            }
        }
        Ok(())
    }

    fn spawn_supervisor(&self, record: &VmJournal) -> Result<tokio::process::Child> {
        let group = self
            .inner
            .cfg
            .paths(record.owner.generation)?
            .supervisor_cgroup;
        let tasks = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(group.join("cgroup.procs"))?;
        let descriptor = tasks.as_raw_fd();
        let lock = self.inner._installation_lock.as_raw_fd();
        let stderr = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(
                self.inner
                    .cfg
                    .data_root
                    .join("records")
                    .join(format!("{}.supervisor.log", record.owner.sandbox_id)),
            )?;
        let metadata = stderr.metadata()?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(invalid("native supervisor diagnostic file ownership mismatch").into());
        }
        let mut command = tokio::process::Command::new(&record.supervisor_artifact.path);
        command
            .arg("supervise")
            .arg("--config")
            .arg(self.inner.cfg.data_root.join("config.json"))
            .arg("--sandbox")
            .arg(record.owner.sandbox_id.to_string())
            .arg("--generation")
            .arg(record.owner.generation.to_string())
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C.UTF-8")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(stderr);
        // SAFETY: only async-signal-safe Linux syscalls execute after fork. The
        // inherited CLOEXEC installation lease fences restart until cgroup join.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(lock, libc::F_GETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::write(descriptor, b"0".as_ptr().cast(), 1) != 1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(command.spawn()?)
    }

    async fn supervisor_call(
        &self,
        record: &VmJournal,
        operation: SupervisorOperation,
    ) -> Result<ObservedState> {
        let expected = record
            .supervisor
            .as_ref()
            .ok_or_else(|| invalid("native supervisor identity is not recorded"))?;
        let fd = track_process(expected)?;
        if expected.uid != 0
            || expected.executable_sha256 != self.inner.cfg.supervisor.sha256
            || record.supervisor_artifact != self.inner.cfg.supervisor
            || pidfd_exited(&fd)?
        {
            return Err(invalid("native supervisor is not live and authenticated").into());
        }
        let group = self
            .inner
            .cfg
            .paths(record.owner.generation)?
            .supervisor_cgroup;
        let _membership = super::reaper::group_child(expected.pid, Some(&group), false)?
            .ok_or_else(|| invalid("native supervisor generation group is absent"))?;
        let path = self
            .inner
            .cfg
            .paths(record.owner.generation)?
            .root
            .join("control.sock");
        tokio::time::timeout(Duration::from_secs(10), async {
            let stream = authenticated_socket(
                &path,
                PeerIdentity {
                    pid: expected.pid,
                    uid: 0,
                    instance: record.owner.generation,
                },
            )
            .await?;
            let mut stream = BufReader::new(stream);
            let mut bytes = serde_json::to_vec(&SupervisorCall {
                owner: record.owner.clone(),
                operation,
            })?;
            bytes.push(b'\n');
            stream.get_mut().write_all(&bytes).await?;
            let frame = read_frame(&mut stream, 65536).await?;
            let reply: SupervisorReply = serde_json::from_slice(&frame)?;
            if reply.generation != record.owner.generation {
                return Err(invalid("native supervisor response generation mismatch").into());
            }
            if let Some(error) = reply.error {
                return Err(error.into());
            }
            Ok(reply.state)
        })
        .await
        .map_err(|_| invalid("native supervisor exchange is uncertain"))?
    }

    async fn wait_ready(
        &self,
        id: Uuid,
        child: Option<tokio::process::Child>,
    ) -> Result<RuntimeHandle> {
        if let Some(child) = child {
            let pid = child
                .id()
                .ok_or_else(|| invalid("native child PID missing"))?;
            let mut children = self
                .inner
                .children
                .lock()
                .map_err(|_| invalid("native child registry poisoned"))?;
            if children.contains_key(&id) {
                return Err(invalid("native child already tracked").into());
            }
            children.insert(
                id,
                OwnedChild {
                    pid,
                    child,
                    status: None,
                },
            );
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let record = self.load(id)?;
            if record.expired()? {
                return Err(invalid("native sandbox expired during creation").into());
            }
            if ["vm_collected", "collected", "unknown"].contains(&record.phase.as_str()) {
                return Err(invalid(
                    record
                        .error
                        .unwrap_or_else(|| "native creation did not complete".into()),
                )
                .into());
            }
            if record.phase == "running"
                && self
                    .supervisor_call(&record, SupervisorOperation::Status)
                    .await
                    .is_ok_and(|state| state == ObservedState::Running)
            {
                return Ok(self.handle(&record));
            }
            if let ChildState::Exited(status) = self.child_state(id, record.supervisor.as_ref())? {
                return Err(invalid(format!(
                    "native supervisor exited during creation: {status}"
                ))
                .into());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(invalid(
                    "native creation deadline; generation retained for reconciliation",
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn create_owned(
        &self,
        sandbox: &Sandbox,
        request: &CreateSandbox,
    ) -> Result<RuntimeHandle> {
        let cfg = &self.inner.cfg;
        if request.profile != PROFILE
            || sandbox.profile != PROFILE
            || request.image != cfg.image
            || sandbox.image != cfg.image
            || sandbox.id.is_nil()
            || sandbox.resources != request.resources
            || request.network != NetworkPolicy::default()
            || request.child_budget.is_some()
            || request.feature_limit.is_some()
            || request.ttl_seconds == 0
            || request.ttl_seconds > cfg.max_ttl_seconds
            || sandbox.expires_at <= Utc::now()
            || sandbox.created_at > Utc::now()
            || sandbox.desired_state != DesiredState::Running
            || sandbox.expires_at - sandbox.created_at
                != chrono::Duration::seconds(request.ttl_seconds as i64)
            || sandbox.expires_at - sandbox.created_at
                > chrono::Duration::seconds(cfg.max_ttl_seconds as i64)
        {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "native sandbox request does not match the configured image, limits or lifetime",
            )
            .into());
        }
        let supported = std::collections::BTreeSet::from([
            Capability::Commands,
            Capability::Files,
            Capability::Pause,
            Capability::NetworkIsolation,
        ]);
        if request
            .required_capabilities
            .iter()
            .any(|capability| !supported.contains(capability))
        {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "native requested capability has no implemented driver path",
            )
            .into());
        }
        validate_resources(&request.resources, &cfg.max_resources).map_err(|_| {
            ApiError::new(
                ErrorCode::InvalidRequest,
                "native resource bounds or memory granularity are invalid",
            )
        })?;
        let digest = request_digest(request)?;
        let path = cfg.record_path(sandbox.id);
        if path.try_exists()? {
            let record = self.load(sandbox.id)?;
            if record.owner.request_sha256 != digest
                || record.owner.expires_at != sandbox.expires_at
            {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "native sandbox identity already has a different intent",
                )
                .into());
            }
            if record.phase == "collected" || record.phase == "vm_collected" {
                return Err(ApiError::new(
                    ErrorCode::InvalidState,
                    "collected native generations cannot be recreated",
                )
                .into());
            }
            if record.supervisor.is_none()
                && record.phase == "reserved"
                && !self.inner.recovered.contains(&sandbox.id)
            {
                let paths = cfg.paths(record.owner.generation)?;
                if !paths.root.try_exists()?
                    && !paths.vm_cgroup.try_exists()?
                    && supervisor::cgroup_empty(&paths.supervisor_cgroup)?
                {
                    if paths.supervisor_cgroup.try_exists()? {
                        supervisor::collect_supervisor_cgroup(cfg, &record)?;
                    }
                    self.prepare_supervisor_group(&record)?;
                    let child = self.spawn_supervisor(&record)?;
                    return self.wait_ready(sandbox.id, Some(child)).await;
                }
            }
            return self.wait_ready(sandbox.id, None).await;
        }
        if probe_kvm().state != KvmState::Ready {
            return Err(invalid("actual KVM is unavailable").into());
        }
        let admission = self.inner.operations.lock().await;
        self.admit(&request.resources)?;
        let generation = Uuid::new_v4();
        let paths = cfg.paths(generation)?;
        if paths.root.try_exists()?
            || paths.vm_cgroup.try_exists()?
            || paths.supervisor_cgroup.try_exists()?
        {
            return Err(invalid("native generation path already exists").into());
        }
        let remaining = (sandbox.expires_at - Utc::now()).to_std()?;
        let deadline = boottime_ns()?
            .checked_add(u64::try_from(remaining.as_nanos())?)
            .ok_or_else(|| invalid("native absolute deadline overflow"))?;
        let record = VmJournal {
            format: 1,
            owner: VmOwner {
                installation_id: cfg.installation_id,
                sandbox_id: sandbox.id,
                generation,
                request_sha256: digest,
                expires_at: sandbox.expires_at,
                host_boot_id: boot_id()?,
                boot_deadline_ns: deadline,
            },
            artifacts: cfg.artifacts.clone(),
            resources: request.resources.clone(),
            supervisor: None,
            supervisor_artifact: cfg.supervisor.clone(),
            original_cgroup: supervisor::original_cgroup()?,
            process: None,
            phase: "reserved".into(),
            ever_ready: false,
            error: None,
            console_tail: String::new(),
            supervisor_stderr_tail: String::new(),
            supervisor_cgroup_events: Default::default(),
        };
        atomic_json(&path, &record)?;
        let launch = (|| -> Result<_> {
            self.prepare_supervisor_group(&record)?;
            self.spawn_supervisor(&record)
        })();
        drop(admission);
        match launch {
            Ok(child) => self.wait_ready(sandbox.id, Some(child)).await,
            Err(error) => {
                let _ = self.collect_dead(&record).await;
                Err(error)
            }
        }
    }

    fn supervisor_alive(&self, record: &VmJournal) -> Result<bool> {
        let Some(expected) = &record.supervisor else {
            return Ok(false);
        };
        if expected.uid != 0
            || expected.executable_sha256 != self.inner.cfg.supervisor.sha256
            || record.supervisor_artifact != self.inner.cfg.supervisor
        {
            return Err(invalid("native supervisor artifact or root identity differs").into());
        }
        if expected.boot_id != boot_id()?
            || !Path::new("/proc")
                .join(expected.pid.to_string())
                .try_exists()?
        {
            return Ok(false);
        }
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, expected.pid, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let observed = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        if pidfd_exited(&observed)? {
            return Ok(false);
        }
        let fd = track_process(expected)?;
        Ok(!pidfd_exited(&fd)?)
    }

    fn retain_dead_supervisor_diagnostics(
        &self,
        record: &mut VmJournal,
        error: &str,
    ) -> Result<()> {
        if self.supervisor_alive(record)? {
            return Err(invalid("live supervisor retains exclusive journal writes").into());
        }
        let group = self
            .inner
            .cfg
            .paths(record.owner.generation)?
            .supervisor_cgroup;
        for name in [
            "memory.current",
            "memory.peak",
            "memory.events.local",
            "memory.stat",
            "io.stat",
            "pids.events",
            "cpu.stat",
        ] {
            match File::open(group.join(name)) {
                Ok(file) => {
                    let mut text = String::new();
                    file.take(8193).read_to_string(&mut text)?;
                    if text.len() > 8192 {
                        return Err(
                            invalid("supervisor resource event observation exceeds limit").into(),
                        );
                    }
                    record.supervisor_cgroup_events.insert(name.into(), text);
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound && !group.try_exists()? => (),
                Err(e) => return Err(e.into()),
            }
        }
        let path = self
            .inner
            .cfg
            .data_root
            .join("records")
            .join(format!("{}.supervisor.log", record.owner.sandbox_id));
        match trusted_file(&path) {
            Ok(mut file) => {
                use std::io::{Seek, SeekFrom};
                let length = file.metadata()?.len();
                file.seek(SeekFrom::Start(length.saturating_sub(16384)))?;
                let mut bytes = Vec::new();
                file.take(16384).read_to_end(&mut bytes)?;
                record.supervisor_stderr_tail = String::from_utf8_lossy(&bytes).into();
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        if record.error.is_none() {
            record.error = Some(error.chars().take(2048).collect());
        }
        atomic_json(&self.inner.cfg.record_path(record.owner.sandbox_id), record)
    }

    fn physical_absence(&self, record: &VmJournal) -> Result<bool> {
        let paths = self.inner.cfg.paths(record.owner.generation)?;
        Ok(!paths.root.try_exists()?
            && !paths.vm_cgroup.try_exists()?
            && !paths.supervisor_cgroup.try_exists()?
            && self.supervisor_gone(record)?
            && !matches!(
                self.child_state(record.owner.sandbox_id, record.supervisor.as_ref())?,
                ChildState::Running
            ))
    }

    fn supervisor_gone(&self, record: &VmJournal) -> Result<bool> {
        let Some(expected) = &record.supervisor else {
            return Ok(true);
        };
        if expected.boot_id != boot_id()? {
            return Ok(true);
        }
        match std::fs::read_to_string(
            Path::new("/proc")
                .join(expected.pid.to_string())
                .join("stat"),
        ) {
            Ok(stat) => Ok(stat
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().nth(19))
                .and_then(|ticks| ticks.parse::<u64>().ok())
                .is_some_and(|ticks| ticks != expected.start_ticks)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
        }
    }

    async fn settle_collected(&self, record: &VmJournal) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if matches!(
                self.child_state(record.owner.sandbox_id, record.supervisor.as_ref())?,
                ChildState::NotOwned
            ) && !self.supervisor_gone(record)?
                && let Some(identity) = &record.supervisor
                && let Some(target) = super::reaper::recorded(identity)?
            {
                let _ = target.collected()?;
            }
            if !self.supervisor_alive(record)? {
                supervisor::collect_supervisor_cgroup(&self.inner.cfg, record)?;
                if self.physical_absence(record)? {
                    let mut updated = self.load(record.owner.sandbox_id)?;
                    if updated.owner != record.owner {
                        return Err(invalid("native generation changed during collection").into());
                    }
                    updated.phase = "collected".into();
                    atomic_json(
                        &self.inner.cfg.record_path(record.owner.sandbox_id),
                        &updated,
                    )?;
                    self.inner
                        .children
                        .lock()
                        .map_err(|_| invalid("native child registry poisoned"))?
                        .remove(&record.owner.sandbox_id);
                    return Ok(());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(
                    invalid("native supervisor/process/filesystem collection unconfirmed").into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn collect_dead(&self, record: &VmJournal) -> Result<()> {
        if matches!(
            self.child_state(record.owner.sandbox_id, record.supervisor.as_ref())?,
            ChildState::Running
        ) {
            return Err(invalid(
                "owned supervisor is still preparing; refresh its durable identity before recovery",
            )
            .into());
        }
        if self.supervisor_alive(record)? {
            return Err(invalid("live native supervisor must own collection").into());
        }
        let mut machine = Machine::recover(&self.inner.cfg, record.clone())?;
        let mut report = GuestReport::empty(record.owner.generation);
        machine.collect(&mut report).await?;
        self.settle_collected(record).await
    }

    async fn remove_owned(&self, record: &VmJournal) -> Result<()> {
        if record.phase == "vm_collected" {
            return self.settle_collected(record).await;
        }
        if self.physical_absence(record)? {
            return self.settle_collected(record).await;
        }
        if self.supervisor_alive(record)? {
            if ["reserved", "preparing", "launch_intent", "tracked"]
                .contains(&record.phase.as_str())
            {
                if matches!(
                    self.child_state(record.owner.sandbox_id, record.supervisor.as_ref())?,
                    ChildState::NotOwned
                ) {
                    return Err(invalid("unacknowledged adopted supervisor must settle its original effect before stop").into());
                }
                let identity = record
                    .supervisor
                    .as_ref()
                    .ok_or_else(|| invalid("native supervisor identity missing"))?;
                let fd = track_process(identity)?;
                let group = self
                    .inner
                    .cfg
                    .paths(record.owner.generation)?
                    .supervisor_cgroup;
                let _membership = super::reaper::group_child(identity.pid, Some(&group), false)?
                    .ok_or_else(|| invalid("owned supervisor generation group is absent"))?;
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd.as_raw_fd(),
                        libc::SIGTERM,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
                if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                    return Err(io::Error::last_os_error().into());
                }
                return self.settle_collected(record).await;
            }
            let result = self
                .supervisor_call(record, SupervisorOperation::Stop)
                .await;
            if result.is_err() && self.supervisor_alive(record)? {
                return Err(
                    invalid("native stop response is uncertain; supervisor retained").into(),
                );
            }
            self.settle_collected(record).await
        } else {
            self.collect_dead(record).await
        }
    }

    pub async fn reap_expired(&self) -> std::result::Result<Vec<Uuid>, ApiError> {
        let mut collected = Vec::new();
        let mut errors = false;
        for record in self.records().map_err(unavailable)? {
            if record.phase != "collected" && record.expired().map_err(unavailable)? {
                let lock = self.vm_lock(record.owner.sandbox_id).await;
                let _guard = lock.lock().await;
                match self.remove_owned(&record).await {
                    Ok(()) => collected.push(record.owner.sandbox_id),
                    Err(_) => errors = true,
                }
            }
        }
        if errors {
            return Err(unavailable(
                "some expired native generations remain unconfirmed",
            ));
        }
        Ok(collected)
    }

    async fn live_agent(&self, record: &VmJournal) -> Result<crate::agent::AgentClient> {
        if record.expired()? || record.phase != "running" || !record.ever_ready {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "native generation is not live for agent dispatch",
            )
            .into());
        }
        if self
            .supervisor_call(record, SupervisorOperation::Status)
            .await?
            != ObservedState::Running
        {
            return Err(invalid("native VMM is not running").into());
        }
        let machine = Machine::recover(&self.inner.cfg, self.load(record.owner.sandbox_id)?)?;
        let agent = machine.agent()?;
        let info = agent.control_info().await?;
        if info.pids != record.resources.pids || record.expired()? {
            return Err(invalid("native guest limits or absolute lifetime mismatch").into());
        }
        Ok(agent)
    }
}

#[async_trait]
impl RuntimeDriver for NativeEngine {
    async fn probe(&self) -> RuntimeProfile {
        let mut result = profile(&self.inner.cfg);
        let id = Uuid::new_v4();
        let now = Utc::now();
        let mut request = CreateSandbox::new(PROFILE, self.inner.cfg.image.clone());
        request.resources = ResourceLimits {
            cpu_millis: self.inner.cfg.max_resources.cpu_millis.min(1000),
            memory_bytes: self.inner.cfg.max_resources.memory_bytes.min(256 * MIB),
            pids: self.inner.cfg.max_resources.pids.min(32),
        };
        request.ttl_seconds = self.inner.cfg.max_ttl_seconds.min(240);
        let sandbox = Sandbox {
            id,
            profile: PROFILE.into(),
            image: request.image.clone(),
            state: SandboxState::Pending,
            desired_state: DesiredState::Running,
            cleanup: CleanupState::Pending,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(request.ttl_seconds as i64),
            observed_at: None,
            resources: request.resources.clone(),
            metadata: Default::default(),
            reason: None,
        };
        let check = async {
            let handle = self.create(&sandbox, &request).await?;
            let agent_request = AgentRequest::WriteFile {
                path: "native-profile-probe".into(),
                data_base64: "bmF0aXZl".into(),
            };
            self.rpc(&handle, &agent_request).await?;
            if !matches!(self.rpc(&handle,&AgentRequest::ReadFile{path:"native-profile-probe".into(),max_bytes:32}).await?,AgentResponse::File{data_base64} if data_base64=="bmF0aXZl")
            {
                return Err(invalid("native probe file result mismatch").into());
            }
            let job = Uuid::new_v4();
            let nonce = Uuid::new_v4().to_string();
            let script = format!(
                "import os\nassert os.getuid()==1000\nassert sorted(os.listdir('/sys/class/net'))==['lo']\nprint({nonce:?},flush=True)"
            );
            let mut command = CommandSpec::new(["python3", "-c", &script]);
            command.timeout_seconds = 10;
            command.max_output_bytes = 4096;
            self.rpc(&handle, &AgentRequest::Start { id: job, command })
                .await?;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let AgentResponse::Execution(execution) = self
                    .rpc(&handle, &AgentRequest::Inspect { id: job })
                    .await?
                else {
                    return Err(invalid("native execution result shape mismatch").into());
                };
                if execution.state.is_terminal() {
                    if execution.state != ExecutionState::Succeeded
                        || execution.exit_code != Some(0)
                        || execution.cleanup != CleanupState::Complete
                    {
                        return Err(
                            invalid("native execution or descendants did not complete").into()
                        );
                    }
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(invalid("native command probe deadline").into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let AgentResponse::Events(events) = self
                .rpc(&handle, &AgentRequest::Events { id: job, after: 0 })
                .await?
            else {
                return Err(invalid("native event result shape mismatch").into());
            };
            use base64::Engine;
            let mut stdout = Vec::new();
            for event in events
                .iter()
                .filter(|event| event.kind == EventKind::Stdout)
            {
                if event.execution_id != job || event.data["encoding"] != "base64" {
                    return Err(invalid("native stdout identity mismatch").into());
                }
                stdout.extend(
                    base64::engine::general_purpose::STANDARD.decode(
                        event.data["data"]
                            .as_str()
                            .ok_or_else(|| invalid("native stdout bytes missing"))?,
                    )?,
                );
            }
            if String::from_utf8(stdout)?.trim() != nonce {
                return Err(invalid("native command stdout nonce mismatch").into());
            }
            self.pause(&handle).await?;
            if self.inspect(&handle).await?.state != ObservedState::Paused {
                return Err(invalid("native pause not observed").into());
            }
            self.resume(&handle).await?;
            self.remove(&handle).await?;
            Ok(())
        };
        let checked: Result<()> = check.await;
        if checked.is_ok() {
            result.availability = Availability::Available;
            result.reason = None;
            result.capabilities.extend([
                Capability::Commands,
                Capability::Files,
                Capability::Pause,
                Capability::NetworkIsolation,
            ]);
        } else {
            let lock = self.vm_lock(id).await;
            let _guard = lock.lock().await;
            if let Ok(record) = self.load(id) {
                let _ = self.remove_owned(&record).await;
            }
            result.availability = Availability::Unavailable;
            result.reason =
                Some("actual native create/agent/pause/resume/collection probe failed".into());
        }
        *self.inner.profile.write().await = result.clone();
        result
    }
    async fn create(
        &self,
        sandbox: &Sandbox,
        request: &CreateSandbox,
    ) -> std::result::Result<RuntimeHandle, ApiError> {
        let lock = self.vm_lock(sandbox.id).await;
        let _guard = lock.lock().await;
        let result = self.create_owned(sandbox, request).await;
        if result.is_err()
            && let Ok(mut record) = self.load(sandbox.id)
            && !record.ever_ready
            && request_digest(request).is_ok_and(|digest| digest == record.owner.request_sha256)
        {
            if let Err(error) = &result
                && !self.supervisor_alive(&record).unwrap_or(true)
            {
                let _ = self.retain_dead_supervisor_diagnostics(&mut record, &error.to_string());
            }
            if record.phase == "vm_collected" {
                let _ = self.settle_collected(&record).await;
            } else if self.supervisor_alive(&record).unwrap_or(false) {
                if let Some(identity) = &record.supervisor
                    && let Ok(fd) = track_process(identity)
                {
                    unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            fd.as_raw_fd(),
                            libc::SIGTERM,
                            std::ptr::null::<libc::siginfo_t>(),
                            0,
                        )
                    };
                }
                let _ = self.settle_collected(&record).await;
            } else {
                let _ = self.collect_dead(&record).await;
            }
        }
        result.map_err(|error| {
            error
                .downcast_ref::<ApiError>()
                .cloned()
                .unwrap_or_else(|| unavailable(error))
        })
    }
    async fn inspect(
        &self,
        handle: &RuntimeHandle,
    ) -> std::result::Result<RuntimeObservation, ApiError> {
        let lock = self.vm_lock(handle.sandbox_id).await;
        let _guard = lock.lock().await;
        let record = self.for_handle(handle).map_err(unavailable)?;
        let state = if self.physical_absence(&record).map_err(unavailable)? {
            ObservedState::Missing
        } else if self.supervisor_alive(&record).map_err(unavailable)? {
            self.supervisor_call(&record, SupervisorOperation::Status)
                .await
                .map_err(unavailable)?
        } else {
            ObservedState::Unknown
        };
        Ok(RuntimeObservation {
            state,
            exit_code: None,
            oom_killed: None,
            observed_at: Utc::now(),
        })
    }
    async fn remove(&self, handle: &RuntimeHandle) -> std::result::Result<(), ApiError> {
        let lock = self.vm_lock(handle.sandbox_id).await;
        let _guard = lock.lock().await;
        let record = self.for_handle(handle).map_err(unavailable)?;
        self.remove_owned(&record).await.map_err(unavailable)
    }
    async fn discover(&self) -> std::result::Result<Vec<RuntimeHandle>, ApiError> {
        let _guard = self.inner.operations.lock().await;
        Ok(self
            .records()
            .map_err(unavailable)?
            .iter()
            .filter(|record| record.phase != "collected")
            .map(|record| self.handle(record))
            .collect())
    }
    async fn pause(&self, handle: &RuntimeHandle) -> std::result::Result<(), ApiError> {
        let lock = self.vm_lock(handle.sandbox_id).await;
        let _guard = lock.lock().await;
        let record = self.for_handle(handle).map_err(unavailable)?;
        if record.expired().map_err(unavailable)? {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "native sandbox lifetime elapsed",
            ));
        }
        self.supervisor_call(&record, SupervisorOperation::Pause)
            .await
            .map_err(unavailable)?;
        Ok(())
    }
    async fn resume(&self, handle: &RuntimeHandle) -> std::result::Result<(), ApiError> {
        let lock = self.vm_lock(handle.sandbox_id).await;
        let _guard = lock.lock().await;
        let record = self.for_handle(handle).map_err(unavailable)?;
        if record.expired().map_err(unavailable)? {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "native sandbox lifetime elapsed",
            ));
        }
        self.supervisor_call(&record, SupervisorOperation::Resume)
            .await
            .map_err(unavailable)?;
        Ok(())
    }
}

#[async_trait]
impl AgentTransport for NativeEngine {
    async fn rpc(
        &self,
        handle: &RuntimeHandle,
        request: &AgentRequest,
    ) -> std::result::Result<AgentResponse, ApiError> {
        self.rpc_reply(handle, request).await?.into_result()
    }
    async fn rpc_reply(
        &self,
        handle: &RuntimeHandle,
        request: &AgentRequest,
    ) -> std::result::Result<AgentReply, ApiError> {
        let lock = self.vm_lock(handle.sandbox_id).await;
        let _guard = lock.lock().await;
        let record = self.for_handle(handle).map_err(unavailable)?;
        let agent = self.live_agent(&record).await.map_err(|error| {
            error
                .downcast_ref::<ApiError>()
                .cloned()
                .unwrap_or_else(|| unavailable(error))
        })?;
        let reply = agent
            .rpc_reply(request)
            .await
            .map_err(|error| error.error)?;
        if record.expired().map_err(unavailable)?
            || !self.supervisor_alive(&record).map_err(unavailable)?
        {
            return Err(unavailable("native response arrived after absolute expiry"));
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[tokio::test]
    async fn recovered_unacknowledged_reservation_waits_without_spawning_or_advertising_a_runtime()
    {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let directory = tempfile::Builder::new()
            .prefix("gm-")
            .tempdir_in("/var/lib")
            .unwrap();
        let artifact_path = PathBuf::from("/usr/bin/true");
        let (sha256, size) = digest(trusted_file(&artifact_path).unwrap()).unwrap();
        let artifact = Artifact {
            path: artifact_path,
            sha256,
            size,
        };
        let resources = ResourceLimits {
            cpu_millis: 500,
            memory_bytes: 256 * MIB,
            pids: 32,
        };
        let cfg = DriverConfig {
            installation_id: Uuid::new_v4(),
            data_root: directory.path().join("d"),
            artifacts: BootInput {
                firecracker: artifact.clone(),
                jailer: artifact.clone(),
                kernel: artifact.clone(),
                rootfs: artifact.clone(),
            },
            image: format!("sha256:{}", artifact.sha256),
            supervisor: artifact,
            max_resources: resources.clone(),
            capacity: HostCapacity::default(),
            max_ttl_seconds: 300,
        };
        let mut request = CreateSandbox::new(PROFILE, cfg.image.clone());
        request.resources = resources.clone();
        request.ttl_seconds = 120;
        let now = Utc::now();
        let id = Uuid::new_v4();
        let generation = Uuid::new_v4();
        let sandbox = Sandbox {
            id,
            profile: PROFILE.into(),
            image: cfg.image.clone(),
            state: SandboxState::Pending,
            desired_state: DesiredState::Running,
            cleanup: CleanupState::Pending,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(120),
            observed_at: None,
            resources: resources.clone(),
            metadata: Default::default(),
            reason: None,
        };
        let lease = metadata::claim_installation(&cfg.data_root, cfg.installation_id).unwrap();
        for name in ["records", "vm"] {
            private_directory(&cfg.data_root.join(name)).unwrap();
        }
        let record = VmJournal {
            format: 1,
            owner: VmOwner {
                installation_id: cfg.installation_id,
                sandbox_id: id,
                generation,
                request_sha256: request_digest(&request).unwrap(),
                expires_at: sandbox.expires_at,
                host_boot_id: boot_id().unwrap(),
                boot_deadline_ns: boottime_ns().unwrap() + 120_000_000_000,
            },
            artifacts: cfg.artifacts.clone(),
            resources,
            supervisor: None,
            supervisor_artifact: cfg.supervisor.clone(),
            original_cgroup: supervisor::original_cgroup().unwrap(),
            process: None,
            phase: "reserved".into(),
            ever_ready: false,
            error: None,
            console_tail: String::new(),
            supervisor_stderr_tail: String::new(),
            supervisor_cgroup_events: Default::default(),
        };
        atomic_json(&cfg.record_path(id), &record).unwrap();
        let engine = NativeEngine::connect(cfg.clone(), lease).unwrap();
        let paths = cfg.paths(generation).unwrap();
        assert!(
            !paths.root.exists() && !paths.vm_cgroup.exists() && !paths.supervisor_cgroup.exists()
        );
        let snapshot = std::fs::read(cfg.record_path(id)).unwrap();
        let observed = engine.observe_recovery().await.unwrap();
        assert_eq!(observed.len(), 1);
        assert!(!observed[0].authenticated && observed[0].observed_state == ObservedState::Unknown);
        let outcome = tokio::time::timeout(
            Duration::from_millis(80),
            engine.create_owned(&sandbox, &request),
        )
        .await;
        let unchanged = std::fs::read(cfg.record_path(id)).unwrap() == snapshot;
        let absent =
            !paths.root.exists() && !paths.vm_cgroup.exists() && !paths.supervisor_cgroup.exists();
        let no_children = engine.inner.children.lock().unwrap().is_empty();
        // The fixture uses no KVM and grants no runtime capability. If a
        // regression dispatched its inert helper, use only normal owned drain.
        if !absent || !no_children {
            let handle = engine.handle(&record);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let _ = engine.reap_children();
                if engine.remove(&handle).await.is_ok() {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    let retained = directory.keep();
                    panic!(
                        "unexpected owned dispatch retained for reconciliation: {}",
                        retained.display()
                    );
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        assert!(
            outcome.is_err(),
            "must wait for the original effect instead of replaying create"
        );
        assert!(
            unchanged && absent && no_children,
            "recovery dispatched or rewrote an unacknowledged reservation"
        );
        assert_eq!(
            engine.inner.profile.read().await.availability,
            Availability::Unverified
        );
        drop(engine);
        let path = directory.path().to_owned();
        directory.close().unwrap();
        assert!(!path.exists());
    }
}
