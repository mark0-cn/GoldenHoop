use super::*;
use crate::{
    machine::{GuestReport, Machine},
    models::InstanceState,
    vsock::read_frame,
};
use goldenhoop_runtime::ObservedState;
use std::{os::unix::fs::PermissionsExt, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

pub(crate) fn original_cgroup() -> Result<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup")?;
    let path = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| invalid("unified cgroup hierarchy is required"))?;
    let relative = path
        .strip_prefix('/')
        .ok_or_else(|| invalid("invalid current cgroup path"))?;
    let result = Path::new("/sys/fs/cgroup").join(relative);
    validate_original_cgroup(&result)?;
    Ok(result)
}

fn validate_original_cgroup(path: &Path) -> Result<()> {
    if !path.starts_with("/sys/fs/cgroup")
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid("original cgroup escapes unified hierarchy").into());
    }
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::statfs(c.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if i128::from(stat.f_type) != i128::from(libc::CGROUP2_SUPER_MAGIC) {
        return Err(invalid("original cgroup is not cgroup v2").into());
    }
    Ok(())
}

pub(crate) fn cgroup_empty(path: &Path) -> Result<bool> {
    match std::fs::read_to_string(path.join("cgroup.events")) {
        Ok(value) => Ok(value.lines().any(|line| line == "populated 0")),
        Err(e) if e.kind() == io::ErrorKind::NotFound && !path.try_exists()? => Ok(true),
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn collect_supervisor_cgroup(cfg: &DriverConfig, record: &VmJournal) -> Result<()> {
    let group = cfg.paths(record.owner.generation)?.supervisor_cgroup;
    if let Some(group) = super::cgroup::recorded(
        &group,
        record.supervisor_cgroup_identity.as_ref(),
        &record.owner,
    )? {
        group.remove_empty()?;
    }
    if group.try_exists()? {
        return Err(invalid("supervisor cgroup still exists").into());
    }
    Ok(())
}

async fn stop_vm(machine: &mut Machine, reason: Option<String>) -> Result<()> {
    let mut metadata_error = None;
    if let Some(reason) = reason
        && let Err(error) = machine.record_error(reason)
    {
        metadata_error = Some(error);
    }
    if let Err(error) = machine.set_phase("collecting") {
        metadata_error = Some(error);
    }
    let mut report = GuestReport::empty(machine.generation);
    machine.collect(&mut report).await?;
    machine.record_console(&report.console)?;
    if !report.vmm_reaped || !report.root_absent || !report.cgroup_absent {
        return Err(invalid("VMM collection evidence incomplete").into());
    }
    if let Some(error) = metadata_error {
        return Err(error);
    }
    Ok(())
}

fn reject_policy(
    hold: Option<Uuid>,
    checkpoints: bool,
    operation: SupervisorOperation,
) -> Option<ApiError> {
    match operation {
        SupervisorOperation::Resume if hold.is_some() => Some(ApiError::new(
            ErrorCode::InvalidState,
            "captured source cannot resume",
        )),
        SupervisorOperation::CaptureHold { .. } if !checkpoints => Some(ApiError::new(
            ErrorCode::UnsupportedCapability,
            "native checkpoints are disabled",
        )),
        SupervisorOperation::CaptureHold { capture } if capture.is_nil() => Some(ApiError::new(
            ErrorCode::InvalidRequest,
            "capture ID is nil",
        )),
        SupervisorOperation::CaptureHold { capture } if hold.is_some_and(|old| old != capture) => {
            Some(ApiError::new(
                ErrorCode::Conflict,
                "source already has a different capture hold",
            ))
        }
        _ => None,
    }
}
async fn write_reply(stream: &mut BufReader<UnixStream>, reply: &SupervisorReply) -> Result<()> {
    let mut bytes = serde_json::to_vec(reply)?;
    bytes.push(b'\n');
    stream.get_mut().write_all(&bytes).await?;
    stream.get_mut().shutdown().await?;
    Ok(())
}
async fn call(machine: &mut Machine, stream: UnixStream, checkpoints: bool) -> Result<bool> {
    let peer = stream.peer_cred()?;
    if peer.uid() != 0 {
        return Err(invalid("native supervisor client is not root").into());
    }
    let mut stream = BufReader::new(stream);
    let frame = read_frame(&mut stream, 65536).await?;
    let request: SupervisorCall = serde_json::from_slice(&frame)?;
    if request.owner != machine.record().owner {
        return Err(invalid("native supervisor request ownership mismatch").into());
    }
    if machine.record().phase == "unknown"
        && !matches!(request.operation, SupervisorOperation::Stop)
    {
        let mut error = ApiError::new(
            ErrorCode::BackendUnavailable,
            "owned generation is fenced after an unconfirmed operation",
        );
        error.retryable = false;
        write_reply(
            &mut stream,
            &SupervisorReply {
                generation: machine.generation,
                state: ObservedState::Unknown,
                error: Some(error),
            },
        )
        .await?;
        return Ok(false);
    }
    // Rejected intent has not dispatched a runtime effect. Do not poison the
    // source journal or make its independent expiry loop collect a healthy VM.
    if let Some(error) = reject_policy(
        machine.record().capture_hold,
        checkpoints,
        request.operation,
    ) {
        write_reply(
            &mut stream,
            &SupervisorReply {
                generation: machine.generation,
                state: ObservedState::Unknown,
                error: Some(error),
            },
        )
        .await?;
        return Ok(false);
    }
    let mut stopping = false;
    let operation = async {
        if matches!(request.operation, SupervisorOperation::Stop) {
            stop_vm(machine, None).await?;
            stopping = true;
            return Ok(ObservedState::Exited);
        }
        machine.check_expiry()?;
        let api = machine.api()?;
        match request.operation {
            SupervisorOperation::Status => (),
            SupervisorOperation::Pause => api.pause().await?,
            SupervisorOperation::Resume => api.resume().await?,
            SupervisorOperation::CaptureHold { capture } => {
                machine.hold_capture(capture)?;
            }
            SupervisorOperation::Stop => unreachable!(),
        }
        let state = match api.instance_info().await?.state {
            InstanceState::Running => ObservedState::Running,
            InstanceState::Paused => ObservedState::Paused,
            InstanceState::NotStarted => ObservedState::Starting,
        };
        let expected = match request.operation {
            SupervisorOperation::Pause => Some(ObservedState::Paused),
            SupervisorOperation::Resume => Some(ObservedState::Running),
            _ => None,
        };
        if expected.is_some_and(|value| value != state) {
            return Err(invalid("VMM lifecycle acknowledgement lacks expected observation").into());
        }
        match state {
            ObservedState::Running => machine.set_phase("running")?,
            ObservedState::Paused => machine.set_phase("paused")?,
            _ => (),
        }
        Ok(state)
    };
    let result: Result<ObservedState> = tokio::time::timeout(Duration::from_secs(8), operation)
        .await
        .unwrap_or_else(|_| Err(invalid("native lifecycle operation is uncertain").into()));
    let reply = match result {
        Ok(state) => SupervisorReply {
            generation: machine.generation,
            state,
            error: None,
        },
        Err(error) => {
            machine.record_error(error.to_string())?;
            SupervisorReply {
                generation: machine.generation,
                state: ObservedState::Unknown,
                error: Some(ApiError::new(
                    ErrorCode::BackendUnavailable,
                    "native lifecycle operation is unconfirmed",
                )),
            }
        }
    };
    write_reply(&mut stream, &reply).await?;
    Ok(stopping)
}

/// Root-only native service. It retains the jailer/VMM handles and bounded
/// console drain across API/worker failures, then confirms collection at expiry.
pub async fn run_supervisor(config: PathBuf, sandbox: Uuid, generation: Uuid) -> Result<()> {
    run_supervisor_with_input(config, sandbox, generation, None).await
}

pub async fn run_supervisor_with_input(
    config: PathBuf,
    sandbox: Uuid,
    generation: Uuid,
    input: Option<File>,
) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(invalid("native supervisor requires root").into());
    }
    let cfg: DriverConfig = read_json(&config)?;
    cfg.validate()?;
    let record_path = cfg.record_path(sandbox);
    let mut record: VmJournal = read_json(&record_path)?;
    record.validate(&cfg, sandbox)?;
    match (&record.selected_image, &input) {
        (None, None) => (),
        (Some(info), Some(file)) => cfg
            .prepared_images
            .as_ref()
            .ok_or_else(|| invalid("prepared images are not configured"))?
            .validate_input(info, file)?,
        _ => return Err(invalid("supervisor image descriptor and journal differ").into()),
    }
    if record.owner.generation != generation || record.phase != "reserved" {
        return Err(invalid("native supervisor launch intent mismatch").into());
    }
    let identity = process_identity(std::process::id())?;
    if identity.uid != 0 || identity.executable_sha256 != record.supervisor_artifact.sha256 {
        return Err(invalid("native supervisor executable mismatch").into());
    }
    let paths = cfg.paths(generation)?;
    let _group = super::cgroup::recorded(
        &paths.supervisor_cgroup,
        record.supervisor_cgroup_identity.as_ref(),
        &record.owner,
    )?
    .ok_or_else(|| invalid("supervisor cgroup receipt is absent"))?;
    let cg = std::fs::read_to_string("/proc/self/cgroup")?;
    if !cg.lines().any(|line| {
        line == format!(
            "0::/{}",
            paths
                .supervisor_cgroup
                .file_name()
                .unwrap()
                .to_string_lossy()
        )
    }) {
        return Err(invalid("native supervisor cgroup mismatch").into());
    }
    validate_original_cgroup(&record.original_cgroup)?;
    record.supervisor = Some(identity);
    atomic_json(&record_path, &record)?;
    let original = record.original_cgroup.clone();
    let artifacts = record.artifacts.clone();
    let mut machine = Machine::persistent(&cfg, record)?;
    if let Some(file) = input {
        machine.prepared_input(file)?;
    }
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let started = tokio::select! {
        result=machine.start(&artifacts)=>result,
        _=term.recv()=>Err(invalid("native creation interrupted; collecting owned generation").into()),
    };
    let result:Result<()>=match started {
        Ok(_)=>async {
            let endpoint=machine.root.join("control.sock");
            let listener=UnixListener::bind(&endpoint)?;
            std::fs::set_permissions(&endpoint,std::fs::Permissions::from_mode(0o600))?;
            let mut tick=tokio::time::interval(Duration::from_millis(100));
            loop {
                tokio::select! {
                    _=tick.tick()=>{if machine.record().expired()? || machine.exited()? || machine.record().phase=="unknown" {break;}},
                    _=term.recv()=>break,
                    stream=listener.accept()=>{
                        let (stream,_)=stream?;
                        let deadline=machine.record().clone();
                        tokio::select! {
                            result=call(&mut machine,stream,cfg.checkpoints.is_some())=>{if matches!(result,Ok(true)) {return Ok(());}},
                            _=async {loop {if deadline.expired().unwrap_or(true){break;}tokio::time::sleep(Duration::from_millis(50)).await;}}=>break,
                        }
                    }
                }
            }
            let reason=machine.record().error.clone().unwrap_or_else(||"native absolute expiry, stop or VMM exit".into());
            stop_vm(&mut machine,Some(reason)).await
        }.await,
        Err(error)=>{let text=error.to_string();stop_vm(&mut machine,Some(text.clone())).await.and_then(|_|Err(invalid(text).into()))},
    };
    if result.is_err() && machine.record().phase != "vm_collected" {
        let _ = stop_vm(
            &mut machine,
            Some("native supervisor operation failed; fencing owned VM".into()),
        )
        .await;
    }
    // Leave only this owned process in its original host group, then remove the
    // positively empty supervisor group. Never move or kill unrelated members.
    if machine.record().phase == "vm_collected" {
        if std::fs::write(original.join("cgroup.procs"), b"0").is_err() {
            // The original worker's service group can disappear while it is
            // down. Only after VMM collection, move this owned helper itself to
            // the stable hierarchy root so its empty group can still be removed.
            validate_original_cgroup(Path::new("/sys/fs/cgroup"))?;
            std::fs::write("/sys/fs/cgroup/cgroup.procs", b"0")?;
        }
        collect_supervisor_cgroup(&cfg, machine.record())?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{HostCapacity, VmOwner};

    #[tokio::test]
    async fn actual_root_ipc_policy_rejection_preserves_the_source_journal_without_runtime_dispatch()
     {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        // The unbooted Machine has no VMM/process/cgroup authority. Real kernel
        // root peer IPC must reject these intents before attempting its API.
        let directory = tempfile::Builder::new()
            .prefix("ghd-")
            .tempdir_in("/var/lib")
            .unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        private_directory(&directory.path().join("records")).unwrap();
        let artifact = Artifact {
            path: "/operator/artifact".into(),
            sha256: "a".repeat(64),
            size: 1,
        };
        let resources = ResourceLimits {
            cpu_millis: 1000,
            memory_bytes: 256 * MIB,
            pids: 32,
        };
        let cfg = DriverConfig {
            installation_id: Uuid::new_v4(),
            data_root: directory.path().into(),
            artifacts: BootInput {
                firecracker: artifact.clone(),
                jailer: artifact.clone(),
                kernel: artifact.clone(),
                rootfs: artifact.clone(),
            },
            supervisor: artifact.clone(),
            image: format!("sha256:{}", "a".repeat(64)),
            prepared_images: None,
            checkpoints: Some(crate::checkpoint::CheckpointStorePolicy {
                max_bytes: 2 * 1024 * MIB,
                max_checkpoints: 1,
            }),
            max_resources: resources.clone(),
            capacity: HostCapacity::default(),
            max_ttl_seconds: 300,
        };
        cfg.validate().unwrap();
        let hold = Uuid::new_v4();
        let record = VmJournal {
            format: 1,
            owner: VmOwner {
                installation_id: cfg.installation_id,
                sandbox_id: Uuid::new_v4(),
                generation: Uuid::new_v4(),
                request_sha256: "a".repeat(64),
                expires_at: Utc::now() + chrono::Duration::seconds(300),
                host_boot_id: boot_id().unwrap(),
                boot_deadline_ns: boottime_ns().unwrap() + 300_000_000_000,
            },
            artifacts: cfg.artifacts.clone(),
            selected_image: None,
            profile_probe_context_sha256: None,
            capture_hold: Some(hold),
            resources,
            supervisor: None,
            supervisor_cgroup_identity: None,
            vm_cgroup_identity: None,
            vm_root: None,
            root_collection_started: false,
            supervisor_artifact: artifact,
            original_cgroup: "/sys/fs/cgroup".into(),
            process: None,
            phase: "paused".into(),
            ever_ready: true,
            error: None,
            console_tail: String::new(),
            supervisor_stderr_tail: String::new(),
            supervisor_cgroup_events: Default::default(),
        };
        let path = cfg.record_path(record.owner.sandbox_id);
        let original = serde_json::to_vec(&record).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&original).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut machine = Machine::persistent(&cfg, record).unwrap();
        for (operation, expected) in [
            (SupervisorOperation::Resume, ErrorCode::InvalidState),
            (
                SupervisorOperation::CaptureHold {
                    capture: Uuid::new_v4(),
                },
                ErrorCode::Conflict,
            ),
            (
                SupervisorOperation::CaptureHold {
                    capture: Uuid::nil(),
                },
                ErrorCode::InvalidRequest,
            ),
        ] {
            let (server, mut client) = UnixStream::pair().unwrap();
            let mut bytes = serde_json::to_vec(&SupervisorCall {
                owner: machine.record().owner.clone(),
                operation,
            })
            .unwrap();
            bytes.push(b'\n');
            let receive = async move {
                client.write_all(&bytes).await.unwrap();
                let mut reader = BufReader::new(client);
                let bytes = read_frame(&mut reader, 65536).await.unwrap();
                serde_json::from_slice::<SupervisorReply>(&bytes).unwrap()
            };
            let (stopped, reply) = tokio::join!(call(&mut machine, server, true), receive);
            assert!(!stopped.unwrap());
            assert_eq!(reply.generation, machine.generation);
            assert_eq!(reply.error.unwrap().code, expected);
            assert_eq!(machine.record().phase, "paused");
            assert!(machine.record().error.is_none());
            assert_eq!(machine.record().capture_hold, Some(hold));
            assert!(machine.process.is_none());
            assert_eq!(
                std::fs::read(&path).unwrap(),
                original,
                "policy rejection must not write unknown or stop intent"
            );
        }
        // A genuine unavailable runtime still poisons the journal. Status must
        // not turn that Unknown back into Running/Paused before the expiry loop
        // fences the original generation.
        let (server, mut client) = UnixStream::pair().unwrap();
        let mut bytes = serde_json::to_vec(&SupervisorCall {
            owner: machine.record().owner.clone(),
            operation: SupervisorOperation::Pause,
        })
        .unwrap();
        bytes.push(b'\n');
        let receive = async move {
            client.write_all(&bytes).await.unwrap();
            let mut r = BufReader::new(client);
            let b = read_frame(&mut r, 65536).await.unwrap();
            serde_json::from_slice::<SupervisorReply>(&b).unwrap()
        };
        let (_, reply) = tokio::join!(call(&mut machine, server, true), receive);
        assert!(reply.error.is_some());
        assert_eq!(machine.record().phase, "unknown");
        assert!(machine.record().error.is_some());
        let poisoned = std::fs::read(&path).unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        let mut bytes = serde_json::to_vec(&SupervisorCall {
            owner: machine.record().owner.clone(),
            operation: SupervisorOperation::Status,
        })
        .unwrap();
        bytes.push(b'\n');
        let receive = async move {
            client.write_all(&bytes).await.unwrap();
            let mut r = BufReader::new(client);
            let b = read_frame(&mut r, 65536).await.unwrap();
            serde_json::from_slice::<SupervisorReply>(&b).unwrap()
        };
        let (stopped, reply) = tokio::join!(call(&mut machine, server, true), receive);
        assert!(!stopped.unwrap());
        assert!(reply.error.is_some());
        assert_eq!(machine.record().phase, "unknown");
        assert_eq!(std::fs::read(&path).unwrap(), poisoned);
        drop(machine);
        let path = directory.path().to_owned();
        directory.close().unwrap();
        assert!(!path.exists());
    }
}
