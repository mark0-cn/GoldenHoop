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

async fn call(machine: &mut Machine, stream: UnixStream) -> Result<bool> {
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
        .map_err(|_| invalid("native lifecycle operation is uncertain"))?;
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
    let mut bytes = serde_json::to_vec(&reply)?;
    bytes.push(b'\n');
    stream.get_mut().write_all(&bytes).await?;
    stream.get_mut().shutdown().await?;
    Ok(stopping)
}

/// Root-only native service. It retains the jailer/VMM handles and bounded
/// console drain across API/worker failures, then confirms collection at expiry.
pub async fn run_supervisor(config: PathBuf, sandbox: Uuid, generation: Uuid) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(invalid("native supervisor requires root").into());
    }
    let cfg: DriverConfig = read_json(&config)?;
    cfg.validate()?;
    let record_path = cfg.record_path(sandbox);
    let mut record: VmJournal = read_json(&record_path)?;
    record.validate(&cfg, sandbox)?;
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
    let input = record.artifacts.clone();
    let mut machine = Machine::persistent(&cfg, record)?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let started = tokio::select! {
        result=machine.start(&input)=>result,
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
                            result=call(&mut machine,stream)=>{if matches!(result,Ok(true)) {return Ok(());}},
                            _=async {loop {if deadline.expired().unwrap_or(true){break;}tokio::time::sleep(Duration::from_millis(50)).await;}}=>break,
                        }
                    }
                }
            }
            stop_vm(&mut machine,Some("native absolute expiry, stop or VMM exit".into())).await
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
