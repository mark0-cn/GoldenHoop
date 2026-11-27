//! Installation service. VM supervisors remain children of this persistent
//! process when a worker or short-lived operator client exits.
use super::recovery::{ManagerRecovery, PathIdentity};
use super::*;
use crate::{
    api::{PeerIdentity, authenticated_socket},
    vsock::read_frame,
};
use async_trait::async_trait;
use goldenhoop_runtime::*;
use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{Notify, RwLock, Semaphore},
    task::JoinSet,
};

pub(super) const MANAGER_MEMORY: u64 = 768 * MIB;
const FRAME_LIMIT: usize = crate::vsock::MAX_AGENT_FRAME;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagerRecord {
    format: u32,
    installation_id: Uuid,
    epoch: Uuid,
    config_sha256: String,
    process: ProcessIdentity,
    cgroup: PathBuf,
    original_cgroup: PathBuf,
    ready: bool,
    #[serde(default)]
    socket_identity: Option<PathIdentity>,
    #[serde(default)]
    cgroup_identity: Option<PathIdentity>,
    #[serde(default)]
    recovery: Option<ManagerRecovery>,
    #[serde(default)]
    metadata_recovery: metadata::Recovery,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Call { call: Box<DriverCall> },
    Shutdown,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    installation_id: Uuid,
    epoch: Uuid,
    config_sha256: String,
    operation: Operation,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    installation_id: Uuid,
    epoch: Uuid,
    config_sha256: String,
    result: std::result::Result<serde_json::Value, ApiError>,
}

fn config_sha(cfg: &DriverConfig) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(cfg)?)))
}
fn manager_group(cfg: &DriverConfig, epoch: Uuid) -> PathBuf {
    Path::new("/sys/fs/cgroup").join(format!(
        "ghm-{}-{}",
        cfg.installation_id.simple(),
        epoch.simple()
    ))
}
fn validate_manager_record(cfg: &DriverConfig, owner: &ManagerRecord) -> Result<()> {
    if owner.format != 1
        || owner.epoch.is_nil()
        || owner.installation_id != cfg.installation_id
        || owner.config_sha256 != config_sha(cfg)?
        || owner.process.pid <= 1
        || owner.process.pid > i32::MAX as u32
        || owner.process.start_ticks == 0
        || owner.process.uid != 0
        || Uuid::parse_str(&owner.process.boot_id)
            .ok()
            .is_none_or(|id| id.is_nil() || id.to_string() != owner.process.boot_id)
        || owner.process.executable_sha256 != cfg.supervisor.sha256
        || owner.cgroup != manager_group(cfg, owner.epoch)
        || !owner.original_cgroup.starts_with("/sys/fs/cgroup")
        || owner.original_cgroup.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid("native manager identity or configuration mismatch").into());
    }
    Ok(())
}
fn unavailable() -> ApiError {
    let mut error = ApiError::new(
        ErrorCode::BackendUnavailable,
        "native manager exchange is unconfirmed; reconcile the owned generation",
    );
    error.retryable = false;
    error
}
fn deadline(call: &DriverCall) -> Duration {
    Duration::from_secs(match call {
        DriverCall::Probe => 240,
        DriverCall::Create { .. } => 150,
        DriverCall::Remove { .. } => 45,
        DriverCall::Reap => 240,
        _ => 20,
    })
}

/// Root-only client of the independently supervised installation service.
#[derive(Clone)]
pub struct FirecrackerDriver {
    cfg: Arc<DriverConfig>,
    profile: Arc<RwLock<RuntimeProfile>>,
}
impl FirecrackerDriver {
    pub fn connect(cfg: DriverConfig) -> Result<Self> {
        cfg.validate()?;
        if unsafe { libc::geteuid() } != 0 {
            return Err(invalid("native manager client requires root").into());
        }
        let profile = Arc::new(RwLock::new(super::driver::profile(&cfg)));
        Ok(Self {
            cfg: Arc::new(cfg),
            profile,
        })
    }

    fn manager(&self) -> Result<(ManagerRecord, OwnedFd)> {
        let cfg = &self.cfg;
        let owner: ManagerRecord = read_json(&cfg.data_root.join("manager.json"))?;
        validate_manager_record(cfg, &owner)?;
        if !owner.ready
            || !PathIdentity::verify(
                &cfg.data_root.join("manager.sock"),
                owner.socket_identity.as_ref(),
                true,
            )?
            || !PathIdentity::verify(&owner.cgroup, owner.cgroup_identity.as_ref(), false)?
        {
            return Err(invalid("native manager identity or configuration mismatch").into());
        }
        let fd = track_process(&owner.process)?;
        if pidfd_exited(&fd)? {
            return Err(invalid("native manager is not live").into());
        }
        Ok((owner, fd))
    }

    async fn exchange(
        &self,
        operation: Operation,
        duration: Duration,
    ) -> std::result::Result<serde_json::Value, ApiError> {
        let exchange = async {
            let (owner, pidfd) = self.manager()?;
            if pidfd_exited(&pidfd)? {
                return Err(invalid("native manager exited").into());
            }
            let stream = authenticated_socket(
                &self.cfg.data_root.join("manager.sock"),
                PeerIdentity {
                    pid: owner.process.pid,
                    uid: 0,
                    instance: owner.epoch,
                },
            )
            .await?;
            let mut stream = BufReader::new(stream);
            let mut bytes = serde_json::to_vec(&Request {
                installation_id: owner.installation_id,
                epoch: owner.epoch,
                config_sha256: owner.config_sha256.clone(),
                operation,
            })?;
            if bytes.len() >= FRAME_LIMIT {
                return Err(invalid("native manager request exceeds frame limit").into());
            }
            bytes.push(b'\n');
            stream.get_mut().write_all(&bytes).await?;
            let frame = read_frame(&mut stream, FRAME_LIMIT).await?;
            let reply: Reply = serde_json::from_slice(&frame)?;
            if reply.installation_id != owner.installation_id
                || reply.epoch != owner.epoch
                || reply.config_sha256 != owner.config_sha256
                || pidfd_exited(&pidfd)?
            {
                return Err(invalid("native manager response ownership mismatch").into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(reply.result)
        };
        tokio::time::timeout(duration, exchange)
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?
    }
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        call: DriverCall,
    ) -> std::result::Result<T, ApiError> {
        let duration = deadline(&call);
        let value = self
            .exchange(
                Operation::Call {
                    call: Box::new(call),
                },
                duration,
            )
            .await?;
        serde_json::from_value(value).map_err(|_| unavailable())
    }
    pub async fn profile_snapshot(&self) -> RuntimeProfile {
        self.profile.read().await.clone()
    }
    pub async fn reap_expired(&self) -> std::result::Result<Vec<Uuid>, ApiError> {
        self.call(DriverCall::Reap).await
    }
    /// Acknowledges the stop request only. The service parent must still wait
    /// and observe actual service/process/cgroup collection.
    pub async fn request_manager_shutdown(&self) -> std::result::Result<(), ApiError> {
        let value = self
            .exchange(Operation::Shutdown, Duration::from_secs(10))
            .await?;
        if value != serde_json::json!({"stop_requested":true,"cleanup":"pending"}) {
            return Err(unavailable());
        }
        Ok(())
    }
}

#[async_trait]
impl RuntimeDriver for FirecrackerDriver {
    async fn probe(&self) -> RuntimeProfile {
        let result: std::result::Result<RuntimeProfile, ApiError> =
            self.call(DriverCall::Probe).await;
        let profile = result.unwrap_or_else(|_| {
            let mut value = super::driver::profile(&self.cfg);
            value.availability = Availability::Unavailable;
            value.reason = Some("native manager or actual lifecycle probe is unavailable".into());
            value
        });
        *self.profile.write().await = profile.clone();
        profile
    }
    async fn create(
        &self,
        sandbox: &Sandbox,
        request: &CreateSandbox,
    ) -> std::result::Result<RuntimeHandle, ApiError> {
        self.call(DriverCall::Create {
            sandbox: sandbox.clone(),
            request: request.clone(),
        })
        .await
    }
    async fn inspect(
        &self,
        handle: &RuntimeHandle,
    ) -> std::result::Result<RuntimeObservation, ApiError> {
        self.call(DriverCall::Inspect {
            handle: handle.clone(),
        })
        .await
    }
    async fn remove(&self, handle: &RuntimeHandle) -> std::result::Result<(), ApiError> {
        self.call(DriverCall::Remove {
            handle: handle.clone(),
        })
        .await
    }
    async fn discover(&self) -> std::result::Result<Vec<RuntimeHandle>, ApiError> {
        self.call(DriverCall::Discover).await
    }
    async fn pause(&self, handle: &RuntimeHandle) -> std::result::Result<(), ApiError> {
        self.call(DriverCall::Pause {
            handle: handle.clone(),
        })
        .await
    }
    async fn resume(&self, handle: &RuntimeHandle) -> std::result::Result<(), ApiError> {
        self.call(DriverCall::Resume {
            handle: handle.clone(),
        })
        .await
    }
}
#[async_trait]
impl AgentTransport for FirecrackerDriver {
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
        self.call(DriverCall::Rpc {
            handle: handle.clone(),
            request: request.clone(),
        })
        .await
    }
}

async fn dispatch(
    engine: &super::driver::NativeEngine,
    call: DriverCall,
) -> std::result::Result<serde_json::Value, ApiError> {
    let data = match call {
        DriverCall::Probe => serde_json::to_value(engine.probe().await),
        DriverCall::Create { sandbox, request } => {
            serde_json::to_value(engine.create(&sandbox, &request).await?)
        }
        DriverCall::Inspect { handle } => serde_json::to_value(engine.inspect(&handle).await?),
        DriverCall::Remove { handle } => {
            engine.remove(&handle).await?;
            Ok(serde_json::Value::Null)
        }
        DriverCall::Discover => serde_json::to_value(engine.discover().await?),
        DriverCall::Pause { handle } => {
            engine.pause(&handle).await?;
            Ok(serde_json::Value::Null)
        }
        DriverCall::Resume { handle } => {
            engine.resume(&handle).await?;
            Ok(serde_json::Value::Null)
        }
        DriverCall::Rpc { handle, request } => {
            serde_json::to_value(engine.rpc_reply(&handle, &request).await?)
        }
        DriverCall::Reap => serde_json::to_value(engine.reap_expired().await?),
    };
    data.map_err(|_| ApiError::new(ErrorCode::Internal, "cannot encode native manager result"))
}

async fn serve(
    stream: UnixStream,
    owner: ManagerRecord,
    engine: super::driver::NativeEngine,
    shutdown: Arc<Notify>,
    rpc_permits: Arc<Semaphore>,
) -> Result<()> {
    if stream.peer_cred()?.uid() != 0 {
        return Err(invalid("native manager peer is not root").into());
    }
    let mut stream = BufReader::new(stream);
    let frame = tokio::time::timeout(
        Duration::from_secs(10),
        read_frame(&mut stream, FRAME_LIMIT),
    )
    .await??;
    let request: Request = serde_json::from_slice(&frame)?;
    drop(frame);
    if request.installation_id != owner.installation_id
        || request.epoch != owner.epoch
        || request.config_sha256 != owner.config_sha256
    {
        return Err(invalid("native manager request ownership mismatch").into());
    }
    let stop = matches!(request.operation, Operation::Shutdown);
    let _rpc_permit = if matches!(&request.operation,Operation::Call{call} if matches!(call.as_ref(),DriverCall::Rpc{..}))
    {
        Some(
            rpc_permits
                .acquire_owned()
                .await
                .map_err(|_| invalid("native RPC admission stopped"))?,
        )
    } else {
        None
    };
    let result = match request.operation {
        Operation::Shutdown => Ok(serde_json::json!({"stop_requested":true,"cleanup":"pending"})),
        Operation::Call { call } => dispatch(&engine, *call).await,
    };
    let mut bytes = serde_json::to_vec(&Reply {
        installation_id: owner.installation_id,
        epoch: owner.epoch,
        config_sha256: owner.config_sha256,
        result,
    })?;
    if bytes.len() >= FRAME_LIMIT {
        return Err(invalid("native manager reply exceeds frame limit").into());
    }
    bytes.push(b'\n');
    let sent =
        tokio::time::timeout(Duration::from_secs(10), stream.get_mut().write_all(&bytes)).await;
    if stop {
        shutdown.notify_one();
    }
    sent??;
    stream.get_mut().shutdown().await?;
    Ok(())
}

fn check_manager_group(record: &ManagerRecord) -> Result<bool> {
    if PathIdentity::verify(&record.cgroup, record.cgroup_identity.as_ref(), false)? {
        if record.process.boot_id != boot_id()? || !supervisor::cgroup_empty(&record.cgroup)? {
            return Err(invalid("native manager cgroup collection unconfirmed").into());
        }
        return Ok(true);
    }
    Ok(false)
}
fn remove_manager_group(record: &ManagerRecord) -> Result<()> {
    if check_manager_group(record)? {
        std::fs::remove_dir(&record.cgroup)?;
    }
    if !super::recovery::absent(&record.cgroup)? {
        return Err(invalid("native manager cgroup remains").into());
    }
    Ok(())
}
fn remove_socket(path: &Path, recorded: Option<&PathIdentity>) -> Result<()> {
    if PathIdentity::verify(path, recorded, true)? {
        std::fs::remove_file(path)?;
    }
    if !super::recovery::absent(path)? {
        return Err(invalid("native manager socket remains").into());
    }
    File::open(
        path.parent()
            .ok_or_else(|| invalid("native manager socket has no parent"))?,
    )?
    .sync_all()?;
    Ok(())
}

/// Foreground installation service. Its service supervisor owns this process;
/// it retains and reaps all per-VM supervisors across worker/client failures.
pub async fn run_manager(config: PathBuf) -> Result<()> {
    let cfg = DriverConfig::read(&config)?;
    if unsafe { libc::geteuid() } != 0 {
        return Err(invalid("native manager requires root").into());
    }
    let process = process_identity(std::process::id())?;
    if process.executable_sha256 != cfg.supervisor.sha256 {
        return Err(invalid("native manager executable mismatch").into());
    }
    let lease = metadata::claim_installation(&cfg.data_root, cfg.installation_id)?;
    let mut metadata_recovery = metadata::recover_entries(
        &cfg.data_root,
        &["config.json", "manager.json"],
        false,
        |name, bytes| {
            if name == "config.json" {
                let stored: DriverConfig = serde_json::from_slice(bytes)?;
                if config_sha(&stored)? != config_sha(&cfg)? {
                    return Err(invalid("pending native configuration differs").into());
                }
                stored.validate()
            } else {
                let stored: ManagerRecord = serde_json::from_slice(bytes)?;
                validate_manager_record(&cfg, &stored)
            }
        },
    )?;
    let marker = cfg.data_root.join("manager.json");
    let socket = cfg.data_root.join("manager.sock");
    let old = if !super::recovery::absent(&marker)? {
        let old: ManagerRecord = read_json(&marker)?;
        validate_manager_record(&cfg, &old)?;
        let persisted: DriverConfig = read_json(&cfg.data_root.join("config.json"))?;
        if config_sha(&persisted)? != old.config_sha256 {
            return Err(invalid("native persisted configuration differs before recovery").into());
        }
        if !super::reaper::process_absent(&old.process)? {
            return Err(invalid("previous native manager process absence is unconfirmed").into());
        }
        check_manager_group(&old)?;
        PathIdentity::verify(&socket, old.socket_identity.as_ref(), true)?;
        Some(old)
    } else {
        if !super::recovery::absent(&socket)? {
            return Err(invalid("unowned native manager socket exists").into());
        }
        None
    };
    let engine = super::driver::NativeEngine::connect(cfg.clone(), lease)?;
    let records = engine.metadata_recovery();
    metadata_recovery.completed.extend(
        records
            .completed
            .into_iter()
            .map(|name| format!("records/{name}")),
    );
    metadata_recovery.unconfirmed.extend(
        records
            .unconfirmed
            .into_iter()
            .map(|name| format!("records/{name}")),
    );
    if engine.recovered_count() > 0
        && old
            .as_ref()
            .is_none_or(|owner| owner.process.boot_id != process.boot_id)
    {
        return Err(invalid("native generations have no same-boot manager recovery fence").into());
    }
    let recovery = if let Some(previous) = &old {
        Some(ManagerRecovery {
            previous_epoch: previous.epoch,
            previous_process: previous.process.clone(),
            observed_at: Utc::now(),
            generations: engine.observe_recovery().await?,
        })
    } else {
        None
    };
    if let Some(previous) = &old {
        remove_manager_group(previous)?;
        remove_socket(&socket, previous.socket_identity.as_ref())?;
        let current: ManagerRecord = read_json(&marker)?;
        if serde_json::to_value(current)? != serde_json::to_value(previous)? {
            return Err(
                invalid("native manager marker changed before recovery publication").into(),
            );
        }
    }
    atomic_json(&cfg.data_root.join("config.json"), &cfg)?;
    let epoch = Uuid::new_v4();
    let mut owner = ManagerRecord {
        format: 1,
        installation_id: cfg.installation_id,
        epoch,
        config_sha256: config_sha(&cfg)?,
        process,
        cgroup: manager_group(&cfg, epoch),
        original_cgroup: supervisor::original_cgroup()?,
        ready: false,
        socket_identity: None,
        cgroup_identity: None,
        recovery,
        metadata_recovery,
    };
    // Retain the old epoch until its replacement is durable. A crash cannot
    // erase the only manager fence while live generation journals remain.
    if old.is_some() {
        atomic_json(&marker, &owner)?;
    } else {
        metadata::initial_json(&marker, &owner)?;
    }
    let mut owns_group = false;
    let mut owns_socket = false;
    let result=async {
        std::fs::create_dir(&owner.cgroup)?;owns_group=true;
        owner.cgroup_identity=Some(PathIdentity::capture(&owner.cgroup,false)?);
        atomic_json(&marker,&owner)?;
        for (name,value) in [("cpu.max","100000 100000".to_owned()),("memory.max",MANAGER_MEMORY.to_string()),("memory.swap.max","0".into()),("pids.max","32".into())]{
            std::fs::write(owner.cgroup.join(name),&value)?;
            if std::fs::read_to_string(owner.cgroup.join(name))?.trim()!=value{return Err(invalid("native manager resource readback mismatch").into());}
        }
        std::fs::write(owner.cgroup.join("cgroup.procs"),b"0")?;
        if unsafe{libc::prctl(libc::PR_SET_NO_NEW_PRIVS,1,0,0,0)}!=0 || unsafe{libc::prctl(libc::PR_SET_CHILD_SUBREAPER,1,0,0,0)}!=0{return Err(io::Error::last_os_error().into());}
        let listener=UnixListener::bind(&socket)?;owns_socket=true;
        std::fs::set_permissions(&socket,std::fs::Permissions::from_mode(0o600))?;
        owner.socket_identity=Some(PathIdentity::capture(&socket,true)?);
        owner.ready=true;atomic_json(&marker,&owner)?;
        let shutdown=Arc::new(Notify::new());
        let permits=Arc::new(Semaphore::new(8));
        let rpc_permits=Arc::new(Semaphore::new(2));
        let reap_permits=Arc::new(Semaphore::new(1));
        let mut tasks=JoinSet::new();
        let mut term=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut interrupt=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut tick=tokio::time::interval(Duration::from_secs(1));
        loop{
            tokio::select!{
                _=shutdown.notified()=>break,
                _=term.recv()=>break,
                _=interrupt.recv()=>break,
                _=tick.tick()=>{let _=engine.reap_children();if let Ok(permit)=reap_permits.clone().try_acquire_owned(){let actor=engine.clone();tasks.spawn(async move{let _permit=permit;let _=actor.reap_expired().await;});}},
                Some(_)=tasks.join_next()=>(),
                incoming=listener.accept()=>{
                    let (stream,_)=match incoming{Ok(value)=>value,Err(_)=>{tokio::time::sleep(Duration::from_millis(100)).await;continue;}};
                    if let Ok(permit)=permits.clone().try_acquire_owned(){
                        let actor=engine.clone();let owner=owner.clone();let stop=shutdown.clone();let rpc=rpc_permits.clone();
                        tasks.spawn(async move{let _permit=permit;let _=serve(stream,owner,actor,stop,rpc).await;});
                    }
                }
            }
        }
        drop(listener);
        owner.ready=false;let _=atomic_json(&marker,&owner);
        tasks.abort_all();while tasks.join_next().await.is_some(){}
        // Keep the reaping parent alive until every owned generation is
        // actually collected. An acknowledgement never substitutes for this.
        loop{
            let handles=match engine.discover().await{Ok(value)=>value,Err(_)=>{tokio::time::sleep(Duration::from_millis(100)).await;continue;}};
            if handles.is_empty() && engine.children_collected().unwrap_or(false){break;}
            for handle in handles{let _=engine.remove(&handle).await;}
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
    }.await;
    if owns_socket {
        remove_socket(&socket, owner.socket_identity.as_ref())?;
    }
    if owns_group {
        if std::fs::write(owner.original_cgroup.join("cgroup.procs"), b"0").is_err() {
            std::fs::write("/sys/fs/cgroup/cgroup.procs", b"0")?;
        }
        remove_manager_group(&owner)?;
    }
    let actual: ManagerRecord = read_json(&marker)?;
    if serde_json::to_value(actual)? != serde_json::to_value(&owner)? {
        return Err(invalid("native manager marker changed during collection").into());
    }
    std::fs::remove_file(&marker)?;
    File::open(&cfg.data_root)?.sync_all()?;
    if marker.try_exists()? || socket.try_exists()? {
        return Err(invalid("native manager metadata collection incomplete").into());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn recovery_record_requires_exact_configuration_epoch_executable_and_scope() {
        // Shape validation is not process/socket authentication or KVM proof.
        let artifact = Artifact {
            path: "/operator/artifact".into(),
            sha256: "a".repeat(64),
            size: 1,
        };
        let cfg = DriverConfig {
            installation_id: Uuid::new_v4(),
            data_root: "/var/lib/gm".into(),
            artifacts: BootInput {
                firecracker: artifact.clone(),
                jailer: artifact.clone(),
                kernel: artifact.clone(),
                rootfs: artifact.clone(),
            },
            supervisor: artifact,
            image: format!("sha256:{}", "a".repeat(64)),
            max_resources: ResourceLimits {
                cpu_millis: 1000,
                memory_bytes: 256 * MIB,
                pids: 32,
            },
            capacity: HostCapacity::default(),
            max_ttl_seconds: 300,
        };
        cfg.validate().unwrap();
        let epoch = Uuid::new_v4();
        let mut record = ManagerRecord {
            format: 1,
            installation_id: cfg.installation_id,
            epoch,
            config_sha256: config_sha(&cfg).unwrap(),
            process: ProcessIdentity {
                pid: 42,
                start_ticks: 1,
                boot_id: boot_id().unwrap(),
                executable_sha256: cfg.supervisor.sha256.clone(),
                uid: 0,
            },
            cgroup: manager_group(&cfg, epoch),
            original_cgroup: "/sys/fs/cgroup".into(),
            ready: false,
            socket_identity: None,
            cgroup_identity: None,
            recovery: None,
            metadata_recovery: Default::default(),
        };
        validate_manager_record(&cfg, &record).unwrap();
        let mut changed = cfg.clone();
        changed.capacity.cpu_millis += 1;
        assert!(validate_manager_record(&changed, &record).is_err());
        changed = cfg.clone();
        changed.installation_id = Uuid::new_v4();
        assert!(validate_manager_record(&changed, &record).is_err());
        record.process.executable_sha256 = "b".repeat(64);
        assert!(validate_manager_record(&cfg, &record).is_err());
        record.process.executable_sha256 = cfg.supervisor.sha256.clone();
        record.epoch = Uuid::nil();
        assert!(validate_manager_record(&cfg, &record).is_err());
        record.epoch = epoch;
        record.cgroup = "/sys/fs/cgroup/foreign".into();
        assert!(validate_manager_record(&cfg, &record).is_err());
        record.cgroup = manager_group(&cfg, epoch);
        record.process.boot_id = Uuid::nil().to_string();
        assert!(validate_manager_record(&cfg, &record).is_err());
    }

    #[test]
    fn actual_socket_receipt_preserves_replacement_symlink_and_unrecorded_endpoint() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        use std::os::unix::{fs::symlink, net::UnixListener as Listener};
        let directory = tempfile::Builder::new()
            .prefix("ghm-receipt-")
            .tempdir_in("/var/lib")
            .unwrap();
        let socket = directory.path().join("manager.sock");
        let old = Listener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let receipt = PathIdentity::capture(&socket, true).unwrap();
        assert!(remove_socket(&socket, None).is_err());
        let saved = directory.path().join("saved.sock");
        std::fs::rename(&socket, &saved).unwrap();
        let replacement = Listener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let replacement_receipt = PathIdentity::capture(&socket, true).unwrap();
        assert!(remove_socket(&socket, Some(&receipt)).is_err());
        assert!(PathIdentity::verify(&socket, Some(&replacement_receipt), true).unwrap());
        let link = directory.path().join("link.sock");
        symlink(&saved, &link).unwrap();
        assert!(remove_socket(&link, Some(&receipt)).is_err());
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        drop(replacement);
        remove_socket(&socket, Some(&replacement_receipt)).unwrap();
        remove_socket(&socket, Some(&replacement_receipt)).unwrap();
        drop(old);
        remove_socket(&saved, Some(&receipt)).unwrap();
        let first = directory.path().join("group");
        std::fs::create_dir(&first).unwrap();
        let group_receipt = PathIdentity::capture(&first, false).unwrap();
        std::fs::rename(&first, directory.path().join("saved-group")).unwrap();
        std::fs::create_dir(&first).unwrap();
        assert!(PathIdentity::verify(&first, Some(&group_receipt), false).is_err());
        let path = directory.path().to_owned();
        directory.close().unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn manager_envelopes_cross_real_sockets_with_the_shared_frame_ceiling() {
        // Framing integration only. This fixture does not establish a usable
        // runtime, manager service or hardware capability.
        let installation_id = Uuid::new_v4();
        let epoch = Uuid::new_v4();
        let config_sha256 = "a".repeat(64);
        let encoded = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 16 * 1024 * 1024]);
        for operation in [
            Operation::Shutdown,
            Operation::Call {
                call: Box::new(DriverCall::Rpc {
                    handle: RuntimeHandle {
                        sandbox_id: Uuid::new_v4(),
                        profile: PROFILE.into(),
                        backend_ref: format!("fc1:{installation_id}:{}", Uuid::new_v4()),
                    },
                    request: AgentRequest::WriteFile {
                        path: "frame-boundary".into(),
                        data_base64: encoded.clone(),
                    },
                }),
            },
        ] {
            let (client, server) = UnixStream::pair().unwrap();
            let digest = config_sha256.clone();
            let responder = tokio::spawn(async move {
                let mut server = BufReader::new(server);
                let frame = read_frame(&mut server, FRAME_LIMIT).await.unwrap();
                let request: Request = serde_json::from_slice(&frame).unwrap();
                assert_eq!(request.installation_id, installation_id);
                assert_eq!(request.epoch, epoch);
                assert_eq!(request.config_sha256, digest);
                match request.operation {
                    Operation::Shutdown => (),
                    Operation::Call { call } => match *call {
                        DriverCall::Rpc {
                            request: AgentRequest::WriteFile { path, data_base64 },
                            ..
                        } => {
                            assert_eq!(path, "frame-boundary");
                            assert_eq!(
                                base64::engine::general_purpose::STANDARD
                                    .decode(data_base64)
                                    .unwrap()
                                    .len(),
                                16 * 1024 * 1024
                            );
                        }
                        _ => panic!("unexpected manager request"),
                    },
                }
                let mut reply = serde_json::to_vec(&Reply {
                    installation_id,
                    epoch,
                    config_sha256: digest,
                    result: Ok(serde_json::Value::Null),
                })
                .unwrap();
                reply.push(b'\n');
                server.get_mut().write_all(&reply).await.unwrap();
                server.get_mut().shutdown().await.unwrap();
            });
            let mut client = BufReader::new(client);
            let mut bytes = serde_json::to_vec(&Request {
                installation_id,
                epoch,
                config_sha256: config_sha256.clone(),
                operation,
            })
            .unwrap();
            assert!(bytes.len() < FRAME_LIMIT);
            bytes.push(b'\n');
            client.get_mut().write_all(&bytes).await.unwrap();
            let frame = read_frame(&mut client, FRAME_LIMIT).await.unwrap();
            let reply: Reply = serde_json::from_slice(&frame).unwrap();
            assert_eq!(reply.installation_id, installation_id);
            assert_eq!(reply.epoch, epoch);
            assert_eq!(reply.config_sha256, config_sha256);
            assert_eq!(reply.result.unwrap(), serde_json::Value::Null);
            responder.await.unwrap();
        }
        assert!(
            !unavailable().retryable,
            "an uncertain native transport must not request replay"
        );
    }
}
