//! Actual private continuation gate. Native-manager/public orchestration stays
//! separate; the core loader performs no test marker commands or workload writes.
use super::*;
use crate::checkpoint::{
    CheckpointProbeConfig, CheckpointReference, CheckpointRuntime,
    storage::{
        CheckpointStore, Destination, host_compatibility,
        restore::{RestoreAdmission, RestoreIntent, RestoreSession},
    },
};
use crate::control::{GuestAuthorityInfo, GuestBarrierInfo};
use goldenhoop_protocol::AgentReply;
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncWriteExt, BufReader};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreProbeConfig {
    pub artifacts: BootInput,
    pub checkpoint: CheckpointProbeConfig,
    pub reference: CheckpointReference,
    pub restoration: Uuid,
    pub target_sandbox: Uuid,
    pub target_generation: Uuid,
    pub marker_execution: Uuid,
    pub marker_hex: String,
    pub disk_marker_base64: String,
}
impl RestoreProbeConfig {
    pub fn read(path: &Path) -> Result<Self> {
        crate::lifecycle::read_json(path)
    }
}
#[derive(Debug, Serialize)]
pub struct RestoreProbeReport {
    pub result: String,
    pub cleanup: String,
    pub target: Option<GuestReport>,
    pub original_restoration: Option<serde_json::Value>,
    pub restoration_collection: Option<serde_json::Value>,
    pub checks: Vec<String>,
    pub source_absence_confirmed: bool,
    pub frozen_authority: Option<GuestAuthorityInfo>,
    pub thawed_barrier: Option<GuestBarrierInfo>,
    pub content_verified_after_target_collection: bool,
    pub error: Option<String>,
}
pub(crate) fn runtime(input: &BootInput) -> Result<CheckpointRuntime> {
    Ok(CheckpointRuntime {
        firecracker_version: crate::api::SUPPORTED_VMM_VERSION.into(),
        firecracker_sha256: input.firecracker.sha256.clone(),
        jailer_sha256: input.jailer.sha256.clone(),
        kernel_sha256: input.kernel.sha256.clone(),
        architecture: std::env::consts::ARCH.into(),
        host_compatibility_sha256: host_compatibility()?,
    })
}
fn backing(path: &Path, expected: &crate::checkpoint::CheckpointContent) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o222 != 0
        || metadata.nlink() != 1
        || digest(file)? != (expected.sha256.clone(), expected.size_bytes)
    {
        return Err(invalid("restored immutable backing file differs").into());
    }
    Ok(())
}
impl Machine {
    pub(crate) async fn restore_reserved(
        &mut self,
        input: &BootInput,
        session: &mut RestoreSession,
    ) -> Result<(AgentClient, GuestAuthorityInfo, GuestBarrierInfo)> {
        let intent = session.intent().clone();
        let manifest = session.manifest().clone();
        if let Some((_, record)) = &self.persistent
            && (record.phase != "reserved"
                || record
                    .restore
                    .as_ref()
                    .is_none_or(|binding| binding.intent != intent)
                || record.resources != manifest.resources
                || record.selected_image.is_some())
        {
            return Err(invalid(
                "persistent restore requires its original journal/session/resources",
            )
            .into());
        }
        if self.generation != intent.generation
            || self.root != intent.destination.path()
            || runtime(input)? != manifest.runtime
        {
            return Err(invalid("restore loader differs from its original target/runtime").into());
        }
        session.source_absent()?;
        self.resources = manifest.resources.clone();
        let files = session.files()?;
        let mut selected = input.clone();
        selected.rootfs.sha256 = manifest.disk.sha256.clone();
        selected.rootfs.size = manifest.disk.size_bytes;
        self.prepare_with_disk(&selected, Some(files.disk))?;
        session.allocated()?;
        let directory = self.jail.join("restore");
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555))?;
        crate::fileio::copy(
            files.state,
            &directory.join("state"),
            &manifest.state.sha256,
            manifest.state.size_bytes,
            0o444,
        )?;
        crate::fileio::copy(
            files.memory,
            &directory.join("memory"),
            &manifest.memory.sha256,
            manifest.memory.size_bytes,
            0o444,
        )?;
        File::open(&directory)?.sync_all()?;
        File::open(&self.jail)?.sync_all()?;
        session.launching()?;
        let api = self.launch(&selected).await?;
        session.tracked(api.peer_identity().pid)?;
        api.load_snapshot(&SnapshotLoad::paused(
            "/restore/state".into(),
            "/restore/memory".into(),
        )?)
        .await?;
        if api.instance_info().await?.state != InstanceState::Paused {
            return Err(invalid("restored target pause unconfirmed").into());
        }
        self.check_expiry()?;
        // The jailer deliberately chowns '/' to the VMM. Harden it only after
        // snapshot load creates its vsock listener and before any guest resumes.
        let jail = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.jail)?;
        if unsafe { libc::fchown(jail.as_raw_fd(), 0, 0) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        jail.set_permissions(std::fs::Permissions::from_mode(0o755))?;
        if jail.metadata()?.uid() != 0 || jail.metadata()?.mode() & 0o7777 != 0o755 {
            return Err(invalid("restore jail immutability boundary unconfirmed").into());
        }
        backing(&directory.join("state"), &manifest.state)?;
        backing(&directory.join("memory"), &manifest.memory)?;
        session.source_absent()?;
        self.check_expiry()?;
        // Only PID1/control becomes schedulable: the captured workload cgroup
        // remains frozen until its new authority is positively acknowledged.
        api.resume().await?;
        let agent = AgentClient::new(
            api.clone(),
            self.jail.join("vsock.sock"),
            52,
            Duration::from_secs(5),
        )?;
        let transfer = session.transfer();
        let until = tokio::time::Instant::now() + Duration::from_secs(45);
        let info = loop {
            match agent.transfer_authority(&transfer).await {
                Ok(info) => break info,
                Err(error) => {
                    if error.error.code == goldenhoop_protocol::ErrorCode::InvalidRequest
                        || self.exited()?
                        || tokio::time::Instant::now() >= until
                    {
                        return Err(error.into());
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        };
        session.transferred(&info)?;
        if agent.control_info().await?.pids != manifest.resources.pids {
            return Err(invalid("restored guest task ceiling differs").into());
        }
        let observed = self.observe(api.peer_identity().pid, &input.firecracker.sha256)?;
        if !observed.no_new_privileges
            || observed.effective_capabilities != "0000000000000000"
            || observed.seccomp_mode != 2
        {
            return Err(invalid("restored VMM host isolation differs").into());
        }
        self.process = Some(observed);
        session.source_absent()?;
        self.check_expiry()?;
        let thawed = agent.thaw(transfer.barrier).await?;
        session.activated(&thawed)?;
        if !matches!(rpc(&agent,AgentRequest::Ping).await?,AgentResponse::Pong{version} if version==env!("CARGO_PKG_VERSION"))
        {
            return Err(invalid("restored agent readiness unconfirmed").into());
        }
        self.check_expiry()?;
        self.journal(input, "running")?;
        Ok((agent, info, thawed))
    }
    async fn reject_old_scope(
        &self,
        input: &BootInput,
        source: Uuid,
        agent: &AgentClient,
    ) -> Result<()> {
        let api = self.api_for_restore(input)?;
        let socket =
            crate::api::authenticated_socket(&self.jail.join("vsock.sock"), api.peer_identity())
                .await?;
        let mut socket = BufReader::new(socket);
        socket.get_mut().write_all(b"CONNECT 52\n").await?;
        let acknowledgement = crate::vsock::read_frame(&mut socket, 32).await?;
        crate::vsock::parse_connect_ack(&acknowledgement)?;
        let path = format!("old-restore-{}", Uuid::new_v4());
        let request = crate::control::GuestRpcRequest::new(
            source,
            AgentRequest::WriteFile {
                path: path.clone(),
                data_base64: STANDARD.encode(b"stale"),
            },
        );
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(b'\n');
        socket.get_mut().write_all(&bytes).await?;
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            crate::vsock::read_frame(&mut socket, crate::vsock::MAX_AGENT_FRAME),
        )
        .await;
        match response {
            Ok(Err(_)) => (),
            Ok(Ok(bytes)) => {
                let reply: AgentReply = serde_json::from_slice(&bytes)?;
                if reply.into_result().is_ok() {
                    return Err(invalid("old source RPC was accepted by restored target").into());
                }
            }
            Err(_) => return Err(invalid("old scoped RPC refusal is unconfirmed").into()),
        }
        let reply = agent
            .rpc_reply(&AgentRequest::ReadFile {
                path,
                max_bytes: 32,
            })
            .await?;
        match reply.into_result() {
            Err(error) if error.code == goldenhoop_protocol::ErrorCode::NotFound => Ok(()),
            _ => Err(invalid("old source frame changed the restored drive").into()),
        }
    }
    fn api_for_restore(&self, input: &BootInput) -> Result<ApiClient> {
        let process = self
            .process
            .as_ref()
            .ok_or_else(|| invalid("restore target VMM absent"))?;
        self.observe(process.pid, &input.firecracker.sha256)?;
        Ok(ApiClient::new(
            self.jail.join("api.sock"),
            PeerIdentity {
                pid: process.pid,
                uid: VMM_UID,
                instance: self.generation,
            },
            Duration::from_secs(10),
        )?)
    }
}

pub async fn validate_restore(cfg: RestoreProbeConfig) -> RestoreProbeReport {
    let mut report = RestoreProbeReport {
        result: "failed".into(),
        cleanup: "not_started".into(),
        target: None,
        original_restoration: None,
        restoration_collection: None,
        checks: Vec::new(),
        source_absence_confirmed: false,
        frozen_authority: None,
        thawed_barrier: None,
        content_verified_after_target_collection: false,
        error: None,
    };
    let mut machine = Machine::for_generation(cfg.target_generation);
    let admission = (|| -> Result<_> {
        if cfg.marker_execution.is_nil()
            || cfg.marker_hex.len() != 64
            || !cfg
                .marker_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || cfg.checkpoint.capture != cfg.reference.capture
        {
            return Err(invalid("restore probe identity/oracle differs").into());
        }
        let store = CheckpointStore::open_or_initialize(&cfg.checkpoint)?;
        let intent = RestoreIntent {
            reference: cfg.reference.clone(),
            runtime: runtime(&cfg.artifacts)?,
            restoration: cfg.restoration,
            sandbox: cfg.target_sandbox,
            generation: cfg.target_generation,
            destination: Destination::observe(&machine.root, machine.generation)?,
        };
        let admission = store.claim_restore(intent)?;
        Ok((store, admission))
    })();
    let (store, mut session) = match admission {
        Ok((_, RestoreAdmission::Existing(original))) => {
            report.result = "existing".into();
            report.cleanup = "not_applicable".into();
            report.original_restoration = Some(original);
            return report;
        }
        Ok((store, RestoreAdmission::Granted(session))) => (store, session),
        Err(error) => {
            report.error = Some(error.to_string());
            return report;
        }
    };
    report.source_absence_confirmed = true;
    let mut target = GuestReport::empty(machine.generation);
    let result = {
        let operation = async {
            let (agent, authority, thawed) = machine
                .restore_reserved(&cfg.artifacts, &mut session)
                .await?;
            target.guest_started = true;
            report.frozen_authority = Some(authority);
            report.thawed_barrier = Some(thawed);
            report.checks.push("fresh_jailed_target_loads_paused_then_transfers_frozen_guest_authority_before_explicit_thaw".into());
            if !matches!(rpc(&agent,AgentRequest::ReadFile{path:"checkpoint-payload".into(),max_bytes:1024}).await?,AgentResponse::File{data_base64} if data_base64==cfg.disk_marker_base64)
            {
                return Err(invalid("restored independent drive payload differs").into());
            }
            rpc(
                &agent,
                AgentRequest::WriteFile {
                    path: "checkpoint-release".into(),
                    data_base64: String::new(),
                },
            )
            .await?;
            let until = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let AgentResponse::Execution(execution) = rpc(
                    &agent,
                    AgentRequest::Inspect {
                        id: cfg.marker_execution,
                    },
                )
                .await?
                else {
                    return Err(invalid("restored execution identity missing").into());
                };
                if execution.state.is_terminal() {
                    if execution.state != ExecutionState::Succeeded
                        || execution.exit_code != Some(0)
                        || execution.cleanup != CleanupState::Complete
                    {
                        return Err(invalid("original retained execution did not complete").into());
                    }
                    break;
                }
                if tokio::time::Instant::now() >= until {
                    return Err(invalid("restored original execution deadline").into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let AgentResponse::File { data_base64 } = rpc(
                &agent,
                AgentRequest::ReadFile {
                    path: "checkpoint-resumed".into(),
                    max_bytes: 128,
                },
            )
            .await?
            else {
                return Err(invalid("restored process RAM oracle missing").into());
            };
            if STANDARD.decode(data_base64)? != cfg.marker_hex.as_bytes() {
                return Err(
                    invalid("original process RAM token differs after continuation").into(),
                );
            }
            report.checks.push("original_captured_execution_finishes_without_Start_replay_and_emits_its_retained_random_RAM_token".into());
            machine
                .reject_old_scope(
                    &cfg.artifacts,
                    session.manifest().source.source_generation,
                    &agent,
                )
                .await?;
            report.checks.push("old_source_generation_frame_is_refused_on_the_new_physical_target_without_a_drive_effect".into());
            store.verify(&cfg.reference, |_, _| Ok(()))?;
            report.checks.push(
                "target_guest_drive_changes_leave_original_checkpoint_objects_unchanged".into(),
            );
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {result=operation=>result,_=term.recv()=>Err(invalid("restore interrupted; collecting original target").into())}
            }
            Err(error) => Err(error.into()),
        }
    };
    if let Err(error) = &result {
        let _ = session.fail(&error.to_string());
    }
    target.process = machine.process.clone();
    let cleanup = machine.collect(&mut target).await;
    target.passed = result.is_ok() && cleanup.is_ok();
    target.error = result.as_ref().err().map(ToString::to_string);
    if cleanup.is_ok() {
        target.cleanup = CleanupState::Complete;
    }
    drop(session);
    let finalization = (|| -> Result<()> {
        cleanup?;
        if !target.root_absent || !target.cgroup_absent || !target.vmm_reaped {
            return Err(invalid("restore target physical collection unconfirmed").into());
        }
        report.restoration_collection = Some(store.close_restore(cfg.reference.capture)?);
        store.verify(&cfg.reference, |_, _| Ok(()))?;
        report.content_verified_after_target_collection = true;
        report.cleanup = "complete".into();
        Ok(())
    })();
    if result.is_ok() && finalization.is_ok() {
        report.result = "passed".into();
    }
    report.error = match (result, finalization) {
        (Ok(()), Ok(())) => None,
        (a, b) => Some(format!(
            "operation={:?}; collection={:?}",
            a.err().map(|e| e.to_string()),
            b.err().map(|e| e.to_string())
        )),
    };
    if report.cleanup != "complete" {
        report.cleanup = "unknown".into();
    }
    report.target = Some(target);
    report
}
