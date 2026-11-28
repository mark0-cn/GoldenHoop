//! Native full capture from an exclusively owned Machine. Public driver
//! orchestration, restore authority and target loading remain separate work.
use super::*;
use crate::checkpoint::{
    CaptureIdentity, CheckpointContent, CheckpointFiles, CheckpointManifest, CheckpointProbeConfig,
    CheckpointReference, CheckpointRuntime, StagedCheckpoint,
    storage::{
        CaptureSession, CheckpointStore, Intent, SourceDirectory, Writer, host_compatibility,
    },
};
use crate::control::GuestBarrierPhase;
use sha2::Digest;
use std::io::{Seek, SeekFrom};

#[derive(Debug, Serialize)]
pub struct CheckpointCaptureReport {
    pub capture: Uuid,
    pub phase: String,
    pub reserved_bytes: u64,
    pub reference: Option<CheckpointReference>,
    pub source_running_after_admission_refusal: Option<bool>,
    pub store_reserved_bytes_after_admission_refusal: Option<u64>,
    pub memory_marker_hex: Option<String>,
    pub marker_execution: Option<Uuid>,
    pub disk_marker_base64: Option<String>,
    pub memory_marker_found: bool,
    pub verified_after_source_collection: bool,
}
impl CheckpointCaptureReport {
    fn new(capture: Uuid) -> Self {
        Self {
            capture,
            phase: "admission".into(),
            reserved_bytes: 0,
            reference: None,
            source_running_after_admission_refusal: None,
            store_reserved_bytes_after_admission_refusal: None,
            memory_marker_hex: None,
            marker_execution: None,
            disk_marker_base64: None,
            memory_marker_found: false,
            verified_after_source_collection: false,
        }
    }
}
fn output(path: &Path, size: Option<u64>, maximum: u64) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.uid() != VMM_UID
        || m.mode() & 0o022 != 0
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > maximum
        || size.is_some_and(|s| m.len() != s)
    {
        return Err(invalid("native capture output type/owner/link count/length differs").into());
    }
    Ok(f)
}
fn content(f: &File) -> Result<CheckpointContent> {
    let (sha256, size_bytes) = digest(f.try_clone()?)?;
    Ok(CheckpointContent {
        id: Uuid::new_v4(),
        sha256,
        size_bytes,
    })
}
fn has_marker(file: &File, marker: &[u8]) -> Result<bool> {
    if marker.is_empty() || marker.len() > 128 {
        return Err(invalid("invalid capture test marker").into());
    }
    let mut input = file.try_clone()?;
    input.seek(SeekFrom::Start(0))?;
    let mut buffer = [0u8; 65536];
    let mut tail = Vec::new();
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            return Ok(false);
        }
        tail.extend_from_slice(&buffer[..count]);
        if tail.windows(marker.len()).any(|w| w == marker) {
            return Ok(true);
        }
        let keep = marker.len().saturating_sub(1);
        tail.drain(..tail.len().saturating_sub(keep));
    }
}
async fn reply(agent: &AgentClient, request: AgentRequest) -> Result<AgentResponse> {
    super::rpc(agent, request).await
}

impl Machine {
    pub(super) fn capture_api(&self, input: &BootInput) -> Result<ApiClient> {
        let process = self
            .process
            .as_ref()
            .ok_or_else(|| invalid("native capture has no owned VMM"))?;
        if self.exited()? {
            return Err(invalid("native capture VMM exited").into());
        }
        let observed = self.observe(process.pid, &input.firecracker.sha256)?;
        if observed.start_ticks != process.start_ticks
            || observed.boot_id != process.boot_id
            || observed.uid != process.uid
        {
            return Err(invalid("native capture process identity changed").into());
        }
        Ok(ApiClient::new(
            self.jail.join("api.sock"),
            PeerIdentity {
                pid: process.pid,
                uid: VMM_UID,
                instance: self.generation,
            },
            Duration::from_secs(120),
        )?)
    }
    async fn memory_marker(&self, agent: &AgentClient) -> Result<(Vec<u8>, Uuid)> {
        let id = Uuid::new_v4();
        let mut command = CommandSpec::new([
            "python3",
            "-c",
            "import os,time;from pathlib import Path;token=os.urandom(32);print(token.hex(),flush=True)\nwhile not Path('/workspace/checkpoint-release').exists(): time.sleep(.1)\nPath('/workspace/checkpoint-resumed').write_text(token.hex())\nprint('restored:'+token.hex(),flush=True)\n",
        ]);
        command.timeout_seconds = 120;
        command.max_output_bytes = 512;
        if !matches!(reply(agent,AgentRequest::Start {id,command}).await?,AgentResponse::Execution(e) if e.id==id)
        {
            return Err(invalid("capture memory marker launch was not acknowledged").into());
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let AgentResponse::Events(events) =
                reply(agent, AgentRequest::Events { id, after: 0 }).await?
            else {
                return Err(invalid("capture marker event shape differs").into());
            };
            let mut bytes = Vec::new();
            for event in events.iter().filter(|e| e.kind == EventKind::Stdout) {
                if event.execution_id != id || event.data["encoding"] != "base64" {
                    return Err(invalid("capture marker event identity differs").into());
                }
                bytes.extend(
                    STANDARD.decode(
                        event.data["data"]
                            .as_str()
                            .ok_or_else(|| invalid("capture marker event data absent"))?,
                    )?,
                );
            }
            if !bytes.is_empty() {
                let hex = std::str::from_utf8(&bytes)?.trim();
                if hex.len() != 64
                    || !hex
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    return Err(invalid("capture marker hex differs").into());
                }
                let value = (0..32)
                    .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                return Ok((value, id));
            }
            if let AgentResponse::Execution(e) = reply(agent, AgentRequest::Inspect { id }).await?
                && e.state.is_terminal()
            {
                return Err(invalid("capture memory marker command terminated").into());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(invalid("capture memory marker deadline").into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    pub(crate) async fn reserve_capture(
        &self,
        input: &BootInput,
        cfg: &CheckpointProbeConfig,
    ) -> Result<CaptureSession> {
        if cfg.root.starts_with(&self.root) || self.root.starts_with(&cfg.root) {
            return Err(invalid("checkpoint store overlaps source VM root").into());
        }
        self.root_handle
            .as_ref()
            .ok_or_else(|| invalid("native capture source root is unacknowledged"))?
            .verify()?;
        let api = self.capture_api(input)?;
        if api.instance_info().await?.state != InstanceState::Running {
            return Err(invalid("native capture requires a running source").into());
        }
        let agent = AgentClient::new(
            api.clone(),
            self.jail.join("vsock.sock"),
            52,
            Duration::from_secs(20),
        )?;
        let control = agent.control_info().await?;
        if control.pids != self.resources.pids {
            return Err(invalid("capture guest task ceiling differs").into());
        }
        let source = if let Some((_, record)) = &self.persistent {
            if record.owner.installation_id != cfg.installation {
                return Err(invalid("capture installation differs from native source").into());
            }
            CaptureIdentity {
                installation: cfg.installation,
                sandbox: record.owner.sandbox_id,
                source_generation: self.generation,
                capture: cfg.capture,
                request_sha256: record.owner.request_sha256.clone(),
            }
        } else {
            CaptureIdentity {
                installation: cfg.installation,
                sandbox: self.generation,
                source_generation: self.generation,
                capture: cfg.capture,
                request_sha256: format!(
                    "{:x}",
                    sha2::Sha256::digest(serde_json::to_vec(&(input, &self.resources))?)
                ),
            }
        };
        let runtime = CheckpointRuntime {
            firecracker_version: crate::api::SUPPORTED_VMM_VERSION.into(),
            firecracker_sha256: input.firecracker.sha256.clone(),
            jailer_sha256: input.jailer.sha256.clone(),
            kernel_sha256: input.kernel.sha256.clone(),
            architecture: std::env::consts::ARCH.into(),
            host_compatibility_sha256: host_compatibility()?,
        };
        let intent = Intent {
            source: source.clone(),
            runtime: runtime.clone(),
            resources: self.resources.clone(),
            barrier: Uuid::new_v4(),
            disk_bytes: input.rootfs.size,
            writer: Writer::observe(api.peer_identity().pid)?,
            source_directory: SourceDirectory::observe(&self.root, self.generation)?,
        };
        let store = CheckpointStore::open_or_initialize(cfg)?;
        store.reserve(intent)
    }

    /// Production capture performs no workload writes or test marker launches.
    /// Its caller retains the exclusive source lease until all I/O has settled.
    pub(crate) async fn capture_reserved(
        &self,
        input: &BootInput,
        cfg: &CheckpointProbeConfig,
        mut session: CaptureSession,
    ) -> Result<CheckpointReference> {
        let intent = session.intent().clone();
        let source = intent.source;
        let runtime = intent.runtime;
        let barrier = intent.barrier;
        session.begin()?;
        let produced = async {
            self.check_expiry()?;
            if source.capture != cfg.capture || source.source_generation != self.generation {
                return Err(invalid("capture lease differs from the owned source").into());
            }
            self.root_handle
                .as_ref()
                .ok_or_else(|| invalid("capture source root missing"))?
                .verify()?;
            let api = self.capture_api(input)?;
            if api.instance_info().await?.state != InstanceState::Running {
                return Err(invalid("native capture source is no longer running").into());
            }
            let agent = AgentClient::new(
                api.clone(),
                self.jail.join("vsock.sock"),
                52,
                Duration::from_secs(20),
            )?;
            let receipt = agent.quiesce(barrier).await?;
            receipt
                .validate(self.generation, barrier)
                .map_err(invalid)?;
            if receipt.phase != GuestBarrierPhase::Quiesced {
                return Err(invalid("native capture has no frozen barrier").into());
            }
            api.pause().await?;
            if api.instance_info().await?.state != InstanceState::Paused {
                return Err(invalid("native capture source pause unconfirmed").into());
            }
            let state_name = format!("ghcp-{}-state", cfg.capture.simple());
            let memory_name = format!("ghcp-{}-memory", cfg.capture.simple());
            for name in [&state_name, &memory_name] {
                match std::fs::symlink_metadata(self.jail.join(name)) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                    _ => {
                        return Err(invalid(
                            "native snapshot output is occupied or unconfirmed; overwrite refused",
                        )
                        .into());
                    }
                }
            }
            api.create_snapshot(&SnapshotCreate::full(
                format!("/{state_name}"),
                format!("/{memory_name}"),
            )?)
            .await?;
            if api.instance_info().await?.state != InstanceState::Paused {
                return Err(invalid("native snapshot source state changed").into());
            }
            let inputs = CheckpointFiles {
                state: output(
                    &self.jail.join(state_name),
                    None,
                    crate::checkpoint::MAX_CHECKPOINT_STATE_BYTES,
                )?,
                memory: output(
                    &self.jail.join(memory_name),
                    Some(self.resources.memory_bytes),
                    self.resources.memory_bytes,
                )?,
                disk: output(
                    &self.jail.join("rootfs.ext4"),
                    Some(input.rootfs.size),
                    input.rootfs.size,
                )?,
            };
            let manifest = CheckpointManifest {
                format: 1,
                source,
                runtime: runtime.clone(),
                resources: self.resources.clone(),
                barrier: receipt,
                state: content(&inputs.state)?,
                memory: content(&inputs.memory)?,
                disk: content(&inputs.disk)?,
            };
            let reference = manifest.reference().map_err(invalid)?;
            let staged = StagedCheckpoint::materialize(
                manifest,
                &reference,
                &runtime,
                session.reserved_bytes(),
                inputs,
                VMM_UID,
                &cfg.root,
            )?;
            self.check_expiry()?;
            if self.capture_api(input)?.instance_info().await?.state != InstanceState::Paused {
                return Err(invalid("capture source pause lost before publication").into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(staged)
        }
        .await;
        let staged = match produced {
            Ok(value) => value,
            Err(e) => {
                if let Err(record_error) = session.fail(&e.to_string()) {
                    return Err(invalid(format!(
                        "{e}; capture failure metadata is unconfirmed: {record_error}"
                    ))
                    .into());
                }
                return Err(e);
            }
        };
        session.publish(staged)
    }

    pub(crate) async fn capture(
        &mut self,
        input: &BootInput,
        cfg: &CheckpointProbeConfig,
        report: &mut GuestReport,
    ) -> Result<()> {
        report.checkpoint = Some(CheckpointCaptureReport::new(cfg.capture));
        let store = CheckpointStore::open_or_initialize(cfg)?;
        let mut session = match self.reserve_capture(input, cfg).await {
            Ok(value) => value,
            Err(error) => {
                let healthy = if let Ok(api) = self.capture_api(input) {
                    let agent = AgentClient::new(
                        api.clone(),
                        self.jail.join("vsock.sock"),
                        52,
                        Duration::from_secs(20),
                    )?;
                    api.instance_info()
                        .await
                        .is_ok_and(|i| i.state == InstanceState::Running)
                        && reply(&agent, AgentRequest::Ping)
                            .await
                            .is_ok_and(|r| matches!(r, AgentResponse::Pong { .. }))
                } else {
                    false
                };
                let progress = report.checkpoint.as_mut().expect("capture report");
                progress.source_running_after_admission_refusal = Some(healthy);
                progress.store_reserved_bytes_after_admission_refusal =
                    Some(store.reserved_bytes()?);
                return Err(error);
            }
        };
        report
            .checkpoint
            .as_mut()
            .expect("capture report")
            .reserved_bytes = session.reserved_bytes();
        // These markers belong exclusively to the private hardware probe.
        let markers = async {
            let agent = AgentClient::new(
                self.capture_api(input)?,
                self.jail.join("vsock.sock"),
                52,
                Duration::from_secs(20),
            )?;
            let marker = self.memory_marker(&agent).await?;
            let disk = STANDARD
                .encode(format!("checkpoint-{}-{}", Uuid::new_v4(), Uuid::new_v4()).as_bytes());
            if !matches!(
                reply(
                    &agent,
                    AgentRequest::WriteFile {
                        path: "checkpoint-payload".into(),
                        data_base64: disk.clone()
                    }
                )
                .await?,
                AgentResponse::Ok
            ) {
                return Err(invalid("checkpoint disk marker was not acknowledged").into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((marker, disk))
        }
        .await;
        let ((marker, execution), disk) = match markers {
            Ok(value) => value,
            Err(error) => {
                session.fail(&error.to_string())?;
                return Err(error);
            }
        };
        let progress = report.checkpoint.as_mut().expect("capture report");
        progress.marker_execution = Some(execution);
        progress.memory_marker_hex = Some(marker.iter().map(|b| format!("{b:02x}")).collect());
        progress.disk_marker_base64 = Some(disk);
        let reference = self.capture_reserved(input, cfg, session).await?;
        let found = store.verify(&reference, |_, files| has_marker(&files.memory, &marker))?;
        let progress = report.checkpoint.as_mut().expect("capture report");
        progress.reference = Some(reference);
        progress.phase = "ready".into();
        progress.memory_marker_found = found;
        if !found {
            return Err(invalid("actual guest RAM marker missing from captured memory").into());
        }
        report.checks.push(
            "actual_frozen_full_snapshot_persisted_with_guest_RAM_marker_and_independent_disk"
                .into(),
        );
        Ok(())
    }
    pub(super) fn verify_capture_after_collection(
        &self,
        cfg: &CheckpointProbeConfig,
        report: &mut GuestReport,
    ) -> Result<()> {
        let progress = report
            .checkpoint
            .as_mut()
            .ok_or_else(|| invalid("capture report absent"))?;
        let reference = progress
            .reference
            .as_ref()
            .ok_or_else(|| invalid("capture Ready reference absent"))?;
        if report.cleanup != CleanupState::Complete
            || !report.root_absent
            || !report.vmm_reaped
            || !report.cgroup_absent
        {
            return Err(invalid("capture source was not positively collected").into());
        }
        let store = CheckpointStore::open_or_initialize(cfg)?;
        store.verify(reference, |_, _| Ok(()))?;
        progress.verified_after_source_collection = true;
        report.checks.push(
            "Ready_capture_content_verifies_after_actual_source_VMM_jail_and_cgroup_collection"
                .into(),
        );
        Ok(())
    }
}
