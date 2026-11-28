//! An actual single-use memory continuation, with durable cleanup intent before
//! any VM effect. Fixture responses and a successful VMM launch grant no support.
use super::*;
use crate::checkpoint::CheckpointReference;
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryProbe {
    format: u32,
    id: Uuid,
    installation: Uuid,
    context_sha256: String,
    source: Sandbox,
    target: Sandbox,
    request: CreateSandbox,
    capture: Uuid,
    restoration: Uuid,
    #[serde(default)]
    source_handle: Option<RuntimeHandle>,
    #[serde(default)]
    reference: Option<CheckpointReference>,
    // A completed check is still insufficient until physical collection passes.
    checked: bool,
    collected: bool,
    #[serde(default)]
    error: Option<String>,
}

impl MemoryProbe {
    fn validate(&self, cfg: &DriverConfig, id: Uuid) -> Result<()> {
        let ids = [
            self.id,
            self.source.id,
            self.target.id,
            self.capture,
            self.restoration,
        ];
        if self.format != 1
            || self.id != id
            || self.installation != cfg.installation_id
            || ids.iter().any(Uuid::is_nil)
            || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len()
            || self.context_sha256.len() != 64
            || !self
                .context_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.request.profile != PROFILE
            || self.request.image != cfg.image
            || self.request.network != NetworkPolicy::default()
            || self.request.child_budget.is_some()
            || self.request.feature_limit.is_some()
            || self.request.ttl_seconds == 0
            || self.request.ttl_seconds > cfg.max_ttl_seconds
            || self.error.as_ref().is_some_and(|error| error.len() > 512)
            || self.checked && self.error.is_some()
        {
            return Err(invalid("native memory probe intent differs").into());
        }
        for sandbox in [&self.source, &self.target] {
            if sandbox.profile != self.request.profile
                || sandbox.image != self.request.image
                || sandbox.resources != self.request.resources
                || sandbox.expires_at - sandbox.created_at
                    != chrono::Duration::seconds(self.request.ttl_seconds as i64)
                || sandbox.desired_state != DesiredState::Running
            {
                return Err(invalid("native memory probe sandbox binding differs").into());
            }
        }
        if let Some(handle) = &self.source_handle {
            let generation = handle
                .backend_ref
                .rsplit(':')
                .next()
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or_else(|| invalid("native memory probe generation is missing"))?;
            if generation.is_nil()
                || handle != &native_handle(cfg.installation_id, self.source.id, generation)
            {
                return Err(invalid("native memory probe source binding differs").into());
            }
        }
        if self.reference.as_ref().is_some_and(|reference| {
            reference.installation != cfg.installation_id
                || reference.capture != self.capture
                || reference.manifest_sha256.len() != 64
                || self.source_handle.is_none()
        }) || self.checked && (self.reference.is_none() || self.source_handle.is_none())
        {
            return Err(invalid("native memory probe checkpoint binding differs").into());
        }
        Ok(())
    }
    fn path(&self, cfg: &DriverConfig) -> PathBuf {
        cfg.data_root
            .join("memory-probes")
            .join(format!("{}.json", self.id))
    }
    fn save(&self, cfg: &DriverConfig) -> Result<()> {
        self.validate(cfg, self.id)?;
        atomic_json(&self.path(cfg), self)
    }
    fn restore_request(&self) -> Result<ManagedRestoreRequest> {
        Ok(ManagedRestoreRequest {
            sandbox: self.target.clone(),
            request: self.request.clone(),
            reference: self
                .reference
                .clone()
                .ok_or_else(|| invalid("probe reference is absent"))?,
            restoration: self.restoration,
            expected_source: Some(
                self.source_handle
                    .clone()
                    .ok_or_else(|| invalid("probe source is absent"))?,
            ),
        })
    }
}
impl NativeEngine {
    fn memory_probes(&self) -> Result<Vec<MemoryProbe>> {
        let cfg = &self.inner.cfg;
        let directory = cfg.data_root.join("memory-probes");
        private_directory(&directory)?;
        let recovery = metadata::recover_entries(&directory, &[], true, |name, bytes| {
            let id = Uuid::parse_str(
                name.strip_suffix(".json")
                    .ok_or_else(|| invalid("memory probe filename differs"))?,
            )?;
            if name != format!("{id}.json") {
                return Err(invalid("memory probe ID is not canonical").into());
            }
            serde_json::from_slice::<MemoryProbe>(bytes)?.validate(cfg, id)
        })?;
        if !recovery.unconfirmed.is_empty() {
            return Err(invalid("memory probe metadata writer remains unconfirmed").into());
        }
        let mut probes = Vec::new();
        for entry in std::fs::read_dir(directory)? {
            let path = entry?.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let id = Uuid::parse_str(
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| invalid("memory probe filename is missing"))?,
            )?;
            if path.file_name().and_then(|s| s.to_str()) != Some(format!("{id}.json").as_str()) {
                return Err(invalid("memory probe ID is not canonical").into());
            }
            let probe: MemoryProbe = read_json(&path)?;
            probe.validate(cfg, id)?;
            probes.push(probe);
            if probes.len() > 256 {
                return Err(invalid("native memory probe history limit exceeded").into());
            }
        }
        Ok(probes)
    }

    /// Recovery only collects the original effect owners. It never resumes an
    /// interrupted probe or grants another target authority for its capture.
    async fn collect_memory_probe(&self, probe: &mut MemoryProbe) -> Result<()> {
        let cfg = &self.inner.cfg;
        if cfg.record_path(probe.source.id).try_exists()? {
            let source = self.load(probe.source.id)?;
            if source.owner.request_sha256 != request_digest(&probe.request)?
                || source.owner.expires_at != probe.source.expires_at
                || source.restore.is_some()
            {
                return Err(invalid("memory probe does not own the source journal").into());
            }
            let handle = native_handle(
                cfg.installation_id,
                probe.source.id,
                source.owner.generation,
            );
            if probe
                .source_handle
                .as_ref()
                .is_some_and(|expected| expected != &handle)
            {
                return Err(invalid("memory probe source generation changed").into());
            }
            if probe.source_handle.is_none() {
                probe.source_handle = Some(handle.clone());
                probe.save(cfg)?;
            }
            self.remove(&handle).await?;
            let current = self.for_handle(&handle)?;
            if current.phase != "collected" || !self.physical_absence(&current)? {
                return Err(invalid("memory probe source is not positively collected").into());
            }
            // Reconcile also closes a never-dispatched capture, without starting
            // a replacement copy. A producer keeps its original VM lease.
            let status = self
                .checkpoint_reconcile_bound(&handle, probe.capture)
                .await?;
            if probe.reference.is_none() && !status["reference"].is_null() {
                probe.reference = Some(serde_json::from_value(status["reference"].clone())?);
                probe.save(cfg)?;
            }
            if probe.reference.is_some() {
                self.checkpoint_restore_collect(&probe.restore_request()?)
                    .await?;
            } else if cfg.record_path(probe.target.id).try_exists()? {
                return Err(invalid(
                    "memory probe target exists without its durable restore intent",
                )
                .into());
            }
            let status = self
                .checkpoint_read_bound(&handle, probe.capture, true)
                .await?;
            if status["objects_absent"] != true || status["reserved_bytes"] != 0 {
                return Err(invalid(
                    "memory probe checkpoint objects are not positively collected",
                )
                .into());
            }
        } else if probe.source_handle.is_some()
            || probe.reference.is_some()
            || cfg.record_path(probe.target.id).try_exists()?
        {
            return Err(invalid("memory probe source ownership is missing").into());
        }
        probe.collected = true;
        probe.save(cfg)
    }

    pub(super) async fn probe_memory(&self) -> Result<()> {
        let cfg = &self.inner.cfg;
        let context = probe_context(cfg)?;
        let mut probes = self.memory_probes()?;
        // Every unresolved probe is cleaned before another can reserve capacity.
        for probe in &mut probes {
            if !probe.collected {
                tokio::time::timeout(Duration::from_secs(90), self.collect_memory_probe(probe))
                    .await??;
            }
        }
        for probe in &mut probes {
            if probe.checked && probe.collected && probe.context_sha256 == context {
                // Re-observe actual absence, closures and object reservations on
                // cache reuse; an in-memory boolean alone never suffices.
                tokio::time::timeout(Duration::from_secs(45), self.collect_memory_probe(probe))
                    .await??;
                return Ok(());
            }
        }
        if probes.len() >= 256 {
            return Err(invalid("native memory probe history is full").into());
        }
        let mut request = CreateSandbox::new(PROFILE, cfg.image.clone());
        request.resources = ResourceLimits {
            cpu_millis: cfg.max_resources.cpu_millis.min(1000),
            memory_bytes: cfg.max_resources.memory_bytes.min(256 * MIB),
            pids: cfg.max_resources.pids.min(32),
        };
        request.ttl_seconds = cfg.max_ttl_seconds.min(300);
        let now = Utc::now();
        let source = Sandbox {
            id: Uuid::new_v4(),
            profile: PROFILE.into(),
            image: cfg.image.clone(),
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
        let mut target = source.clone();
        target.id = Uuid::new_v4();
        let mut probe = MemoryProbe {
            format: 1,
            id: Uuid::new_v4(),
            installation: cfg.installation_id,
            context_sha256: context,
            source,
            target,
            request,
            capture: Uuid::new_v4(),
            restoration: Uuid::new_v4(),
            source_handle: None,
            reference: None,
            checked: false,
            collected: false,
            error: None,
        };
        probe.validate(cfg, probe.id)?;
        metadata::initial_json(&probe.path(cfg), &probe)?;
        let checked = tokio::time::timeout(
            Duration::from_secs(210),
            self.check_memory_probe(&mut probe),
        )
        .await;
        let passed = matches!(&checked, Ok(Ok(())));
        probe.checked = passed;
        probe.error = match &checked {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error.to_string().chars().take(128).collect()),
            Err(_) => Some("actual memory probe deadline elapsed".into()),
        };
        probe.save(cfg)?;
        let collected = tokio::time::timeout(
            Duration::from_secs(90),
            self.collect_memory_probe(&mut probe),
        )
        .await;
        collected??;
        checked??;
        Ok(())
    }

    pub(super) async fn collect_interrupted_memory_probes(&self) -> Result<()> {
        for mut probe in self.memory_probes()? {
            if !probe.collected {
                tokio::time::timeout(
                    Duration::from_secs(90),
                    self.collect_memory_probe(&mut probe),
                )
                .await??;
            }
        }
        Ok(())
    }

    async fn probe_write(&self, handle: &RuntimeHandle, path: &str, value: &[u8]) -> Result<()> {
        if !matches!(
            self.rpc(
                handle,
                &AgentRequest::WriteFile {
                    path: path.into(),
                    data_base64: STANDARD.encode(value),
                }
            )
            .await?,
            AgentResponse::Ok
        ) {
            return Err(invalid("memory probe write acknowledgement differs").into());
        }
        Ok(())
    }
    async fn probe_read(&self, handle: &RuntimeHandle, path: &str) -> Result<Vec<u8>> {
        let AgentResponse::File { data_base64 } = self
            .rpc(
                handle,
                &AgentRequest::ReadFile {
                    path: path.into(),
                    max_bytes: 512,
                },
            )
            .await?
        else {
            return Err(invalid("memory probe read acknowledgement differs").into());
        };
        Ok(STANDARD.decode(data_base64)?)
    }
    async fn probe_stdout(&self, handle: &RuntimeHandle, job: Uuid) -> Result<String> {
        let AgentResponse::Events(events) = self
            .rpc(handle, &AgentRequest::Events { id: job, after: 0 })
            .await?
        else {
            return Err(invalid("memory probe event acknowledgement differs").into());
        };
        let mut bytes = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.kind == EventKind::Stdout)
        {
            if event.execution_id != job || event.data["encoding"] != "base64" {
                return Err(invalid("memory probe event identity differs").into());
            }
            bytes.extend(
                STANDARD.decode(
                    event.data["data"]
                        .as_str()
                        .ok_or_else(|| invalid("memory probe stdout bytes are missing"))?,
                )?,
            );
        }
        Ok(String::from_utf8(bytes)?)
    }
    async fn check_memory_probe(&self, probe: &mut MemoryProbe) -> Result<()> {
        let cfg = &self.inner.cfg;
        let source = self.create(&probe.source, &probe.request).await?;
        probe.source_handle = Some(source.clone());
        probe.save(cfg)?;
        let nonce = Uuid::new_v4().to_string();
        self.probe_write(&source, "memory-probe-disk", nonce.as_bytes())
            .await?;
        let job = Uuid::new_v4();
        let script = "import os,time\nfrom pathlib import Path\ntoken=os.urandom(32).hex()\nwith Path('/workspace/memory-probe-once').open('a') as f: f.write('once')\nprint(token,flush=True)\nwhile not Path('/workspace/memory-probe-release').exists(): time.sleep(.05)\nprint('resumed:'+token,flush=True)\n";
        let mut command = CommandSpec::new(["python3", "-c", script]);
        command.timeout_seconds = 180;
        command.max_output_bytes = 512;
        let AgentResponse::Execution(started) = self
            .rpc(&source, &AgentRequest::Start { id: job, command })
            .await?
        else {
            return Err(invalid("memory probe original execution is missing").into());
        };
        if started.id != job
            || (!started.sandbox_id.is_nil() && started.sandbox_id != probe.source.id)
        {
            return Err(invalid("memory probe execution owner differs").into());
        }
        let until = tokio::time::Instant::now() + Duration::from_secs(20);
        let token = loop {
            let stdout = self.probe_stdout(&source, job).await?;
            if !stdout.is_empty() {
                let token = stdout.trim().to_string();
                if token.len() != 64
                    || !token
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(invalid("memory probe RAM token differs").into());
                }
                break token;
            }
            if tokio::time::Instant::now() >= until {
                return Err(invalid("memory probe readiness deadline").into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let AgentResponse::Execution(original) = self
            .rpc(&source, &AgentRequest::Inspect { id: job })
            .await?
        else {
            return Err(invalid("memory probe running execution is missing").into());
        };
        if original.id != started.id
            || original.sandbox_id != started.sandbox_id
            || original.started_at.is_none()
            || original.state != ExecutionState::Running
        {
            return Err(invalid("memory probe execution has not actually started").into());
        }
        let mut status = self.checkpoint_capture(&source, probe.capture).await?;
        let until = tokio::time::Instant::now() + Duration::from_secs(120);
        while status["phase"] != "ready" {
            if status["capture_outcome"] != "pending" || tokio::time::Instant::now() >= until {
                return Err(invalid("memory probe capture is not ready").into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            status = self
                .checkpoint_read_bound(&source, probe.capture, false)
                .await?;
        }
        if status["content_verified"] != true {
            return Err(invalid("memory probe capture content is unverified").into());
        }
        probe.reference = Some(serde_json::from_value(status["reference"].clone())?);
        probe.save(cfg)?;
        self.remove(&source).await?;
        let record = self.for_handle(&source)?;
        if record.phase != "collected" || !self.physical_absence(&record)? {
            return Err(invalid("memory probe source still exists before transfer").into());
        }
        let target = self.checkpoint_restore(&probe.restore_request()?).await?;
        if target.sandbox_id != probe.target.id
            || target.backend_ref == source.backend_ref
            || self.inspect(&target).await?.state != ObservedState::Running
        {
            return Err(invalid("memory probe target generation differs").into());
        }
        let AgentResponse::Execution(retained) = self
            .rpc(&target, &AgentRequest::Inspect { id: job })
            .await?
        else {
            return Err(invalid("memory probe retained execution is missing").into());
        };
        if retained.id != original.id
            || retained.sandbox_id != original.sandbox_id
            || retained.started_at != original.started_at
            || retained.state != ExecutionState::Running
            || self.probe_read(&target, "memory-probe-disk").await? != nonce.as_bytes()
            || self.probe_read(&target, "memory-probe-once").await? != b"once"
        {
            return Err(invalid("memory probe retained RAM/disk/execution binding differs").into());
        }
        // No Start is sent to the restored generation.
        self.probe_write(&target, "memory-probe-release", b"release")
            .await?;
        let until = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let AgentResponse::Execution(done) = self
                .rpc(&target, &AgentRequest::Inspect { id: job })
                .await?
            else {
                return Err(invalid("memory probe completion acknowledgement differs").into());
            };
            if done.state.is_terminal() {
                if done.id != original.id
                    || done.sandbox_id != original.sandbox_id
                    || done.started_at != original.started_at
                    || done.state != ExecutionState::Succeeded
                    || done.exit_code != Some(0)
                    || done.cleanup != CleanupState::Complete
                    || self.probe_stdout(&target, job).await?
                        != format!("{token}\nresumed:{token}\n")
                    || self.probe_read(&target, "memory-probe-once").await? != b"once"
                {
                    return Err(invalid("memory probe command continuation is unconfirmed").into());
                }
                break;
            }
            if tokio::time::Instant::now() >= until {
                return Err(invalid("memory probe completion deadline").into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::CheckpointStorePolicy;

    #[tokio::test]
    async fn interrupted_probe_intent_reopens_for_collection_without_creating_or_proving_a_vm() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let directory = tempfile::Builder::new()
            .prefix("gmp-")
            .tempdir_in("/var/lib")
            .unwrap();
        let binary = PathBuf::from("/usr/bin/true");
        let (sha256, size) = digest(trusted_file(&binary).unwrap()).unwrap();
        let artifact = Artifact {
            path: binary,
            sha256,
            size,
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
            supervisor: artifact.clone(),
            image: format!("sha256:{}", artifact.sha256),
            prepared_images: None,
            checkpoints: Some(CheckpointStorePolicy {
                max_bytes: 3 * 1024 * MIB,
                max_checkpoints: 2,
            }),
            max_resources: ResourceLimits {
                cpu_millis: 1000,
                memory_bytes: 256 * MIB,
                pids: 32,
            },
            capacity: HostCapacity::default(),
            max_ttl_seconds: 300,
        };
        let mut request = CreateSandbox::new(PROFILE, cfg.image.clone());
        request.resources = cfg.max_resources.clone();
        request.ttl_seconds = 240;
        let now = Utc::now();
        let source = Sandbox {
            id: Uuid::new_v4(),
            profile: PROFILE.into(),
            image: cfg.image.clone(),
            state: SandboxState::Pending,
            desired_state: DesiredState::Running,
            cleanup: CleanupState::Pending,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(240),
            observed_at: None,
            resources: request.resources.clone(),
            metadata: Default::default(),
            reason: None,
        };
        let mut target = source.clone();
        target.id = Uuid::new_v4();
        let mut probe = MemoryProbe {
            format: 1,
            id: Uuid::new_v4(),
            installation: cfg.installation_id,
            context_sha256: probe_context(&cfg).unwrap(),
            source,
            target,
            request,
            capture: Uuid::new_v4(),
            restoration: Uuid::new_v4(),
            source_handle: None,
            reference: None,
            checked: false,
            collected: false,
            error: None,
        };
        let lease = metadata::claim_installation(&cfg.data_root, cfg.installation_id).unwrap();
        let engine = NativeEngine::connect(cfg.clone(), lease).unwrap();
        assert!(engine.memory_probes().unwrap().is_empty());
        metadata::initial_json(&probe.path(&cfg), &probe).unwrap();
        drop(engine);
        let lease = metadata::claim_installation(&cfg.data_root, cfg.installation_id).unwrap();
        let reopened = NativeEngine::connect(cfg.clone(), lease).unwrap();
        assert_eq!(reopened.memory_probes().unwrap().len(), 1);
        reopened.collect_memory_probe(&mut probe).await.unwrap();
        assert!(probe.collected && !probe.checked);
        assert!(reopened.records().unwrap().is_empty());
        assert!(
            !reopened
                .inner
                .profile
                .read()
                .await
                .capabilities
                .contains(&Capability::MemorySnapshot)
        );
        let mut changed = probe.clone();
        changed.target.id = changed.source.id;
        assert!(changed.save(&cfg).is_err());
        assert!(reopened.memory_probes().unwrap()[0].collected);
        changed = probe.clone();
        changed.checked = true;
        assert!(changed.save(&cfg).is_err());
        assert!(!reopened.memory_probes().unwrap()[0].checked);
        drop(reopened);
        let path = directory.path().to_owned();
        directory.close().unwrap();
        assert!(!path.exists());
    }
}
