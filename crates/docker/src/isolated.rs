use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

impl DockerDriver {
    /// Verifies separate native sandboxes. Hierarchy accounting, permissions and
    /// cascade policy are host features and are not advertised by this driver.
    pub async fn probe_isolated_sandboxes(&self) -> Result<(), ApiError> {
        let _probe = self.probes.lock().await;
        let profile = self.profile_snapshot().await;
        for capability in [
            Capability::Commands,
            Capability::Files,
            Capability::NetworkIsolation,
        ] {
            goldenhoop_core::require_capability(&profile, capability)?;
        }
        let mut sandboxes = Vec::new();
        for (cpu, memory, pids) in [(250, 256, 128), (500, 384, 192)] {
            let mut request = CreateSandbox::new(&profile.id, &self.config.agent_image);
            request.resources = ResourceLimits {
                cpu_millis: cpu,
                memory_bytes: memory * 1024 * 1024,
                pids,
            };
            request.ttl_seconds = 90;
            let created = Utc::now();
            let sandbox = Sandbox {
                id: Uuid::new_v4(),
                profile: profile.id.clone(),
                image: request.image.clone(),
                state: SandboxState::Starting,
                desired_state: DesiredState::Running,
                cleanup: CleanupState::Pending,
                created_at: created,
                expires_at: created + chrono::Duration::seconds(90),
                observed_at: None,
                resources: request.resources.clone(),
                metadata: Default::default(),
                reason: None,
            };
            sandboxes.push((sandbox, request));
        }
        let outcome = tokio::time::timeout(Duration::from_secs(45), async {
            let a = self.create(&sandboxes[0].0, &sandboxes[0].1).await?;
            let b = self.create(&sandboxes[1].0, &sandboxes[1].1).await?;
            if a.backend_ref == b.backend_ref {
                return Err(unavailable("isolated sandboxes reused a runtime identity"));
            }
            for (handle, (_, request)) in [(&a, &sandboxes[0]), (&b, &sandboxes[1])] {
                let host = self
                    .owned(handle)
                    .await?
                    .and_then(|value| value.host_config)
                    .ok_or_else(|| unavailable("isolated runtime configuration is absent"))?;
                if host.runtime.as_deref() != Some(self.config.profile.runtime())
                    || host.network_mode.as_deref() != Some("none")
                    || host.ipc_mode.as_deref() != Some("private")
                    || host
                        .pid_mode
                        .as_deref()
                        .is_some_and(|mode| !mode.is_empty())
                    || host.readonly_rootfs != Some(true)
                    || host.privileged != Some(false)
                    || host.nano_cpus != Some(i64::from(request.resources.cpu_millis) * 1_000_000)
                    || host.memory != Some(request.resources.memory_bytes as i64)
                    || host.memory_swap != Some(request.resources.memory_bytes as i64)
                    || host.pids_limit != Some(i64::from(request.resources.pids))
                    || host.binds.as_ref().is_some_and(|values| !values.is_empty())
                    || host
                        .volumes_from
                        .as_ref()
                        .is_some_and(|values| !values.is_empty())
                {
                    return Err(unavailable(
                        "isolated runtime limits or namespace configuration differ",
                    ));
                }
                let mounts = host
                    .mounts
                    .ok_or_else(|| unavailable("isolated runtime lacks its trusted agent mount"))?;
                if mounts.len() != 1
                    || mounts[0].target.as_deref() != Some("/opt/goldenhoop")
                    || mounts[0].read_only != Some(true)
                    || mounts[0].typ != Some(MountType::VOLUME)
                {
                    return Err(unavailable(
                        "isolated runtime has an unexpected shared mount",
                    ));
                }
            }
            self.isolation_loop(&a, &b).await
        })
        .await
        .map_err(|_| unavailable("isolated runtime probe timed out"))
        .and_then(|value| value);
        // Includes a create that reached Docker before its handle was returned.
        for handle in self.discover().await?.into_iter().filter(|handle| {
            sandboxes
                .iter()
                .any(|(sandbox, _)| sandbox.id == handle.sandbox_id)
        }) {
            self.remove(&handle).await?;
        }
        if self.discover().await?.iter().any(|handle| {
            sandboxes
                .iter()
                .any(|(sandbox, _)| sandbox.id == handle.sandbox_id)
        }) {
            return Err(unavailable("isolated runtime probe cleanup is unconfirmed"));
        }
        outcome
    }

    async fn isolation_loop(
        &self,
        parent: &RuntimeHandle,
        child: &RuntimeHandle,
    ) -> Result<(), ApiError> {
        let path = "isolation-proof.txt";
        self.bridge(
            parent,
            &AgentRequest::WriteFile {
                path: path.into(),
                data_base64: STANDARD.encode(b"parent"),
            },
        )
        .await?;
        match self
            .bridge(
                child,
                &AgentRequest::ReadFile {
                    path: path.into(),
                    max_bytes: 16,
                },
            )
            .await
        {
            Err(error) if error.code == ErrorCode::NotFound => {}
            _ => return Err(unavailable("child can read its parent's workspace")),
        }
        self.bridge(
            child,
            &AgentRequest::WriteFile {
                path: path.into(),
                data_base64: STANDARD.encode(b"child"),
            },
        )
        .await?;
        match self
            .bridge(
                parent,
                &AgentRequest::ReadFile {
                    path: path.into(),
                    max_bytes: 16,
                },
            )
            .await?
        {
            AgentResponse::File { data_base64 } if data_base64 == STANDARD.encode(b"parent") => {}
            _ => return Err(unavailable("child changed its parent's workspace")),
        }
        let marker = format!("gh-isolation-{}", Uuid::new_v4().simple());
        let key = (u32::from_be_bytes(
            Uuid::new_v4().as_bytes()[..4]
                .try_into()
                .expect("four bytes"),
        ) & 0x7fff_ffff)
            | 1;
        let id = Uuid::new_v4();
        let mut command = CommandSpec::new([
            "python3",
            "-c",
            r#"import os,sys,socket,ctypes,json,time
marker,key=sys.argv[1],int(sys.argv[2])
libc=ctypes.CDLL(None,use_errno=True)
segment=libc.shmget(key,4096,0o1000|0o2000|0o600)
assert segment>=0,('parent shmget',ctypes.get_errno())
open('/dev/shm/'+marker,'w').write(marker)
tcp=socket.socket();tcp.bind(('127.0.0.1',0));tcp.listen(1)
abstract=socket.socket(socket.AF_UNIX);abstract.bind('\0'+marker)
with open('/workspace/isolation-ready.tmp','w') as ready:ready.write(json.dumps({'port':tcp.getsockname()[1]}))
os.replace('/workspace/isolation-ready.tmp','/workspace/isolation-ready.json')
while True:time.sleep(.1)
"#,
            &marker,
            &key.to_string(),
        ]);
        command.timeout_seconds = 40;
        command.max_output_bytes = 4096;
        self.bridge(parent, &AgentRequest::Start { id, command })
            .await?;
        let mut port = None;
        for _ in 0..50 {
            match self
                .bridge(
                    parent,
                    &AgentRequest::ReadFile {
                        path: "isolation-ready.json".into(),
                        max_bytes: 1024,
                    },
                )
                .await
            {
                Ok(AgentResponse::File { data_base64 }) => {
                    let bytes = STANDARD
                        .decode(data_base64)
                        .map_err(|_| unavailable("invalid isolation readiness encoding"))?;
                    let value: serde_json::Value = serde_json::from_slice(&bytes)
                        .map_err(|_| unavailable("invalid isolation readiness observation"))?;
                    port = value["port"]
                        .as_u64()
                        .and_then(|value| u16::try_from(value).ok());
                    break;
                }
                Err(error) if error.code == ErrorCode::NotFound => {}
                _ => return Err(unavailable("isolated process readiness failed")),
            }
            if let AgentResponse::Execution(record) =
                self.bridge(parent, &AgentRequest::Inspect { id }).await?
                && record.state.is_terminal()
            {
                self.isolation_execution(parent, id, ExecutionState::Running)
                    .await?;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let port = port.ok_or_else(|| {
            unavailable("isolated process did not establish its IPC and loopback listeners")
        })?;
        self.pause(parent).await?;
        let proof = CommandSpec::new([
            "python3",
            "-c",
            r#"import os,sys,socket,ctypes,errno
marker,key,port=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
assert not os.path.exists('/dev/shm/'+marker)
assert not os.path.exists('/workspace/isolation-ready.json')
assert open('/workspace/isolation-proof.txt').read()=='child'
for name in os.listdir('/proc'):
    if not name.isdigit() or int(name)==os.getpid():continue
    try:content=open('/proc/'+name+'/cmdline','rb').read()
    except (PermissionError,ProcessLookupError,FileNotFoundError):continue
    assert marker.encode() not in content,('shared process',name)
libc=ctypes.CDLL(None,use_errno=True)
assert libc.shmget(key,0,0)==-1 and ctypes.get_errno()==errno.ENOENT,('shared SysV IPC',ctypes.get_errno())
segment=libc.shmget(key,4096,0o1000|0o2000|0o600)
assert segment>=0,('child shmget',ctypes.get_errno())
assert libc.shmctl(segment,0,None)==0
abstract=socket.socket(socket.AF_UNIX);abstract.bind('\0'+marker)
with socket.socket() as attempt:
    attempt.settimeout(.3);assert attempt.connect_ex(('127.0.0.1',port))!=0
with socket.socket() as listener:
    listener.bind(('127.0.0.1',port));listener.listen(1)
    with socket.create_connection(('127.0.0.1',port),timeout=1) as local:
        accepted,_=listener.accept();accepted.close()
for address in ['1.1.1.1','172.17.0.1','169.254.169.254']:
    with socket.socket() as denied:
        denied.settimeout(.3);assert denied.connect_ex((address,443))!=0
"#,
            &marker,
            &key.to_string(),
            &port.to_string(),
        ]);
        self.isolation_command(child, proof).await?;
        self.resume(parent).await?;
        match self.bridge(parent, &AgentRequest::Inspect { id }).await? {
            AgentResponse::Execution(record) if record.state == ExecutionState::Running => {}
            _ => {
                return Err(unavailable(
                    "isolated child probe changed its parent's process",
                ));
            }
        }
        self.remove(child).await?;
        self.bridge(parent, &AgentRequest::Cancel { id }).await?;
        self.isolation_execution(parent, id, ExecutionState::Cancelled)
            .await?;
        self.isolation_command(
            parent,
            CommandSpec::new([
                "python3",
                "-c",
                "assert open('/workspace/isolation-proof.txt').read()=='parent'",
            ]),
        )
        .await
    }

    async fn isolation_command(
        &self,
        handle: &RuntimeHandle,
        mut command: CommandSpec,
    ) -> Result<(), ApiError> {
        command.timeout_seconds = 5;
        command.max_output_bytes = 4096;
        let id = Uuid::new_v4();
        self.bridge(handle, &AgentRequest::Start { id, command })
            .await?;
        self.isolation_execution(handle, id, ExecutionState::Succeeded)
            .await
    }
    async fn isolation_execution(
        &self,
        handle: &RuntimeHandle,
        id: Uuid,
        expected: ExecutionState,
    ) -> Result<(), ApiError> {
        for _ in 0..50 {
            if let AgentResponse::Execution(record) =
                self.bridge(handle, &AgentRequest::Inspect { id }).await?
                && record.state.is_terminal()
            {
                let AgentResponse::Events(events) = self
                    .bridge(handle, &AgentRequest::Events { id, after: 0 })
                    .await?
                else {
                    return Err(unavailable("isolated runtime lacks command events"));
                };
                if record.state != expected
                    || record.cleanup != CleanupState::Complete
                    || (expected == ExecutionState::Succeeded && record.exit_code != Some(0))
                {
                    let mut detail = Vec::new();
                    for event in events
                        .iter()
                        .filter(|event| event.kind == EventKind::Stderr)
                    {
                        if let Some(data) = event.data["data"]
                            .as_str()
                            .and_then(|value| STANDARD.decode(value).ok())
                        {
                            detail.extend(data.into_iter().take(2048 - detail.len()));
                        }
                    }
                    return Err(unavailable(&format!(
                        "isolated runtime command failed: state={:?}, cleanup={:?}, stderr={}",
                        record.state,
                        record.cleanup,
                        String::from_utf8_lossy(&detail)
                    )));
                }
                if !events
                    .iter()
                    .any(|event| event.execution_id == id && event.kind == EventKind::Completed)
                {
                    return Err(unavailable("isolated runtime lacks explicit completion"));
                }
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(unavailable(
            "isolated runtime command completion was not observed",
        ))
    }
}
