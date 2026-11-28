use std::{
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use goldenhoop_client::*;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "goldenhoop", version, about = "GoldenHoop sandbox client")]
struct Args {
    #[arg(
        long,
        global = true,
        env = "GOLDENHOOP_ENDPOINT",
        default_value = "http://127.0.0.1:8080"
    )]
    endpoint: String,
    #[command(subcommand)]
    command: Command,
}

fn capability(value: &str) -> std::result::Result<Capability, String> {
    serde_json::from_value(serde_json::Value::String(value.into()))
        .map_err(|_| format!("unknown capability: {value}"))
}

fn code_language(value: &str) -> std::result::Result<CodeLanguage, String> {
    CodeLanguage::ALL
        .into_iter()
        .find(|language| language.as_str() == value)
        .ok_or_else(|| "language must be python, java, go, typescript, bash or javascript".into())
}
fn snapshot_kind(value: &str) -> std::result::Result<SnapshotKind, String> {
    serde_json::from_value(serde_json::Value::String(value.into()))
        .map_err(|_| "snapshot kind must be rootfs, volumes or memory_and_disk".into())
}

#[derive(clap::Args)]
struct ScopeArgs {
    #[arg(long, requires_all=["child_memory_bytes","child_pids"])]
    child_cpu_millis: Option<u32>,
    #[arg(long, requires_all=["child_cpu_millis","child_pids"])]
    child_memory_bytes: Option<u64>,
    #[arg(long, requires_all=["child_cpu_millis","child_memory_bytes"])]
    child_pids: Option<u32>,
    #[arg(long, value_delimiter=',', value_parser=capability)]
    feature_limit: Option<Vec<Capability>>,
    #[arg(long, conflicts_with = "feature_limit")]
    no_features: bool,
    #[arg(long="require", value_delimiter=',', value_parser=capability)]
    required_capabilities: Vec<Capability>,
}
impl ScopeArgs {
    fn budget(&self) -> Option<ResourceLimits> {
        self.child_cpu_millis
            .zip(self.child_memory_bytes)
            .zip(self.child_pids)
            .map(|((cpu_millis, memory_bytes), pids)| ResourceLimits {
                cpu_millis,
                memory_bytes,
                pids,
            })
    }
    fn features(&self) -> Option<std::collections::BTreeSet<Capability>> {
        if self.no_features {
            Some(Default::default())
        } else {
            self.feature_limit
                .as_ref()
                .map(|items| items.iter().copied().collect())
        }
    }
}

#[derive(Subcommand)]
enum Command {
    Profiles,
    Snapshots {
        #[command(subcommand)]
        command: SnapshotCommand,
    },
    Keys {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Credentials {
        #[command(subcommand)]
        command: CredentialCommand,
    },
    Audit {
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long, default_value_t = 100)]
        limit: u32,
        #[arg(long)]
        through: Option<u64>,
    },
    #[command(flatten)]
    Sandbox(SandboxCommand),
    #[command(flatten)]
    Execution(ExecutionCommand),
    #[command(flatten)]
    Filesystem(FilesystemCommand),
    #[command(flatten)]
    Artifacts(ArtifactsCommand),
    #[command(flatten)]
    Sessions(SessionsCommand),
    #[command(flatten)]
    Code(CodeCommand),
}

#[derive(Subcommand)]
enum KeyCommand {
    Create { request: PathBuf },
    Get { id: Uuid },
    Revoke { id: Uuid },
}

#[derive(Subcommand)]
enum SnapshotCommand {
    Create {
        sandbox: Uuid,
        #[arg(long,value_parser=snapshot_kind)]
        kind: SnapshotKind,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long)]
        no_wait: bool,
    },
    Get {
        id: Uuid,
    },
    List {
        #[arg(long)]
        sandbox: Option<Uuid>,
        #[arg(long)]
        after: Option<Uuid>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    Delete {
        id: Uuid,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long)]
        no_wait: bool,
    },
}

#[derive(Subcommand)]
enum CredentialCommand {
    List {
        sandbox: Uuid,
    },
    Get {
        sandbox: Uuid,
        id: Uuid,
    },
    Put {
        sandbox: Uuid,
        id: Uuid,
        request: PathBuf,
    },
    Revoke {
        sandbox: Uuid,
        id: Uuid,
    },
    Ca {
        sandbox: Uuid,
    },
}

#[derive(Subcommand)]
enum SandboxCommand {
    Create {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        image: String,
        #[arg(long, default_value_t = 1800)]
        ttl: u64,
        #[arg(long, default_value_t = 1073741824)]
        memory_bytes: u64,
        #[arg(long, default_value_t = 1000)]
        cpu_millis: u32,
        #[arg(long, default_value_t = 256)]
        pids: u32,
        #[command(flatten)]
        scope: ScopeArgs,
        #[arg(long)]
        network_policy: Option<PathBuf>,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    List {
        #[arg(long)]
        after: Option<Uuid>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    Get {
        id: Uuid,
    },
    Scope {
        id: Uuid,
    },
    IsolatedCreate {
        parent: Uuid,
        #[arg(long)]
        image: Option<String>,
        #[arg(long)]
        ttl: Option<u64>,
        #[arg(long, default_value_t = 1000)]
        cpu_millis: u32,
        #[arg(long, default_value_t = 1073741824)]
        memory_bytes: u64,
        #[arg(long, default_value_t = 256)]
        pids: u32,
        #[command(flatten)]
        scope: ScopeArgs,
        #[arg(long)]
        network_policy: Option<PathBuf>,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long)]
        no_wait: bool,
    },
    IsolatedList {
        parent: Uuid,
        #[arg(long)]
        after: Option<Uuid>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    Diagnostics {
        id: Uuid,
    },
    NetworkPolicy {
        id: Uuid,
    },
    NetworkPolicySet {
        id: Uuid,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long)]
        no_wait: bool,
    },
    Delete {
        id: Uuid,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Pause {
        id: Uuid,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Resume {
        id: Uuid,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Operation {
        id: Uuid,
    },
}

#[derive(Subcommand)]
enum ExecutionCommand {
    Execution {
        id: Uuid,
    },
    Cancel {
        id: Uuid,
    },
    /// Literal argv after --; streams are collected until explicit completion.
    Exec {
        sandbox: Uuid,
        #[arg(long, default_value_t = 300)]
        timeout: u64,
        #[arg(long, default_value_t = 4194304)]
        output_limit: u64,
        #[arg(long, default_value = "/workspace")]
        cwd: String,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
}

#[derive(Subcommand)]
enum FilesystemCommand {
    Files {
        sandbox: Uuid,
        #[arg(default_value = ".")]
        path: String,
    },
    FilePut {
        sandbox: Uuid,
        local: PathBuf,
        remote: String,
    },
    /// Download atomically; an existing destination is never overwritten.
    FileGet {
        sandbox: Uuid,
        remote: String,
        local: PathBuf,
    },
    FileRemove {
        sandbox: Uuid,
        path: String,
    },
}

#[derive(Subcommand)]
enum ArtifactsCommand {
    #[command(name = "artifact-capture")]
    Capture {
        sandbox: Uuid,
        path: String,
        #[arg(long, default_value = "artifact.bin")]
        name: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    #[command(name = "artifact-get")]
    Get { id: Uuid },
    #[command(name = "artifact-list")]
    List {
        #[arg(long)]
        sandbox: Option<Uuid>,
        #[arg(long)]
        after: Option<Uuid>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    #[command(name = "artifact-download")]
    Download { id: Uuid, local: PathBuf },
    #[command(name = "artifact-delete")]
    Delete {
        id: Uuid,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum SessionsCommand {
    #[command(name = "session-create")]
    Create {
        sandbox: Uuid,
        #[arg(long)]
        pty: bool,
        #[arg(long, default_value_t = 24)]
        rows: u16,
        #[arg(long, default_value_t = 80)]
        columns: u16,
        #[arg(long, default_value_t = 300)]
        timeout: u64,
        #[arg(long, default_value = "/workspace")]
        cwd: String,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(last = true)]
        argv: Vec<String>,
    },
    #[command(name = "session-get")]
    Get { id: Uuid },
    #[command(name = "session-list")]
    List {
        #[arg(long)]
        sandbox: Option<Uuid>,
        #[arg(long)]
        after: Option<Uuid>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Submit at most 64 KiB from a file, or - for stdin. This acknowledges delivery.
    #[command(name = "session-write")]
    Write {
        id: Uuid,
        sequence: u64,
        local: PathBuf,
    },
    #[command(name = "session-close-input")]
    CloseInput { id: Uuid, sequence: u64 },
    #[command(name = "session-resize")]
    Resize {
        id: Uuid,
        sequence: u64,
        rows: u16,
        columns: u16,
    },
    #[command(name = "session-receipt")]
    Receipt { id: Uuid, sequence: u64 },
    /// Emit durable events as JSON lines; EOF without completion is an error.
    #[command(name = "session-events")]
    Events {
        id: Uuid,
        #[arg(long, default_value_t = 0)]
        after: u64,
    },
}

#[derive(Subcommand)]
enum CodeCommand {
    ContextCreate {
        sandbox: Uuid,
        #[arg(long, default_value = "python", value_parser = code_language)]
        language: CodeLanguage,
        #[arg(long, default_value = "/workspace")]
        cwd: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    ContextGet {
        id: Uuid,
    },
    ContextList {
        #[arg(long)]
        sandbox: Option<Uuid>,
        #[arg(long)]
        after: Option<Uuid>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    ContextClose {
        id: Uuid,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Read literal UTF-8 source from a file, or - for stdin; emits a JSON result.
    CodeRun {
        context: Uuid,
        local: PathBuf,
        #[arg(long, default_value_t = 60)]
        timeout: u64,
        #[arg(long, default_value_t = 1048576)]
        output_limit: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Return durable acceptance without waiting for kernel completion.
        #[arg(long)]
        no_wait: bool,
    },
    CodeGet {
        id: Uuid,
    },
    CodeList {
        context: Uuid,
        #[arg(long)]
        after: Option<Uuid>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Cancel the entire interpreter context and wait for collection.
    CodeCancel {
        id: Uuid,
    },
    /// Emit durable JSON events until explicit context collection.
    ContextEvents {
        id: Uuid,
        #[arg(long, default_value_t = 0)]
        after: u64,
    },
}

type CliResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn print_json(value: &impl serde::Serialize) -> CliResult<()> {
    serde_json::to_writer(std::io::stdout().lock(), value)?;
    println!();
    std::io::stdout().flush()?;
    Ok(())
}
fn key(key: Option<String>) -> String {
    key.unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn read_network_policy(path: PathBuf) -> CliResult<NetworkPolicy> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        return Err("network policy file exceeds 64 KiB".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

async fn submit_control(client: &Client, id: Uuid, control: SessionControl) -> CliResult<u8> {
    eprintln!("session_id={id} control_sequence={}", control.sequence);
    client.session_control(id, &control).await?;
    let receipt = client
        .wait_session_control(id, control.sequence, Duration::from_secs(30))
        .await?;
    print_json(&receipt)?;
    Ok(if receipt.state == SessionControlState::Applied {
        0
    } else {
        125
    })
}

async fn session_events(client: &Client, id: Uuid, mut cursor: u64) -> CliResult<()> {
    eprintln!("session_id={id} after={cursor}");
    for _ in 0..3 {
        let mut events = match client.events(id, Some(cursor)).await {
            Ok(events) => events,
            Err(Error::Transport) => continue,
            Err(error) => return Err(error.into()),
        };
        while let Some(event) = events.next().await {
            let event = match event {
                Ok(event) => event,
                Err(Error::Transport) => break,
                Err(error) => return Err(error.into()),
            };
            if event.kind == EventKind::Completed {
                let execution: Execution = serde_json::from_value(event.data.clone())?;
                if execution.id != id
                    || !execution.state.is_terminal()
                    || execution.cleanup != CleanupState::Complete
                    || execution.finished_at.is_none()
                    || (execution.state == ExecutionState::Succeeded
                        && execution.exit_code != Some(0))
                {
                    return Err(Error::Protocol("invalid session completion").into());
                }
                print_json(&event)?;
                return Ok(());
            }
            cursor = event.sequence;
            print_json(&event)?;
        }
    }
    Err(format!("session {id} output ended without completion; resume after={cursor}; the session was not cancelled").into())
}

async fn run(args: Args) -> CliResult<u8> {
    let token = std::env::var("GOLDENHOOP_API_TOKEN")
        .map_err(|_| "set GOLDENHOOP_API_TOKEN in the environment")?;
    let client = Client::new(&args.endpoint, &token)?;
    match args.command {
        Command::Profiles => print_json(&client.profiles().await?)?,
        Command::Snapshots { command } => match command {
            SnapshotCommand::Create {
                sandbox,
                kind,
                idempotency_key,
                no_wait,
            } => {
                let key = key(idempotency_key);
                eprintln!("idempotency_key={key}");
                let created = client
                    .create_snapshot(sandbox, &CreateSnapshot { kind }, &key)
                    .await?;
                eprintln!(
                    "snapshot_id={} operation_id={}",
                    created.snapshot.id, created.operation.id
                );
                if no_wait {
                    print_json(&created)?;
                } else {
                    client
                        .wait_operation(created.operation.id, Duration::from_secs(60))
                        .await?;
                    let snapshot = client.snapshot(created.snapshot.id).await?;
                    if snapshot.state != SnapshotState::Ready {
                        return Err(Error::Protocol(
                            "snapshot is not Ready after capture operation",
                        )
                        .into());
                    }
                    print_json(&snapshot)?;
                }
            }
            SnapshotCommand::Get { id } => print_json(&client.snapshot(id).await?)?,
            SnapshotCommand::List {
                sandbox,
                after,
                limit,
            } => print_json(&client.list_snapshots(sandbox, after, limit).await?)?,
            SnapshotCommand::Delete {
                id,
                idempotency_key,
                no_wait,
            } => {
                let key = key(idempotency_key);
                eprintln!("idempotency_key={key}");
                let operation = client.delete_snapshot(id, &key).await?;
                eprintln!("snapshot_id={id} operation_id={}", operation.id);
                if no_wait {
                    print_json(&operation)?;
                } else {
                    client
                        .wait_operation(operation.id, Duration::from_secs(60))
                        .await?;
                    let snapshot = client.snapshot(id).await?;
                    if snapshot.state != SnapshotState::Collected
                        || snapshot.cleanup != CleanupState::Complete
                    {
                        return Err(
                            Error::Protocol("snapshot object collection is not confirmed").into(),
                        );
                    }
                    print_json(&snapshot)?;
                }
            }
        },
        Command::Keys {
            command: KeyCommand::Create { request },
        } => {
            let mut data = Vec::new();
            std::fs::File::open(request)?
                .take(64 * 1024 + 1)
                .read_to_end(&mut data)?;
            if data.len() > 64 * 1024 {
                return Err("key request exceeds size limit".into());
            }
            let request: CreateApiKey = serde_json::from_slice(&data)?;
            print_json(&client.issue_api_key(&request).await?)?;
        }
        Command::Keys {
            command: KeyCommand::Get { id },
        } => print_json(&client.api_key(id).await?)?,
        Command::Keys {
            command: KeyCommand::Revoke { id },
        } => print_json(&client.revoke_api_key(id).await?)?,
        Command::Audit {
            after,
            limit,
            through,
        } => {
            let page = if let Some(through) = through {
                client.audit_through(after, limit, through).await?
            } else {
                client.audit(after, limit).await?
            };
            print_json(&page)?;
        }
        Command::Credentials { command } => match command {
            CredentialCommand::List { sandbox } => print_json(&client.credentials(sandbox).await?)?,
            CredentialCommand::Get { sandbox, id } => {
                print_json(&client.credential(sandbox, id).await?)?
            }
            CredentialCommand::Revoke { sandbox, id } => {
                print_json(&client.revoke_credential(sandbox, id).await?)?
            }
            CredentialCommand::Ca { sandbox } => print_json(&client.credential_ca(sandbox).await?)?,
            CredentialCommand::Put {
                sandbox,
                id,
                request,
            } => {
                let mut bytes = zeroize::Zeroizing::new(Vec::new());
                std::fs::File::open(request)?
                    .take(256 * 1024 + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > 256 * 1024 {
                    return Err("credential request exceeds 256 KiB".into());
                }
                let request: WriteCredential =
                    serde_json::from_slice(&bytes).map_err(|_| "invalid credential request")?;
                print_json(&client.put_credential(sandbox, id, &request).await?)?;
            }
        },
        Command::Sandbox(SandboxCommand::Create {
            profile,
            image,
            ttl,
            memory_bytes,
            cpu_millis,
            pids,
            scope,
            network_policy,
            idempotency_key,
        }) => {
            let mut request = CreateSandbox::new(profile, image);
            request.ttl_seconds = ttl;
            request.resources = ResourceLimits {
                cpu_millis,
                memory_bytes,
                pids,
            };
            request.child_budget = scope.budget();
            request.feature_limit = scope.features();
            request.required_capabilities = scope.required_capabilities.into_iter().collect();
            if let Some(path) = network_policy {
                request.network = read_network_policy(path)?;
                request
                    .required_capabilities
                    .insert(Capability::NetworkPolicy);
            }
            let key = key(idempotency_key);
            eprintln!("idempotency_key={key}");
            let mut created = client.create(&request, &key).await?;
            // Emit identity before waiting, so a failed observation can be recovered.
            eprintln!(
                "sandbox_id={} operation_id={}",
                created.sandbox.id, created.operation.id
            );
            created.operation = client
                .wait_operation(created.operation.id, Duration::from_secs(60))
                .await?;
            created.sandbox = client.sandbox(created.sandbox.id).await?;
            print_json(&created)?;
        }
        Command::Sandbox(SandboxCommand::Get { id }) => print_json(&client.sandbox(id).await?)?,
        Command::Sandbox(SandboxCommand::Scope { id }) => {
            print_json(&client.sandbox_scope(id).await?)?
        }
        Command::Sandbox(SandboxCommand::IsolatedList {
            parent,
            after,
            limit,
        }) => print_json(&client.isolated_sessions(parent, after, limit).await?)?,
        Command::Sandbox(SandboxCommand::IsolatedCreate {
            parent,
            image,
            ttl,
            cpu_millis,
            memory_bytes,
            pids,
            scope,
            network_policy,
            idempotency_key,
            no_wait,
        }) => {
            let mut request = CreateIsolatedSession {
                image,
                ttl_seconds: ttl,
                resources: ResourceLimits {
                    cpu_millis,
                    memory_bytes,
                    pids,
                },
                child_budget: scope.budget(),
                feature_limit: scope.features(),
                required_capabilities: scope.required_capabilities.into_iter().collect(),
                ..Default::default()
            };
            if let Some(path) = network_policy {
                request.network = Some(read_network_policy(path)?);
                request
                    .required_capabilities
                    .insert(Capability::NetworkPolicy);
            }
            let key = key(idempotency_key);
            eprintln!("idempotency_key={key}");
            let mut created = client
                .create_isolated_session(parent, &request, &key)
                .await?;
            eprintln!(
                "sandbox_id={} operation_id={}",
                created.sandbox.id, created.operation.id
            );
            if !no_wait {
                created.operation = client
                    .wait_operation(created.operation.id, Duration::from_secs(60))
                    .await?;
                created.sandbox = client.sandbox(created.sandbox.id).await?;
                created.scope = client.sandbox_scope(created.sandbox.id).await?;
            }
            print_json(&created)?;
        }
        Command::Sandbox(SandboxCommand::Diagnostics { id }) => {
            print_json(&client.diagnostics(id).await?)?
        }
        Command::Sandbox(SandboxCommand::NetworkPolicy { id }) => {
            print_json(&client.network_policy(id).await?)?
        }
        Command::Sandbox(SandboxCommand::NetworkPolicySet {
            id,
            expected_revision,
            policy,
            idempotency_key,
            no_wait,
        }) => {
            let request = SetNetworkPolicy {
                expected_revision,
                policy: read_network_policy(policy)?,
            };
            let key = key(idempotency_key);
            eprintln!("idempotency_key={key}");
            let mut changed = client.set_network_policy(id, &request, &key).await?;
            eprintln!("sandbox_id={id} operation_id={}", changed.operation.id);
            if !no_wait {
                changed.operation = client
                    .wait_operation(changed.operation.id, Duration::from_secs(60))
                    .await?;
            }
            print_json(&changed)?;
        }
        Command::Sandbox(SandboxCommand::List { after, limit }) => {
            print_json(&client.list(after, limit).await?)?
        }
        Command::Sandbox(SandboxCommand::Delete {
            id,
            idempotency_key,
        }) => {
            let operation = client.terminate(id, &key(idempotency_key)).await?;
            print_json(
                &client
                    .wait_operation(operation.id, Duration::from_secs(60))
                    .await?,
            )?;
            let sandbox = client.sandbox(id).await?;
            if sandbox.cleanup != CleanupState::Complete
                || !matches!(
                    sandbox.state,
                    SandboxState::Terminated | SandboxState::Failed
                )
            {
                return Err(Error::Protocol("sandbox cleanup is not confirmed").into());
            }
        }
        Command::Sandbox(SandboxCommand::Pause {
            id,
            idempotency_key,
        }) => {
            let operation = client.pause(id, &key(idempotency_key)).await?;
            print_json(
                &client
                    .wait_operation(operation.id, Duration::from_secs(60))
                    .await?,
            )?;
        }
        Command::Sandbox(SandboxCommand::Resume {
            id,
            idempotency_key,
        }) => {
            let operation = client.resume(id, &key(idempotency_key)).await?;
            print_json(
                &client
                    .wait_operation(operation.id, Duration::from_secs(60))
                    .await?,
            )?;
        }
        Command::Sandbox(SandboxCommand::Operation { id }) => {
            print_json(&client.operation(id).await?)?
        }
        Command::Execution(ExecutionCommand::Execution { id }) => {
            print_json(&client.execution(id).await?)?
        }
        Command::Execution(ExecutionCommand::Cancel { id }) => {
            print_json(&client.cancel(id).await?)?
        }
        Command::Sessions(SessionsCommand::Create {
            sandbox,
            pty,
            rows,
            columns,
            timeout,
            cwd,
            idempotency_key,
            argv,
        }) => {
            let key = key(idempotency_key);
            eprintln!("idempotency_key={key}");
            let mut spec = SessionSpec::shell();
            if !argv.is_empty() {
                spec.command.argv = argv;
            }
            spec.command.timeout_seconds = timeout;
            spec.command.cwd = cwd;
            if pty {
                spec.terminal = Some(TerminalSize { rows, columns });
            } else if rows != 24 || columns != 80 {
                return Err("terminal size requires --pty".into());
            }
            let session = client.create_session(sandbox, &spec, &key).await?;
            eprintln!("session_id={}", session.execution.id);
            print_json(&session)?;
        }
        Command::Sessions(SessionsCommand::Get { id }) => print_json(&client.session(id).await?)?,
        Command::Sessions(SessionsCommand::List {
            sandbox,
            after,
            limit,
        }) => print_json(&client.list_sessions(sandbox, after, limit).await?)?,
        Command::Sessions(SessionsCommand::Write {
            id,
            sequence,
            local,
        }) => {
            let mut bytes = Vec::new();
            if local == std::path::Path::new("-") {
                std::io::stdin().take(65537).read_to_end(&mut bytes)?;
            } else {
                std::fs::File::open(local)?
                    .take(65537)
                    .read_to_end(&mut bytes)?;
            }
            if bytes.len() > 65536 {
                return Err("session input exceeds 64 KiB".into());
            }
            return submit_control(
                &client,
                id,
                SessionControl {
                    sequence,
                    action: SessionAction::Write {
                        data_base64: STANDARD.encode(bytes),
                    },
                },
            )
            .await;
        }
        Command::Sessions(SessionsCommand::CloseInput { id, sequence }) => {
            return submit_control(
                &client,
                id,
                SessionControl {
                    sequence,
                    action: SessionAction::CloseInput,
                },
            )
            .await;
        }
        Command::Sessions(SessionsCommand::Resize {
            id,
            sequence,
            rows,
            columns,
        }) => {
            return submit_control(
                &client,
                id,
                SessionControl {
                    sequence,
                    action: SessionAction::Resize {
                        size: TerminalSize { rows, columns },
                    },
                },
            )
            .await;
        }
        Command::Sessions(SessionsCommand::Receipt { id, sequence }) => {
            print_json(&client.session_control_status(id, sequence).await?)?
        }
        Command::Sessions(SessionsCommand::Events { id, after }) => {
            session_events(&client, id, after).await?
        }
        Command::Code(CodeCommand::ContextCreate {
            sandbox,
            language,
            cwd,
            idempotency_key,
        }) => {
            let key = key(idempotency_key);
            eprintln!("idempotency_key={key}");
            let context = client
                .create_code_context(sandbox, &CodeContextSpec { language, cwd }, &key)
                .await?;
            eprintln!("context_id={}", context.id);
            print_json(
                &client
                    .wait_code_context_ready(context.id, Duration::from_secs(60))
                    .await?,
            )?;
        }
        Command::Code(CodeCommand::ContextGet { id }) => {
            print_json(&client.code_context(id).await?)?
        }
        Command::Code(CodeCommand::ContextList {
            sandbox,
            after,
            limit,
        }) => print_json(&client.list_code_contexts(sandbox, after, limit).await?)?,
        Command::Code(CodeCommand::ContextClose {
            id,
            idempotency_key,
        }) => {
            let key = key(idempotency_key);
            eprintln!("context_id={id} idempotency_key={key}");
            client.close_code_context(id, &key).await?;
            print_json(
                &client
                    .wait_code_context_closed(id, Duration::from_secs(60))
                    .await?,
            )?;
        }
        Command::Code(CodeCommand::CodeGet { id }) => print_json(&client.code_run(id).await?)?,
        Command::Code(CodeCommand::CodeList {
            context,
            after,
            limit,
        }) => print_json(&client.list_code_runs(context, after, limit).await?)?,
        Command::Code(CodeCommand::CodeRun {
            context,
            local,
            timeout,
            output_limit,
            idempotency_key,
            no_wait,
        }) => {
            let mut bytes = Vec::new();
            if local == std::path::Path::new("-") {
                std::io::stdin().take(65537).read_to_end(&mut bytes)?;
            } else {
                std::fs::File::open(local)?
                    .take(65537)
                    .read_to_end(&mut bytes)?;
            }
            if bytes.is_empty() || bytes.len() > 65536 {
                return Err("code source must contain 1..65536 UTF-8 bytes".into());
            }
            let spec = CodeRunSpec {
                code: String::from_utf8(bytes)?,
                timeout_seconds: timeout,
                max_output_bytes: output_limit,
            };
            let key = key(idempotency_key);
            eprintln!("context_id={context} idempotency_key={key}");
            if no_wait {
                let accepted = client.start_code(context, &spec, &key).await?;
                eprintln!("code_run_id={}", accepted.id);
                print_json(&accepted)?;
            } else {
                let result = client.run_code_with_key(context, &spec, &key).await?;
                eprintln!("code_run_id={}", result.run.id);
                let status = match result.run.state {
                    CodeRunState::KernelSucceeded => 0,
                    CodeRunState::KernelFailed => 1,
                    CodeRunState::TimedOut => 124,
                    CodeRunState::Cancelled => 130,
                    _ => 125,
                };
                print_json(&result)?;
                return Ok(status);
            }
        }
        Command::Code(CodeCommand::CodeCancel { id }) => {
            let accepted = client.cancel_code_run(id).await?;
            if !accepted.state.is_terminal() {
                client
                    .wait_code_context_closed(accepted.context_id, Duration::from_secs(60))
                    .await?;
            }
            let result = client.code_run(id).await?;
            let status = if result.state == CodeRunState::Unknown {
                125
            } else {
                0
            };
            print_json(&result)?;
            return Ok(status);
        }
        Command::Code(CodeCommand::ContextEvents { id, after }) => {
            let mut cursor = after;
            eprintln!("context_id={id} after={cursor}");
            for attempt in 0..3 {
                let mut stream = match client.code_context_events(id, cursor).await {
                    Ok(value) => value,
                    Err(Error::Transport) if attempt < 2 => continue,
                    Err(error) => return Err(error.into()),
                };
                let mut interrupted = false;
                while let Some(event) = stream.next().await {
                    let event = match event {
                        Ok(value) => value,
                        Err(Error::Transport) => {
                            interrupted = true;
                            break;
                        }
                        Err(error) => return Err(error.into()),
                    };
                    cursor = event.sequence;
                    let closed = event.kind == CodeContextEventKind::Closed;
                    print_json(&event)?;
                    if closed {
                        return Ok(0);
                    }
                }
                let context = client.code_context(id).await?;
                if !interrupted
                    && context.cleanup == CleanupState::Complete
                    && matches!(
                        context.state,
                        CodeContextState::Closed | CodeContextState::Failed
                    )
                {
                    return Ok(0);
                }
            }
            return Err(format!("context {id} stream ended without collection; resume after={cursor}; the context was not cancelled").into());
        }
        Command::Execution(ExecutionCommand::Exec {
            sandbox,
            timeout,
            output_limit,
            cwd,
            idempotency_key,
            json,
            argv,
        }) => {
            let mut command = CommandSpec::new(argv);
            command.timeout_seconds = timeout;
            command.max_output_bytes = output_limit;
            command.cwd = cwd;
            let result = client
                .run_with_key(sandbox, &command, &key(idempotency_key))
                .await?;
            if json {
                print_json(&serde_json::json!({"execution":result.execution,
                    "stdout_base64":STANDARD.encode(&result.stdout),"stderr_base64":STANDARD.encode(&result.stderr)}))?;
            } else {
                std::io::stdout().lock().write_all(&result.stdout)?;
                std::io::stderr().lock().write_all(&result.stderr)?;
            }
            return Ok(match result.execution.state {
                ExecutionState::Succeeded => 0,
                ExecutionState::TimedOut => 124,
                ExecutionState::Cancelled => 130,
                _ => result
                    .execution
                    .exit_code
                    .and_then(|n| u8::try_from(n).ok())
                    .filter(|n| *n != 0)
                    .unwrap_or(1),
            });
        }
        Command::Filesystem(FilesystemCommand::Files { sandbox, path }) => {
            print_json(&client.list_files(sandbox, &path).await?)?
        }
        Command::Filesystem(FilesystemCommand::FilePut {
            sandbox,
            local,
            remote,
        }) => {
            let mut data = Vec::new();
            std::fs::File::open(local)?
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut data)?;
            client.write_file(sandbox, &remote, &data).await?;
        }
        Command::Filesystem(FilesystemCommand::FileGet {
            sandbox,
            remote,
            local,
        }) => {
            let data = client.read_file(sandbox, &remote, 16 * 1024 * 1024).await?;
            let parent = local
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            temporary.write_all(&data)?;
            temporary.as_file().sync_all()?;
            temporary
                .persist_noclobber(local)
                .map_err(|error| error.error)?;
        }
        Command::Filesystem(FilesystemCommand::FileRemove { sandbox, path }) => {
            client.remove_file(sandbox, &path).await?
        }
        Command::Artifacts(ArtifactsCommand::Capture {
            sandbox,
            path,
            name,
            idempotency_key,
        }) => {
            let key = key(idempotency_key);
            eprintln!("idempotency_key={key}");
            let created = client
                .create_artifact(sandbox, &CreateArtifact { path, name }, &key)
                .await?;
            eprintln!(
                "artifact_id={} operation_id={}",
                created.artifact.id, created.operation.id
            );
            client
                .wait_operation(created.operation.id, Duration::from_secs(60))
                .await?;
            let artifact = client.artifact(created.artifact.id).await?;
            if artifact.state != ArtifactState::Available {
                return Err(Error::Protocol("artifact is not available after capture").into());
            }
            print_json(&artifact)?;
        }
        Command::Artifacts(ArtifactsCommand::Get { id }) => {
            print_json(&client.artifact(id).await?)?
        }
        Command::Artifacts(ArtifactsCommand::List {
            sandbox,
            after,
            limit,
        }) => print_json(&client.list_artifacts(sandbox, after, limit).await?)?,
        Command::Artifacts(ArtifactsCommand::Download { id, local }) => {
            let bytes = client.artifact_bytes(id).await?;
            let parent = local
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            temporary.write_all(&bytes)?;
            temporary.as_file().sync_all()?;
            temporary
                .persist_noclobber(local)
                .map_err(|error| error.error)?;
        }
        Command::Artifacts(ArtifactsCommand::Delete {
            id,
            idempotency_key,
        }) => {
            let operation = client.delete_artifact(id, &key(idempotency_key)).await?;
            client
                .wait_operation(operation.id, Duration::from_secs(60))
                .await?;
            let artifact = client.artifact(id).await?;
            if artifact.state != ArtifactState::Deleted
                || artifact.cleanup != CleanupState::Complete
            {
                return Err(Error::Protocol("artifact cleanup is not confirmed").into());
            }
            print_json(&artifact)?;
        }
    }
    Ok(0)
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run(Args::parse()).await {
        Ok(code) => std::process::ExitCode::from(code),
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::from(125)
        }
    }
}
