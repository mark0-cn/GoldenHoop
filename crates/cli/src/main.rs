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

#[derive(Subcommand)]
enum Command {
    Profiles,
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
    Diagnostics {
        id: Uuid,
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
    ArtifactCapture {
        sandbox: Uuid,
        path: String,
        #[arg(long, default_value = "artifact.bin")]
        name: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    ArtifactGet {
        id: Uuid,
    },
    ArtifactList {
        #[arg(long)]
        sandbox: Option<Uuid>,
        #[arg(long)]
        after: Option<Uuid>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    ArtifactDownload {
        id: Uuid,
        local: PathBuf,
    },
    ArtifactDelete {
        id: Uuid,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    SessionCreate {
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
    SessionGet {
        id: Uuid,
    },
    SessionList {
        #[arg(long)]
        sandbox: Option<Uuid>,
        #[arg(long)]
        after: Option<Uuid>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Submit at most 64 KiB from a file, or - for stdin. This acknowledges delivery.
    SessionWrite {
        id: Uuid,
        sequence: u64,
        local: PathBuf,
    },
    SessionCloseInput {
        id: Uuid,
        sequence: u64,
    },
    SessionResize {
        id: Uuid,
        sequence: u64,
        rows: u16,
        columns: u16,
    },
    SessionReceipt {
        id: Uuid,
        sequence: u64,
    },
    /// Emit durable events as JSON lines; EOF without completion is an error.
    SessionEvents {
        id: Uuid,
        #[arg(long, default_value_t = 0)]
        after: u64,
    },
    ContextCreate {
        sandbox: Uuid,
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
        Command::Create {
            profile,
            image,
            ttl,
            memory_bytes,
            cpu_millis,
            pids,
            idempotency_key,
        } => {
            let mut request = CreateSandbox::new(profile, image);
            request.ttl_seconds = ttl;
            request.resources = ResourceLimits {
                cpu_millis,
                memory_bytes,
                pids,
            };
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
        Command::Get { id } => print_json(&client.sandbox(id).await?)?,
        Command::Diagnostics { id } => print_json(&client.diagnostics(id).await?)?,
        Command::List { after, limit } => print_json(&client.list(after, limit).await?)?,
        Command::Delete {
            id,
            idempotency_key,
        } => {
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
        Command::Pause {
            id,
            idempotency_key,
        } => {
            let operation = client.pause(id, &key(idempotency_key)).await?;
            print_json(
                &client
                    .wait_operation(operation.id, Duration::from_secs(60))
                    .await?,
            )?;
        }
        Command::Resume {
            id,
            idempotency_key,
        } => {
            let operation = client.resume(id, &key(idempotency_key)).await?;
            print_json(
                &client
                    .wait_operation(operation.id, Duration::from_secs(60))
                    .await?,
            )?;
        }
        Command::Operation { id } => print_json(&client.operation(id).await?)?,
        Command::Execution { id } => print_json(&client.execution(id).await?)?,
        Command::Cancel { id } => print_json(&client.cancel(id).await?)?,
        Command::SessionCreate {
            sandbox,
            pty,
            rows,
            columns,
            timeout,
            cwd,
            idempotency_key,
            argv,
        } => {
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
        Command::SessionGet { id } => print_json(&client.session(id).await?)?,
        Command::SessionList {
            sandbox,
            after,
            limit,
        } => print_json(&client.list_sessions(sandbox, after, limit).await?)?,
        Command::SessionWrite {
            id,
            sequence,
            local,
        } => {
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
        Command::SessionCloseInput { id, sequence } => {
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
        Command::SessionResize {
            id,
            sequence,
            rows,
            columns,
        } => {
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
        Command::SessionReceipt { id, sequence } => {
            print_json(&client.session_control_status(id, sequence).await?)?
        }
        Command::SessionEvents { id, after } => session_events(&client, id, after).await?,
        Command::ContextCreate {
            sandbox,
            cwd,
            idempotency_key,
        } => {
            let key = key(idempotency_key);
            eprintln!("idempotency_key={key}");
            let context = client
                .create_code_context(
                    sandbox,
                    &CodeContextSpec {
                        cwd,
                        ..Default::default()
                    },
                    &key,
                )
                .await?;
            eprintln!("context_id={}", context.id);
            print_json(
                &client
                    .wait_code_context_ready(context.id, Duration::from_secs(60))
                    .await?,
            )?;
        }
        Command::ContextGet { id } => print_json(&client.code_context(id).await?)?,
        Command::ContextList {
            sandbox,
            after,
            limit,
        } => print_json(&client.list_code_contexts(sandbox, after, limit).await?)?,
        Command::ContextClose {
            id,
            idempotency_key,
        } => {
            let key = key(idempotency_key);
            eprintln!("context_id={id} idempotency_key={key}");
            client.close_code_context(id, &key).await?;
            print_json(
                &client
                    .wait_code_context_closed(id, Duration::from_secs(60))
                    .await?,
            )?;
        }
        Command::CodeGet { id } => print_json(&client.code_run(id).await?)?,
        Command::CodeList {
            context,
            after,
            limit,
        } => print_json(&client.list_code_runs(context, after, limit).await?)?,
        Command::CodeRun {
            context,
            local,
            timeout,
            output_limit,
            idempotency_key,
            no_wait,
        } => {
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
        Command::CodeCancel { id } => {
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
        Command::ContextEvents { id, after } => {
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
        Command::Exec {
            sandbox,
            timeout,
            output_limit,
            cwd,
            idempotency_key,
            json,
            argv,
        } => {
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
        Command::Files { sandbox, path } => print_json(&client.list_files(sandbox, &path).await?)?,
        Command::FilePut {
            sandbox,
            local,
            remote,
        } => {
            let mut data = Vec::new();
            std::fs::File::open(local)?
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut data)?;
            client.write_file(sandbox, &remote, &data).await?;
        }
        Command::FileGet {
            sandbox,
            remote,
            local,
        } => {
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
        Command::FileRemove { sandbox, path } => client.remove_file(sandbox, &path).await?,
        Command::ArtifactCapture {
            sandbox,
            path,
            name,
            idempotency_key,
        } => {
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
        Command::ArtifactGet { id } => print_json(&client.artifact(id).await?)?,
        Command::ArtifactList {
            sandbox,
            after,
            limit,
        } => print_json(&client.list_artifacts(sandbox, after, limit).await?)?,
        Command::ArtifactDownload { id, local } => {
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
        Command::ArtifactDelete {
            id,
            idempotency_key,
        } => {
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
