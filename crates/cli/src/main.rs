use std::{
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};
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
}

type CliResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn print_json(value: &impl serde::Serialize) -> CliResult<()> {
    serde_json::to_writer(std::io::stdout().lock(), value)?;
    println!();
    Ok(())
}
fn key(key: Option<String>) -> String {
    key.unwrap_or_else(|| Uuid::new_v4().to_string())
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
