use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "goldenhoop-agent",
    version,
    about = "Sandbox-local agent; not a host command runner"
)]
struct Args {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    Serve {
        #[arg(long, default_value = "/run/goldenhoop/agent.sock")]
        socket: std::path::PathBuf,
        #[arg(long, default_value = "/workspace")]
        workspace: std::path::PathBuf,
    },
    Rpc {
        #[arg(long, default_value = "/run/goldenhoop/agent.sock")]
        socket: std::path::PathBuf,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    #[cfg(target_os = "linux")]
    match args.command {
        Action::Serve { socket, workspace } => {
            if std::env::var("GOLDENHOOP_ISOLATED_AGENT").as_deref() != Ok("1") {
                return Err(
                    "refusing host execution: isolated worker environment is required".into(),
                );
            }
            goldenhoop_agent::service::serve(&socket, &workspace).await?;
        }
        Action::Rpc { socket } => {
            goldenhoop_agent::service::rpc_stdio(&socket).await?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        return Err("the execution agent requires a Linux sandbox".into());
    }
    #[allow(unreachable_code)]
    Ok(())
}
