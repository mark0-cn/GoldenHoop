#[cfg(target_os = "linux")]
mod server {
    use goldenhoop_egress::{Allocation, Config, Manager, Observation};
    use goldenhoop_protocol::{ApiError, ErrorCode};
    use serde::Deserialize;
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    const MAX_FRAME: u64 = 256 * 1024;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        id: u64,
        command: Request,
    }

    #[derive(Deserialize)]
    #[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
    enum Request {
        Open {
            allocation: Allocation,
        },
        Install,
        Apply {
            expected_revision: u64,
            config: Config,
        },
        Quarantine {
            expected_revision: u64,
        },
        Renew {
            expected_revision: u64,
        },
        Inspect,
        Remove {
            expected_revision: u64,
        },
    }

    async fn execute(
        manager: &mut Option<Manager>,
        request: Request,
    ) -> Result<Observation, ApiError> {
        if let Request::Open { allocation } = request {
            if manager.is_some() {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "controller already has an allocation",
                ));
            }
            let opened = Manager::new(allocation)?;
            let observed = opened.inspect().await?;
            *manager = Some(opened);
            return Ok(observed);
        }
        let manager = manager.as_mut().ok_or_else(|| {
            ApiError::new(ErrorCode::InvalidState, "open a trusted allocation first")
        })?;
        match request {
            Request::Install => manager.install().await,
            Request::Apply {
                expected_revision,
                config,
            } => manager.apply(expected_revision, &config).await,
            Request::Quarantine { expected_revision } => {
                manager.quarantine(expected_revision).await
            }
            Request::Renew { expected_revision } => manager.renew(expected_revision).await,
            Request::Inspect => manager.inspect().await,
            Request::Remove { expected_revision } => manager.remove(expected_revision).await,
            Request::Open { .. } => unreachable!("handled above"),
        }
    }

    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::args_os()
            .nth(1)
            .is_some_and(|arg| arg == "--probe-dns-sets")
            && std::env::args_os().len() == 2
        {
            let mut bytes = Vec::new();
            tokio::io::stdin()
                .take(MAX_FRAME + 1)
                .read_to_end(&mut bytes)
                .await?;
            if bytes.len() as u64 > MAX_FRAME {
                return Err("oversized probe allocation".into());
            }
            let allocation = serde_json::from_slice::<Allocation>(&bytes)?;
            let result = goldenhoop_egress::dns::probe_staged_sets(allocation).await?;
            println!("{}", serde_json::to_string(&result)?);
            return Ok(());
        }
        if std::env::args_os().len() != 1 {
            return Err("manager accepts private JSON-line control on stdio only".into());
        }
        let mut manager = None;
        let mut input = BufReader::new(tokio::io::stdin());
        let mut output = tokio::io::stdout();
        loop {
            let mut bytes = Vec::new();
            let count = (&mut input)
                .take(MAX_FRAME + 1)
                .read_until(b'\n', &mut bytes)
                .await?;
            if count == 0 {
                return Ok(());
            }
            let frame_valid = count as u64 <= MAX_FRAME && bytes.last() == Some(&b'\n');
            let response = if frame_valid {
                match serde_json::from_slice::<Envelope>(&bytes) {
                    Ok(frame) => match execute(&mut manager, frame.command).await {
                        Ok(value) => json!({"id":frame.id,"result":value}),
                        Err(error) => json!({"id":frame.id,"error":error}),
                    },
                    Err(_) => {
                        json!({"id":null,"error":ApiError::new(ErrorCode::InvalidRequest,"invalid egress control frame")})
                    }
                }
            } else {
                json!({"id":null,"error":ApiError::new(ErrorCode::InvalidRequest,"oversized or incomplete egress control frame")})
            };
            let mut encoded = serde_json::to_vec(&response)?;
            encoded.push(b'\n');
            output.write_all(&encoded).await?;
            output.flush().await?;
            if !frame_valid {
                return Err("control framing lost".into());
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    server::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("goldenhoop-egress requires a hardened Linux host network namespace");
    std::process::exit(1);
}
