#[cfg(target_os = "linux")]
mod server {
    use goldenhoop_egress::controller::{Envelope, MAX_FRAME, Request};
    use goldenhoop_egress::{Allocation, Listening, Manager, Observation, Resolution};
    use goldenhoop_protocol::{ApiError, ErrorCode};
    use serde::Serialize;
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    #[derive(Serialize)]
    #[serde(untagged)]
    enum Reply {
        State(Observation),
        Dns(Resolution),
        Source(serde_json::Value),
        Listening(Listening),
    }

    async fn execute(
        manager: &mut Option<Manager>,
        frontend: &mut Option<goldenhoop_egress::frontend::Frontend>,
        queries: &tokio::sync::mpsc::Sender<goldenhoop_egress::frontend::QueryRequest>,
        request: Request,
    ) -> Result<Reply, ApiError> {
        if let Request::Open { allocation } = request {
            if manager.is_some() {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "controller already has an allocation",
                ));
            }
            let opened = Manager::new(allocation).await?;
            let observed = opened.inspect().await?;
            *manager = Some(opened);
            return Ok(Reply::State(observed));
        }
        let manager = manager.as_mut().ok_or_else(|| {
            ApiError::new(ErrorCode::InvalidState, "open a trusted allocation first")
        })?;
        match request {
            Request::ProtectDestinations {
                expected_revision,
                private_exceptions,
                control_addresses,
            } => {
                manager
                    .protect_destinations(expected_revision, private_exceptions, control_addresses)
                    .await
            }
            Request::BindSource {
                expected_revision,
                endpoint,
            } => manager.bind_source(expected_revision, endpoint).await,
            Request::EnableEthernet { expected_revision } => {
                manager.enable_ethernet(expected_revision).await
            }
            Request::ListenDns { expected_revision } => {
                if frontend.is_some() {
                    return Err(ApiError::new(
                        ErrorCode::Conflict,
                        "DNS frontend is already running",
                    ));
                }
                let (state, sockets) = manager.listen_dns(expected_revision).await?;
                *frontend = Some(sockets.serve(queries.clone()));
                return Ok(Reply::Listening(state));
            }

            Request::Resolve { wire, tcp } => {
                return manager.resolve(&wire, tcp).await.map(Reply::Dns);
            }
            Request::DnsSource { name, aaaa } => {
                return manager.dns_source(&name, aaaa).await.map(Reply::Source);
            }
            Request::EnableDns {
                expected_revision,
                upstream,
                remaining_seconds,
            } => {
                manager
                    .enable_dns(expected_revision, upstream, remaining_seconds)
                    .await
            }
            Request::Install {} => manager.install().await,
            Request::Apply {
                expected_revision,
                config,
            } => manager.apply(expected_revision, &config).await,
            Request::Quarantine { expected_revision } => {
                manager.quarantine(expected_revision).await
            }
            Request::Renew { expected_revision } => manager.renew(expected_revision).await,
            Request::Inspect {} => manager.inspect().await,
            Request::Remove { expected_revision } => {
                let observed = manager.remove(expected_revision).await?;
                if let Some(frontend) = frontend.take() {
                    frontend.shutdown().await;
                }
                Ok(observed)
            }
            Request::Open { .. } => unreachable!("handled above"),
        }
        .map(Reply::State)
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
        let mut manager: Option<Manager> = None;
        let mut frontend: Option<goldenhoop_egress::frontend::Frontend> = None;
        let (queries, mut incoming) = goldenhoop_egress::frontend::channel();
        let mut input = BufReader::new(tokio::io::stdin());
        let mut output = tokio::io::stdout();
        let mut bytes = Vec::new();
        loop {
            let remaining = (MAX_FRAME + 1).saturating_sub(bytes.len() as u64);
            let mut bounded = (&mut input).take(remaining);
            let read = tokio::select! {
                biased;
                count=bounded.read_until(b'\n',&mut bytes)=>Some(count?),
                Some(query)=incoming.recv(),if frontend.is_some()=>{
                    if !query.reply.is_closed(){
                        let result=match manager.as_mut(){Some(manager)=>manager.resolve(&query.wire,query.tcp).await,None=>Err(ApiError::new(ErrorCode::InvalidState,"DNS allocation is unavailable"))};
                        let response=match result{Ok(resolved)=>Some(resolved.wire),Err(error)=>goldenhoop_egress::dns::failure_wire(&query.wire,error.code)};
                        if let Some(response)=response{let _=query.reply.send(response);}
                    }
                    None
                }
            };
            let Some(count) = read else { continue };
            if count == 0 && bytes.is_empty() {
                if let Some(frontend) = frontend.take() {
                    frontend.shutdown().await;
                }
                return Ok(());
            }
            let frame_valid = bytes.len() as u64 <= MAX_FRAME && bytes.last() == Some(&b'\n');
            let response = if frame_valid {
                match serde_json::from_slice::<Envelope>(&bytes) {
                    Ok(frame) => {
                        match execute(&mut manager, &mut frontend, &queries, frame.command).await {
                            Ok(value) => json!({"id":frame.id,"result":value}),
                            Err(error) => json!({"id":frame.id,"error":error}),
                        }
                    }
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
            bytes.clear();
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
