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
        Native(goldenhoop_egress::native::NativeBridgeObservation),
        Collected(goldenhoop_egress::CollectionReceipt),
        BoundSource(goldenhoop_egress::SourceBindingReceipt),
        Binding(goldenhoop_egress::ProtectedBindingReceipt),
        Effective(goldenhoop_egress::EffectivePolicyReceipt),
    }

    async fn execute(
        collection_only: bool,
        manager: &mut Option<Manager>,
        native_context: &mut Option<goldenhoop_egress::native::NativeBridgePlan>,
        frontend: &mut Option<goldenhoop_egress::frontend::Frontend>,
        queries: &tokio::sync::mpsc::Sender<goldenhoop_egress::frontend::QueryRequest>,
        request: Request,
    ) -> Result<Reply, ApiError> {
        if collection_only
            && !matches!(
                &request,
                Request::Open { .. } | Request::Inspect {} | Request::Remove { .. }
            )
        {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "collection controller refuses enforcement commands",
            ));
        }
        if let Request::BindNative { plan } = request {
            if manager.is_some() {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "native binding requires no active manager",
                ));
            }
            if native_context.as_ref().is_some_and(|bound| {
                serde_json::to_value(bound).ok() != serde_json::to_value(&plan).ok()
            }) {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "native dispatch is already frozen",
                ));
            }
            let observed = goldenhoop_egress::native::bind(plan.clone()).await?;
            *native_context = Some(plan);
            return Ok(Reply::Native(observed));
        }
        if let Request::Open { allocation } = request {
            if manager.is_some() {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "controller already has an allocation",
                ));
            }
            if native_context
                .as_ref()
                .is_some_and(|bound| bound.allocation.owner() != allocation.owner())
            {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "allocation differs from native dispatch",
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
            Request::RecoverDns {
                expected_revision,
                upstream,
                source,
                destinations,
            } => {
                if frontend.is_some() {
                    return Err(ApiError::new(
                        ErrorCode::Conflict,
                        "DNS frontend is already running",
                    ));
                }
                let bound = native_context.as_ref().ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::InvalidState,
                        "bind original native lifetime before recovery",
                    )
                })?;
                bound.validate_at(chrono::Utc::now())?;
                let (state, sockets) = manager
                    .recover_dns(
                        expected_revision,
                        upstream,
                        bound.expires_at,
                        &source,
                        &destinations,
                    )
                    .await?;
                *frontend = Some(sockets.serve(queries.clone()));
                return Ok(Reply::Listening(state));
            }
            Request::ConfigureDns {
                expected_revision,
                upstream,
            } => {
                let bound = native_context.as_ref().ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::InvalidState,
                        "bind original native lifetime before DNS",
                    )
                })?;
                bound.validate_at(chrono::Utc::now())?;
                manager
                    .configure_dns_until(expected_revision, upstream, bound.expires_at)
                    .await
            }
            Request::InspectBinding { expected_revision } => {
                if !frontend
                    .as_ref()
                    .is_some_and(|frontend| frontend.is_running())
                {
                    return Err(ApiError::new(
                        ErrorCode::InvalidState,
                        "protected DNS frontend is not running",
                    ));
                }
                let receipt = manager.inspect_binding(expected_revision).await?;
                if !frontend
                    .as_ref()
                    .is_some_and(|frontend| frontend.is_running())
                {
                    return Err(ApiError::new(
                        ErrorCode::BackendUnavailable,
                        "protected DNS frontend stopped during inspection",
                    ));
                }
                return Ok(Reply::Binding(receipt));
            }
            Request::InspectPolicy { expected_revision } => {
                let bound = native_context.as_ref().ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::InvalidState,
                        "bind original native lifetime before policy inspection",
                    )
                })?;
                bound.validate_at(chrono::Utc::now())?;
                if !frontend.as_ref().is_some_and(|f| f.is_running()) {
                    return Err(ApiError::new(
                        ErrorCode::InvalidState,
                        "protected DNS frontend is not running",
                    ));
                }
                let receipt = manager.inspect_policy(expected_revision).await?;
                if receipt.binding.expires_at != bound.expires_at
                    || receipt.binding.allocation.owner() != bound.allocation.owner()
                    || !frontend.as_ref().is_some_and(|f| f.is_running())
                {
                    return Err(ApiError::new(
                        ErrorCode::BackendUnavailable,
                        "effective policy frontend or original context changed",
                    ));
                }
                return Ok(Reply::Effective(receipt));
            }
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
            Request::BindRuntimeSource {
                expected_revision,
                addresses,
            } => {
                return manager
                    .bind_runtime_source(expected_revision, addresses)
                    .await
                    .map(Reply::BoundSource);
            }
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
                if collection_only {
                    return Ok(Reply::Collected(goldenhoop_egress::CollectionReceipt {
                        allocation: manager.allocation().clone(),
                        bridge_absent: true,
                        owned_tables_absent: true,
                        observed_at: chrono::Utc::now(),
                    }));
                }
                Ok(observed)
            }
            Request::Open { .. } | Request::BindNative { .. } => unreachable!("handled above"),
        }
        .map(Reply::State)
    }

    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::args_os()
            .nth(1)
            .is_some_and(|v| v == "--probe-native")
            && std::env::args_os().len() == 3
        {
            let raw = std::env::args().nth(2).ok_or("missing probe plan")?;
            if raw.len() as u64 > MAX_FRAME {
                return Err("oversized probe plan".into());
            }
            let plan: goldenhoop_egress::ProbePlan = serde_json::from_str(&raw)?;
            let observed = goldenhoop_egress::observe_probe(plan).await?;
            let mut bytes = serde_json::to_vec(&observed)?;
            bytes.push(b'\n');
            tokio::io::stdout().write_all(&bytes).await?;
            return Ok(());
        }
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
        let collection_only = std::env::args_os().len() == 2
            && std::env::args_os()
                .nth(1)
                .is_some_and(|arg| arg == "--collection-only");
        if std::env::args_os().len() != 1 && !collection_only {
            return Err("manager accepts private JSON-line control on stdio only".into());
        }
        let mut manager: Option<Manager> = None;
        let mut native_context = None;
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
                        match execute(
                            collection_only,
                            &mut manager,
                            &mut native_context,
                            &mut frontend,
                            &queries,
                            frame.command,
                        )
                        .await
                        {
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
