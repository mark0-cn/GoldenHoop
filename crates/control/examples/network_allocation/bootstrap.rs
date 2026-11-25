//! Actual production-driver staging, not workload readiness or policy publication.
use super::*;
use goldenhoop_docker::{ControllerPlan, ControllerSession, WorkloadNetworkPlan};

pub(super) async fn run(
    args: &Args,
    store: &Store,
    plan: &ControllerPlan,
    session: &mut ControllerSession,
) -> Result<Value, ApiError> {
    frame(&json!({"bootstrap_stage":"entered"}));
    let profile = match plan.native.identity.profile.as_str() {
        "local-runc-dev" => DockerProfile::RuncDevelopment,
        "local-gvisor" => DockerProfile::Gvisor,
        _ => return Err(invalid()),
    };
    let driver = DockerDriver::connect(DockerConfig {
        installation_id: store.installation_id(),
        agent_image: args.agent_image.clone(),
        profile,
        allow_runc_development: matches!(profile, DockerProfile::RuncDevelopment),
    })
    .await?;
    frame(&json!({"bootstrap_stage":"connected_before_profile_probe"}));
    // This nested debug contract otherwise polls the complete driver probe on
    // Windows' main thread below the controller/RPC futures. Join an owned task
    // so the probe runs from the runtime task boundary, as worker reconciliation does.
    let probing = driver.clone();
    let observed = tokio::spawn(async move { probing.probe().await })
        .await
        .map_err(|_| invalid())?;
    frame(&json!({"bootstrap_stage":"profile_probed"}));
    require(
        observed.availability == Availability::Available
            && !observed.capabilities.contains(&Capability::NetworkPolicy),
    )?;
    let id = plan.native.identity.sandbox_id;
    let mut stored = store.sandbox(id).await?;
    let native = store
        .network_allocation(id)
        .await?
        .native_binding()
        .ok_or_else(invalid)?;
    let network = WorkloadNetworkPlan {
        native: plan.native.clone(),
        network_id: native.network_id,
    };
    controller_call(session, ControllerRequest::Install {}).await?;
    // Even a live controller and installed inet deny table cannot substitute
    // for the immutable Ethernet floor before a runtime is created.
    require(
        driver
            .prepare_quarantined(&stored.sandbox, &stored.request, &network, session)
            .await
            .is_err(),
    )?;
    require(!driver.discover().await?.iter().any(|h| h.sandbox_id == id))?;
    let ethernet = controller_call(
        session,
        ControllerRequest::EnableEthernet {
            expected_revision: 0,
        },
    )
    .await;
    if let Err(error) = ethernet {
        require(args.bootstrap_expect_bridge_unavailable && !args.bootstrap_stop_after_prepare)?;
        require(!driver.discover().await?.iter().any(|h| h.sandbox_id == id))?;
        return Ok(
            json!({"mode":"unsupported_bridge_refusal","missing_floor_refused_before_creation":true,"ethernet_error":error,"profile":observed,"workload_ready":false}),
        );
    }
    require(!args.bootstrap_expect_bridge_unavailable)?;
    let handle = driver
        .prepare_quarantined(&stored.sandbox, &stored.request, &network, session)
        .await?;
    stored.handle = Some(handle.clone());
    stored.sandbox.state = SandboxState::Starting;
    stored.sandbox.cleanup = CleanupState::Pending;
    stored.sandbox.observed_at = Some(Utc::now());
    store.observe(stored.clone()).await?;
    frame(
        &json!({"bootstrap_prepared":{"handle":handle,"network":network,"stored":store.sandbox(id).await?.sandbox,"observation":driver.inspect(&handle).await?}}),
    );
    if args.bootstrap_stop_after_prepare {
        eprintln!("controlled exit after committed runtime identity before trusted-agent start");
        std::process::exit(79);
    }
    let result=async {
        require(driver.inspect(&handle).await?.state==goldenhoop_runtime::ObservedState::Starting)?;
        require(driver.create(&stored.sandbox,&stored.request).await.is_err())?;
        require(driver.inspect(&handle).await?.state==goldenhoop_runtime::ObservedState::Starting)?;
        let endpoint=driver.start_quarantined(&handle,&network,session).await?;
        require(driver.start_quarantined(&handle,&network,session).await.is_err())?;
        require(driver.prepare_quarantined(&stored.sandbox,&stored.request,&network,session).await.is_err())?;
        let independent=driver.observe_quarantined_endpoint(&handle,&network).await?;
        require(serde_json::to_value(&endpoint).map_err(|_|invalid())?==serde_json::to_value(independent).map_err(|_|invalid())?)?;
        let source=driver.bind_quarantined_source(&handle,&network,session).await?;
        require(driver.bind_quarantined_source(&handle,&network,session).await.is_err() && !session.is_uncertain())?;
        let current=store.sandbox(id).await?;
        require(current.sandbox.state==SandboxState::Starting && !current.ever_running)?;
        Ok::<Value,ApiError>(json!({"mode":"trusted_agent_quarantined","handle":handle,"network":network,"endpoint":endpoint,"source_binding":source,"duplicate_source_binding_refused":true,"missing_floor_refused_before_creation":true,"none_network_fallback_refused":true,"duplicate_start_refused":true,"nonempty_bootstrap_refused":true,"workload_ready":false,"user_execution_dispatched":false,"stored":current.sandbox,"ever_running":current.ever_running,"guard":controller_call(session,ControllerRequest::Inspect{}).await?,"profile":observed}))
    }.await;
    if result.is_err() {
        driver.remove(&handle).await?;
    }
    result
}
