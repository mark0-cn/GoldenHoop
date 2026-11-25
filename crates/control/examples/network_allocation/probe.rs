//! Actual probe dispatch and producer-loss windows, private debug contract only.
use super::*;
use goldenhoop_egress::{HostProcessPlan, ProbePurpose};

pub(super) async fn run(
    args: &Args,
    store: &Store,
    provider: &DockerNetworkProvider,
    network: &NetworkAllocation,
    network_plan: &NetworkPlan,
) -> Result<Value, ApiError> {
    let generation = args.probe_generation.ok_or_else(invalid)?;
    let id = network.sandbox_id;
    if matches!(args.action, Action::AutoNative) {
        let (binding, observed, collected) = goldenhoop_control::host_process::discover_native(
            store,
            id,
            generation,
            args.controller_image.as_deref().ok_or_else(invalid)?,
        )
        .await?;
        return Ok(
            json!({"binding":binding,"observation":observed,"probe":collected,"journal":store.network_allocation(id).await?,"manual_ifindex_input":false,"packet_permissions_granted":false}),
        );
    }
    let record = if matches!(args.action, Action::ProbeReserve | Action::ProbeCreate) {
        let actual = provider.lookup(network_plan).await?.ok_or_else(invalid)?;
        require(actual.attached_endpoints == 0)?;
        store
            .reserve_network_probe(
                id,
                network.generation,
                generation,
                args.controller_image.as_deref().ok_or_else(invalid)?,
                ProbePurpose::Discover,
                Some(&actual.network_id),
            )
            .await?
    } else {
        require(args.controller_image.is_none())?;
        store.network_controller(id, generation).await?
    };
    let HostProcessPlan::Probe(plan) = &record.plan else {
        return Err(invalid());
    };
    frame(&json!({"probe_plan":plan,"probe_journal":record}));
    if matches!(args.action, Action::ProbeReserve) {
        return Ok(json!({"probe":record,"dispatch_performed":false}));
    }
    let processes = DockerControllerProvider::connect(&plan.image_id).await?;
    if matches!(args.action, Action::ProbeCreate) {
        let creating = store
            .begin_controller_create(id, generation, record.revision)
            .await?;
        frame(&json!({"probe_create_intent":creating}));
        let actual = processes.create_probe(plan).await?;
        frame(&json!({"actual_probe_created":actual}));
        if args.fault_after_probe_create {
            std::process::exit(83);
        }
        let created = store
            .record_controller_created(
                id,
                generation,
                creating.create_token.ok_or_else(invalid)?,
                &actual.container_id,
            )
            .await?;
        return Ok(json!({"probe":created,"actual":actual,"start_dispatched":false}));
    }
    if args.fault_after_probe_start {
        let starting = store
            .begin_controller_start(id, generation, record.revision)
            .await?;
        frame(&json!({"probe_start_intent":starting}));
        let actual = processes
            .start_probe(plan, starting.container_id.as_deref().ok_or_else(invalid)?)
            .await?;
        frame(&json!({"actual_probe_started":actual}));
        std::process::exit(84);
    }
    let (binding, observed, collected) =
        goldenhoop_control::host_process::discover_native(store, id, generation, &plan.image_id)
            .await?;
    Ok(
        json!({"binding":binding,"observation":observed,"probe":collected,"journal":store.network_allocation(id).await?,"creation_replayed":false,"start_replayed":false,"packet_permissions_granted":false}),
    )
}
