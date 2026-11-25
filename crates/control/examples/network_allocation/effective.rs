//! Actual held-session policy transitions; no workload Ready or user commands.
use super::*;
use goldenhoop_docker::{ControllerSession, WorkloadNetworkPlan};
use goldenhoop_egress::{Config, ProtectedBindingReceipt};
use goldenhoop_runtime::RuntimeHandle;

pub(super) async fn run(
    driver: &DockerDriver,
    handle: &RuntimeHandle,
    network: &WorkloadNetworkPlan,
    session: &mut ControllerSession,
    frozen: &ProtectedBindingReceipt,
) -> Result<Value, ApiError> {
    let config:Config=serde_json::from_value(json!({"policies":[{"default_action":"deny","rules":[{"destination":"93.184.216.34","ports":[443],"action":"allow"}]}],"tcp_cap":[443]})).map_err(|_|invalid())?;
    let applied = driver
        .apply_protected_policy(handle, network, session, frozen, &config)
        .await?;
    applied.receipt().validate_config(&config)?;
    require(
        applied.receipt().binding.revision == frozen.revision + 1 && !applied.remaining().is_zero(),
    )?;
    require(
        driver
            .apply_protected_policy(handle, network, session, frozen, &config)
            .await
            .is_err()
            && !session.is_uncertain(),
    )?;
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    let renewed = driver
        .renew_protected_policy(handle, network, session, &applied)
        .await?;
    require(
        renewed.receipt().binding.revision == applied.receipt().binding.revision
            && renewed.receipt().config_sha256 == applied.receipt().config_sha256
            && !renewed.remaining().is_zero(),
    )?;
    let deny: Config =
        serde_json::from_value(json!({"policies":[{"default_action":"deny","rules":[]}]}))
            .map_err(|_| invalid())?;
    let replaced = driver
        .replace_protected_policy(handle, network, session, &renewed, &deny)
        .await?;
    replaced.receipt().validate_config(&deny)?;
    require(
        replaced.receipt().binding.revision == renewed.receipt().binding.revision + 1
            && replaced.receipt().config_sha256 != renewed.receipt().config_sha256,
    )?;
    // No concurrent trusted renewer exists in this private producer. Require
    // actual kernel expiry, not merely a local receipt's conservative deadline.
    tokio::time::sleep(std::time::Duration::from_secs(
        u64::from(goldenhoop_egress::LEASE_SECONDS) + 1,
    ))
    .await;
    require(
        replaced.remaining().is_zero()
            && driver
                .renew_protected_policy(handle, network, session, &replaced)
                .await
                .is_err()
            && !session.is_uncertain(),
    )?;
    let expired = controller_call(
        session,
        ControllerRequest::Renew {
            expected_revision: replaced.receipt().binding.revision,
        },
    )
    .await
    .unwrap_err();
    require(expired.code == ErrorCode::Conflict)?;
    let uncertain = controller_call(session, ControllerRequest::Inspect {}).await?;
    require(uncertain["uncertain"] == true)?;
    controller_call(
        session,
        ControllerRequest::Quarantine {
            expected_revision: replaced.receipt().binding.revision,
        },
    )
    .await?;
    let revision = replaced.receipt().binding.revision + 1;
    let quarantine: ProtectedBindingReceipt = serde_json::from_value(
        controller_call(
            session,
            ControllerRequest::InspectBinding {
                expected_revision: revision,
            },
        )
        .await?,
    )
    .map_err(|_| invalid())?;
    quarantine.validate()?;
    require(
        quarantine.source == frozen.source
            && quarantine.destinations == frozen.destinations
            && quarantine.expires_at == frozen.expires_at,
    )?;
    let refused = controller_call(
        session,
        ControllerRequest::InspectPolicy {
            expected_revision: revision,
        },
    )
    .await
    .unwrap_err();
    require(refused.code == ErrorCode::InvalidState)?;
    Ok(
        json!({"initial_config":config,"tightened_config":deny,"applied":applied.receipt(),"renewed":renewed.receipt(),"replaced":replaced.receipt(),"duplicate_apply_refused":true,"expired_driver_renew_refused_before_dispatch":true,"actual_expired_kernel_renewal":expired,"actual_expired_observation":uncertain,"final_quarantine":quarantine,"quarantine_cannot_issue_effective_receipt":true,"workload_ready":false,"user_execution_dispatched":false}),
    )
}
