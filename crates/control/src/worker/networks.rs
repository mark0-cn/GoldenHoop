//! Owned network recovery/collection. No public network capability is published.
use super::*;
use goldenhoop_docker::{DockerControllerProvider, DockerNetworkProvider, NetworkPlan};
use goldenhoop_egress::{
    CollectionReceipt,
    controller::{Reply, Request},
};
use goldenhoop_store::{NetworkAbsence, NetworkController, NetworkPhase};
use serde_json::Value;

fn unknown() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "owned network recovery is not confirmed",
    )
}
impl Worker {
    async fn collect_pre_native(
        &self,
        stored: &StoredSandbox,
        network: &goldenhoop_store::NetworkAllocation,
        image: &str,
    ) -> Result<(), ApiError> {
        use goldenhoop_egress::{HostProcessPlan, ProbeObservation, ProbePurpose};
        let id = stored.sandbox.id;
        let history = self.store.network_allocation_history(id, None, 128).await?;
        let dispatched = history
            .iter()
            .find(|r| r.phase == NetworkPhase::Provisioning);
        let original_token = dispatched
            .map(|v| v.token.ok_or_else(unknown))
            .transpose()?;
        let processes = self.store.network_controllers(id).await?;
        if processes
            .iter()
            .any(|p| matches!(p.plan, HostProcessPlan::Controller(_)))
        {
            return Err(unknown());
        }
        let mut known = network
            .network_id
            .iter()
            .cloned()
            .chain(processes.iter().filter_map(|p| p.network_id.clone()))
            .collect::<std::collections::BTreeSet<_>>();
        if known.len() > 1 {
            return Err(unknown());
        }
        let provider = DockerNetworkProvider::connect().await?;
        let plan = original_token.map(|provisioning_token| NetworkPlan {
            identity: network.identity(),
            provisioning_token,
            expires_at: stored.sandbox.expires_at,
        });
        if let Some(plan) = &plan {
            if let Some(actual) = provider.lookup(plan).await? {
                if actual.attached_endpoints != 0
                    || known
                        .iter()
                        .next()
                        .is_some_and(|id| id != &actual.network_id)
                {
                    return Err(unknown());
                }
                known.insert(actual.network_id);
            } else if known.is_empty() {
                return Err(unknown());
            }
        } else if !known.is_empty() || !provider.reserved_name_absent(&network.identity()).await? {
            return Err(unknown());
        }
        let network_id = known.iter().next().map(String::as_str);
        // Record known provider identity before removal, including a crash
        // between that removal and dispatch of the read-only absence probe.
        let reserved = self
            .store
            .reserve_network_probe(
                id,
                network.generation,
                Uuid::new_v4(),
                image,
                ProbePurpose::ObserveAbsence,
                network_id,
            )
            .await?;
        if let Some(plan) = &plan
            && !provider
                .remove_empty(plan, network_id)
                .await?
                .provider_absent
        {
            return Err(unknown());
        }
        let (observed, _) = crate::host_process::run_probe(&self.store, &reserved).await?;
        let ProbeObservation::Absence(receipt) = observed else {
            return Err(unknown());
        };
        if !receipt.bridge_absent || !receipt.owned_tables_absent {
            return Err(unknown());
        }
        if let Some(plan) = &plan {
            if provider.lookup(plan).await?.is_some() {
                return Err(unknown());
            }
        } else if !provider.reserved_name_absent(&network.identity()).await? {
            return Err(unknown());
        }
        self.store
            .confirm_network_absence(
                id,
                network.generation,
                network.token.ok_or_else(unknown)?,
                NetworkAbsence {
                    provisioning_settled: true,
                    endpoints_absent: true,
                    network_absent: true,
                    bridge_absent: true,
                    owned_tables_absent: true,
                    observed_at: receipt.observed_at,
                },
            )
            .await?;
        Ok(())
    }
    async fn settle_controller(&self, record: NetworkController) -> Result<(), ApiError> {
        crate::host_process::collect(&self.store, record).await?;
        Ok(())
    }
    pub(super) async fn collect_network(&self, stored: &StoredSandbox) -> Result<(), ApiError> {
        let id = stored.sandbox.id;
        let mut network = match self.store.network_allocation(id).await {
            Ok(value) => value,
            Err(error) if error.code == ErrorCode::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if network.phase == NetworkPhase::Collected {
            return Ok(());
        }
        self.store.require_network_creates_settled(id).await?;
        if network.phase != NetworkPhase::Collecting {
            network = self
                .store
                .begin_network_collection(id, network.generation, network.revision)
                .await?;
        }
        let image = self.network_controller_image.as_deref().ok_or_else(|| {
            ApiError::new(
                ErrorCode::UnsupportedCapability,
                "configure a pinned egress controller image to collect owned networks",
            )
        })?;
        if let Some(active) = self.store.active_network_controller(id).await? {
            self.settle_controller(active).await?;
        }
        let Some(native) = network.native_binding() else {
            return self.collect_pre_native(stored, &network, image).await;
        };
        let token = self
            .store
            .network_allocation_history(id, None, 128)
            .await?
            .into_iter()
            .find(|r| r.phase == NetworkPhase::Provisioning)
            .and_then(|r| r.token)
            .ok_or_else(unknown)?;
        let plan = NetworkPlan {
            identity: network.identity(),
            provisioning_token: token,
            expires_at: stored.sandbox.expires_at,
        };
        let provider = DockerNetworkProvider::connect().await?;
        let removed = provider
            .remove_empty(&plan, Some(&native.network_id))
            .await?;
        if !removed.provider_absent {
            return Err(unknown());
        }
        let reserved = self
            .store
            .reserve_network_collector(id, network.generation, Uuid::new_v4(), image)
            .await?;
        let creating = self
            .store
            .begin_controller_create(id, reserved.controller_generation, reserved.revision)
            .await?;
        let controllers = DockerControllerProvider::connect(image).await?;
        let actual = controllers
            .create_fresh(creating.plan.controller()?)
            .await?;
        let created = self
            .store
            .record_controller_created(
                id,
                creating.controller_generation,
                creating.create_token.ok_or_else(unknown)?,
                &actual.container_id,
            )
            .await?;
        let starting = self
            .store
            .begin_controller_start(id, created.controller_generation, created.revision)
            .await?;
        let mut session = controllers
            .start_created(starting.plan.controller()?, &actual.container_id)
            .await?;
        let running = self
            .store
            .record_controller_running(
                id,
                starting.controller_generation,
                starting.start_token.ok_or_else(unknown)?,
                &actual.container_id,
            )
            .await?;
        async fn call(
            session: &mut goldenhoop_docker::ControllerSession,
            request: Request,
        ) -> Result<Value, ApiError> {
            match session
                .call(
                    request,
                    tokio::time::Instant::now() + Duration::from_secs(10),
                )
                .await
                .map_err(|_| unknown())?
            {
                Reply::Result(value) => Ok(value),
                Reply::Error(error) => Err(error),
            }
        }
        let receipt = async {
            let state = call(
                &mut session,
                Request::Open {
                    allocation: native.allocation.clone(),
                },
            )
            .await?;
            let revision = if state["installed"] == true {
                state["revision"].as_u64().ok_or_else(unknown)?
            } else if state["installed"] == false && state["revision"].is_null() {
                0
            } else {
                return Err(unknown());
            };
            let value = call(
                &mut session,
                Request::Remove {
                    expected_revision: revision,
                },
            )
            .await?;
            let receipt: CollectionReceipt =
                serde_json::from_value(value).map_err(|_| unknown())?;
            if receipt.allocation.owner() != native.allocation.owner()
                || !receipt.bridge_absent
                || !receipt.owned_tables_absent
            {
                return Err(unknown());
            }
            Ok::<_, ApiError>(receipt)
        }
        .await;
        let exited = session.close().await;
        self.settle_controller(running).await?;
        exited?;
        let receipt = receipt?;
        if provider.lookup(&plan).await?.is_some() {
            return Err(unknown());
        }
        self.store
            .confirm_network_absence(
                id,
                network.generation,
                network.token.ok_or_else(unknown)?,
                NetworkAbsence {
                    provisioning_settled: true,
                    endpoints_absent: true,
                    network_absent: true,
                    bridge_absent: receipt.bridge_absent,
                    owned_tables_absent: receipt.owned_tables_absent,
                    observed_at: receipt.observed_at,
                },
            )
            .await?;
        Ok(())
    }
}
