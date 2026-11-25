//! Owned network recovery/collection. No public network capability is published.
use super::*;
use goldenhoop_docker::{DockerControllerProvider, DockerNetworkProvider, NetworkPlan};
use goldenhoop_egress::{
    CollectionReceipt,
    controller::{Reply, Request},
};
use goldenhoop_store::{ControllerAbsence, NetworkAbsence, NetworkController, NetworkPhase};
use serde_json::Value;

fn unknown() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "owned network recovery is not confirmed",
    )
}
impl Worker {
    async fn settle_controller(&self, mut record: NetworkController) -> Result<(), ApiError> {
        let provider = DockerControllerProvider::connect(&record.plan.image_id).await?;
        record = self
            .store
            .begin_controller_collection(
                record.sandbox_id,
                record.controller_generation,
                record.revision,
            )
            .await?;
        let observed = provider.lookup(&record.plan).await?;
        if record.container_id.is_none() {
            if let Some(observed) = observed {
                record = self
                    .store
                    .record_controller_created(
                        record.sandbox_id,
                        record.controller_generation,
                        record.create_token.ok_or_else(unknown)?,
                        &observed.container_id,
                    )
                    .await?;
            } else if record.create_token.is_some() {
                return Err(unknown());
            }
        }
        let absent = if let Some(id) = &record.container_id {
            provider.collect(&record.plan, id).await?.provider_absent
        } else {
            true
        };
        self.store
            .confirm_controller_absence(
                record.sandbox_id,
                record.controller_generation,
                record.collection_token.ok_or_else(unknown)?,
                ControllerAbsence {
                    container_id: record.container_id.clone(),
                    creation_settled: true,
                    start_settled: true,
                    provider_absent: absent,
                    observed_at: Utc::now(),
                },
            )
            .await?;
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
        let native = network.native_binding().ok_or_else(unknown)?;
        if let Some(active) = self.store.active_network_controller(id).await? {
            self.settle_controller(active).await?;
        }
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
        let actual = controllers.create_fresh(&creating.plan).await?;
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
            .start_created(&starting.plan, &actual.container_id)
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
