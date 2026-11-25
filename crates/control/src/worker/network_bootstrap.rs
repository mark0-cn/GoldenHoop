//! First protected creation. A partial dispatched allocation is never replayed.
use super::*;
use goldenhoop_docker::{
    ControllerSession, DockerNetworkProvider, NetworkPlan, QuarantineProtection,
    WorkloadNetworkPlan,
};
use goldenhoop_egress::{
    controller::{Reply, Request},
    native::NativeBridgeObservation,
};
use goldenhoop_store::{NetworkBinding, NetworkCreateKind, NetworkOperatorPolicy};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

struct CreateJournal {
    store: Store,
    id: Uuid,
    generation: Uuid,
    kind: NetworkCreateKind,
    attempt: Mutex<Option<Uuid>>,
}
#[async_trait::async_trait]
impl goldenhoop_docker::ResourceCreateObserver for CreateJournal {
    async fn dispatched(&self, request_sha256: &str) -> Result<(), ApiError> {
        let mut attempt = self.attempt.lock().await;
        if attempt.is_some() {
            return Err(unavailable());
        }
        let dispatched = self
            .store
            .begin_network_create(self.id, self.generation, self.kind, request_sha256)
            .await?;
        *attempt = Some(dispatched.attempt);
        Ok(())
    }
    async fn settled(&self) -> Result<(), ApiError> {
        let attempt = self.attempt.lock().await.ok_or_else(unavailable)?;
        self.store
            .settle_network_create(self.id, self.kind, attempt, None)
            .await?;
        Ok(())
    }
}

#[derive(Default)]
pub struct NetworkSetup {
    pub controller_image: Option<String>,
    pub options: Option<NetworkOptions>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkOptions {
    pub upstream: SocketAddr,
    #[serde(default)]
    pub operator: NetworkOperatorPolicy,
    #[serde(default)]
    pub private_exceptions: Vec<String>,
    #[serde(default)]
    pub control_addresses: Vec<IpAddr>,
}
impl NetworkOptions {
    pub(super) fn validate(&self) -> Result<(), ApiError> {
        goldenhoop_egress::dns::Upstream::new(self.upstream)?;
        goldenhoop_egress::ProtectedDestinations::new(goldenhoop_egress::DestinationScope {
            host_addresses: vec![],
            private_exceptions: self.private_exceptions.clone(),
            control_addresses: self.control_addresses.clone(),
        })?;
        Ok(())
    }
}

fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "protected network bootstrap is unconfirmed",
    )
}
async fn call(
    session: &mut ControllerSession,
    request: Request,
) -> Result<serde_json::Value, ApiError> {
    match session
        .call(
            request,
            tokio::time::Instant::now() + Duration::from_secs(10),
        )
        .await
        .map_err(|_| unavailable())?
    {
        Reply::Result(value) => Ok(value),
        Reply::Error(error) => Err(error),
    }
}
impl Worker {
    async fn admit_bootstrap(&self, id: Uuid) -> Result<(), ApiError> {
        if self.store.effective_desired(id).await? != DesiredState::Running
            || self.store.worker().await?.id != self.registration.id
        {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(super) async fn bootstrap_network(
        &self,
        mut stored: StoredSandbox,
        driver: &DockerDriver,
    ) -> Result<(), ApiError> {
        let id = stored.sandbox.id;
        let options = self.network_options.as_ref().ok_or_else(unavailable)?;
        let image = self
            .network_controller_image
            .as_deref()
            .ok_or_else(unavailable)?;
        self.admit_bootstrap(id).await?;
        // Validate the full host request before reserving or creating anything.
        // User policy belongs to the protected host compiler. The native
        // container request carries workload limits, not that host capability.
        let mut native_request = self.runtime_request(&stored)?;
        native_request
            .required_capabilities
            .remove(&Capability::NetworkPolicy);
        native_request.network = NetworkPolicy::default();
        self.store.resolved_network_policy(id).await?;
        let reserved = self.store.reserve_network(id, Uuid::new_v4()).await?;
        let network = self
            .store
            .begin_network_provisioning(id, reserved.generation, reserved.revision)
            .await?;
        let plan = NetworkPlan {
            identity: network.identity(),
            provisioning_token: network.token.ok_or_else(unavailable)?,
            expires_at: stored.sandbox.expires_at,
        };
        self.admit_bootstrap(id).await?;
        let bridge_journal = CreateJournal {
            store: self.store.clone(),
            id,
            generation: network.generation,
            kind: NetworkCreateKind::Bridge,
            attempt: Mutex::new(None),
        };
        DockerNetworkProvider::connect()
            .await?
            .create_fresh_observed(&plan, &bridge_journal)
            .await?;
        let (binding, _, _) =
            crate::host_process::discover_native(&self.store, id, Uuid::new_v4(), image).await?;
        let controller = self
            .store
            .reserve_network_controller(id, network.generation, Uuid::new_v4(), image)
            .await?;
        let started = crate::host_process::start_controller(&self.store, &controller).await;
        let (controller, mut session) = match started {
            Ok(value) => value,
            Err(error) => {
                let fresh = self
                    .store
                    .network_controller(id, controller.controller_generation)
                    .await?;
                crate::host_process::collect(&self.store, fresh).await?;
                return Err(error);
            }
        };
        let result = async {
            let native_plan = controller.plan.controller()?.native.clone();
            let alias: NativeBridgeObservation = serde_json::from_value(
                call(
                    &mut session,
                    Request::BindNative {
                        plan: native_plan.clone(),
                    },
                )
                .await?,
            )
            .map_err(|_| unavailable())?;
            if alias.allocation.owner() != binding.allocation.owner()
                || alias.alias != binding.allocation.owner()
                || alias.provisioning_token != plan.provisioning_token
                || alias.identity_sha256 != plan.identity.digest()
            {
                return Err(unavailable());
            }
            let opened = call(
                &mut session,
                Request::Open {
                    allocation: binding.allocation.clone(),
                },
            )
            .await?;
            if opened["installed"] != false
                || !opened["revision"].is_null()
                || opened["uncertain"] != false
            {
                return Err(unavailable());
            }
            let installed = call(&mut session, Request::Install {}).await?;
            if installed["installed"] != true
                || installed["revision"] != 0
                || installed["uncertain"] != false
            {
                return Err(unavailable());
            }
            call(
                &mut session,
                Request::EnableEthernet {
                    expected_revision: 0,
                },
            )
            .await?;
            self.admit_bootstrap(id).await?;
            let runtime_network = WorkloadNetworkPlan {
                native: native_plan,
                network_id: binding.network_id.clone(),
            };
            stored = self
                .save(stored, SandboxState::Starting, CleanupState::Pending, None)
                .await?;
            self.store
                .finish_operations(id, "create", OperationState::Running, None)
                .await?;
            let journal = CreateJournal {
                store: self.store.clone(),
                id,
                generation: network.generation,
                kind: NetworkCreateKind::Workload,
                attempt: Mutex::new(None),
            };
            let handle = driver
                .prepare_quarantined_observed(
                    &stored.sandbox,
                    &native_request,
                    &runtime_network,
                    &mut session,
                    &journal,
                )
                .await?;
            // The physical identity is durable before the only start dispatch.
            stored.handle = Some(handle.clone());
            self.store.observe(stored.clone()).await?;
            self.admit_bootstrap(id).await?;
            driver
                .start_quarantined(&handle, &runtime_network, &mut session)
                .await?;
            let source = driver
                .bind_quarantined_source(&handle, &runtime_network, &mut session)
                .await?;
            let protection = QuarantineProtection {
                upstream: options.upstream,
                private_exceptions: options.private_exceptions.clone(),
                control_addresses: options.control_addresses.clone(),
            };
            let protected = driver
                .protect_quarantined_network(
                    &handle,
                    &runtime_network,
                    &mut session,
                    &source,
                    &protection,
                )
                .await?;
            self.store
                .bind_network(
                    id,
                    network.generation,
                    plan.provisioning_token,
                    NetworkBinding {
                        network_id: binding.network_id,
                        allocation: protected.allocation.clone(),
                        source: protected.source.clone(),
                        destinations: protected.destinations.clone(),
                    },
                )
                .await?;
            self.store
                .stage_public_network_policy(id, network.generation, protected, options.upstream)
                .await?;
            Ok::<_, ApiError>(())
        }
        .await;
        // Closing a transport is not collection. The old epoch must be
        // positively absent before the held actor may create its fresh epoch.
        let _ = session.close().await;
        let fresh = self
            .store
            .network_controller(id, controller.controller_generation)
            .await?;
        crate::host_process::collect(&self.store, fresh).await?;
        result
    }

    pub(super) async fn settle_create_dispatches(
        &self,
        stored: &StoredSandbox,
        driver: &DockerDriver,
    ) -> Result<(), ApiError> {
        let id = stored.sandbox.id;
        let bridge = self
            .store
            .network_create_dispatch(id, NetworkCreateKind::Bridge)
            .await?;
        let workload = self
            .store
            .network_create_dispatch(id, NetworkCreateKind::Workload)
            .await?;
        if bridge.as_ref().is_none_or(|r| r.settled_at.is_some())
            && workload.as_ref().is_none_or(|r| r.settled_at.is_some())
        {
            return Ok(());
        }
        let network = self.store.network_allocation(id).await?;
        let token = self
            .store
            .network_allocation_history(id, None, 128)
            .await?
            .into_iter()
            .find(|row| row.phase == goldenhoop_store::NetworkPhase::Provisioning)
            .and_then(|row| row.token)
            .ok_or_else(unavailable)?;
        let provider_plan = NetworkPlan {
            identity: network.identity(),
            provisioning_token: token,
            expires_at: stored.sandbox.expires_at,
        };
        if let Some(bridge) = bridge
            && bridge.settled_at.is_none()
        {
            if bridge.request_sha256 != provider_plan.fingerprint()? {
                return Err(unavailable());
            }
            let actual = DockerNetworkProvider::connect()
                .await?
                .lookup(&provider_plan)
                .await?
                .ok_or_else(unavailable)?;
            self.store
                .settle_network_create(
                    id,
                    NetworkCreateKind::Bridge,
                    bridge.attempt,
                    Some(&actual.network_id),
                )
                .await?;
        }
        let Some(dispatch) = workload.filter(|r| r.settled_at.is_none()) else {
            return Ok(());
        };
        let handle = stored.handle.as_ref().ok_or_else(unavailable)?;
        let native = network.native_binding().ok_or_else(unavailable)?;
        let plan = WorkloadNetworkPlan {
            native: goldenhoop_egress::native::NativeBridgePlan {
                identity: network.identity(),
                allocation: native.allocation,
                provisioning_token: token,
                expires_at: stored.sandbox.expires_at,
            },
            network_id: native.network_id,
        };
        driver
            .validate_recovered_network_create(handle, &plan, &dispatch.request_sha256)
            .await?;
        self.store
            .settle_network_create(
                id,
                NetworkCreateKind::Workload,
                dispatch.attempt,
                Some(&handle.backend_ref),
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn administrator_network_configuration_is_bounded_typed_and_distinct_from_user_policy() {
        let valid: NetworkOptions =
            serde_json::from_value(serde_json::json!({"upstream":"8.8.8.8:53"})).unwrap();
        valid.validate().unwrap();
        assert!(
            serde_json::from_value::<NetworkOptions>(
                serde_json::json!({"upstream":"8.8.8.8:53","policy":{"default_action":"allow"}})
            )
            .is_err()
        );
        for value in [
            serde_json::json!({"upstream":"0.0.0.0:53"}),
            serde_json::json!({"upstream":"8.8.8.8:0"}),
            serde_json::json!({"upstream":"8.8.8.8:53","private_exceptions":["127.0.0.0/8"]}),
            serde_json::json!({"upstream":"8.8.8.8:53","private_exceptions":["0.0.0.0/0"]}),
        ] {
            let options: NetworkOptions = serde_json::from_value(value).unwrap();
            assert!(options.validate().is_err());
        }
    }
}
