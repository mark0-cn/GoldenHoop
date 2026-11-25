//! Trusted-agent bootstrap on a journal-bound quarantined network.
//! Returning a handle or endpoint does not publish workload readiness.
use super::*;
use goldenhoop_egress::{
    ControllerPurpose, Mac,
    controller::{Reply, Request},
    native::NativeBridgePlan,
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
mod protection;
mod source;
pub use protection::QuarantineProtection;
#[cfg(test)]
mod tests;

pub(super) const NETWORK_PLAN_LABEL: &str = "dev.goldenhoop.workload-network-plan";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadNetworkPlan {
    pub native: NativeBridgePlan,
    pub network_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadEndpoint {
    pub container_id: String,
    pub endpoint_id: String,
    pub mac: Mac,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}
// Cancellation after a mutation must fence the session while confirmation
// remains incomplete. Closing it does not attest process or kernel absence.
struct ControllerAttempt<'a> {
    session: &'a mut ControllerSession,
    confirmed: bool,
}
impl Drop for ControllerAttempt<'_> {
    fn drop(&mut self) {
        if !self.confirmed {
            self.session.fence();
        }
    }
}
fn conflict() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "owned workload network bootstrap is unconfirmed",
    )
}
fn physical_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl WorkloadNetworkPlan {
    pub fn validate(&self) -> Result<(), ApiError> {
        self.native.validate()?;
        if !physical_id(&self.network_id) {
            return Err(conflict());
        }
        Ok(())
    }
    fn provider_plan(&self) -> NetworkPlan {
        NetworkPlan {
            identity: self.native.identity.clone(),
            provisioning_token: self.native.provisioning_token,
            expires_at: self.native.expires_at,
        }
    }
}
pub(super) fn match_requested_plan(
    actual: &ContainerInspectResponse,
    expected: Option<&WorkloadNetworkPlan>,
) -> Result<(), ApiError> {
    let raw = actual
        .config
        .as_ref()
        .and_then(|c| c.labels.as_ref())
        .and_then(|l| l.get(NETWORK_PLAN_LABEL));
    let wanted = expected
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| conflict())?;
    if raw != wanted.as_ref() {
        return Err(conflict());
    }
    Ok(())
}
impl DockerDriver {
    async fn quarantine_for_bootstrap(
        &self,
        network: &WorkloadNetworkPlan,
        session: &mut ControllerSession,
    ) -> Result<(), ApiError> {
        network.validate()?;
        let controller = session.plan();
        controller.validate_dispatch_at(Utc::now())?;
        if controller.purpose != ControllerPurpose::Enforce
            || serde_json::to_value(&controller.native).map_err(|_| conflict())?
                != serde_json::to_value(&network.native).map_err(|_| conflict())?
            || network.native.identity.installation_id != self.config.installation_id
            || network.native.identity.profile != self.config.profile.id()
        {
            return Err(conflict());
        }
        let provider = DockerNetworkProvider::connect().await?;
        let observed = provider
            .lookup(&network.provider_plan())
            .await?
            .ok_or_else(conflict)?;
        if observed.network_id != network.network_id || observed.attached_endpoints != 0 {
            return Err(conflict());
        }
        async fn call(
            session: &mut ControllerSession,
            request: Request,
        ) -> Result<serde_json::Value, ApiError> {
            match session
                .call(
                    request,
                    tokio::time::Instant::now() + Duration::from_secs(5),
                )
                .await
                .map_err(|_| conflict())?
            {
                Reply::Result(v) => Ok(v),
                Reply::Error(e) => Err(e),
            }
        }
        let before = call(session, Request::Inspect {}).await?;
        let revision = before["revision"].as_u64().ok_or_else(conflict)?;
        if before["installed"] != true
            || before["uncertain"] != false
            || before["ethernet_guarded"] != true
        {
            return Err(conflict());
        }
        // Rewrite a known deny policy and wait for the actual kernel readback.
        // Reading an old revision or accepting a caller-supplied receipt is insufficient.
        let denied = call(
            session,
            Request::Quarantine {
                expected_revision: revision,
            },
        )
        .await?;
        if denied["installed"] != true
            || denied["uncertain"] != false
            || denied["ethernet_guarded"] != true
            || denied["revision"].as_u64() != revision.checked_add(1)
            || denied["table_sha256"]
                .as_str()
                .is_none_or(|s| !physical_id(s))
            || denied["ethernet_sha256"]
                .as_str()
                .is_none_or(|s| !physical_id(s))
        {
            return Err(conflict());
        }
        Ok(())
    }

    /// Create only. The trusted agent is not started, and no user execution is permitted.
    /// The caller must persist its intent/plan before invoking this external write.
    pub async fn prepare_quarantined(
        &self,
        sandbox: &Sandbox,
        request: &CreateSandbox,
        network: &WorkloadNetworkPlan,
        session: &mut ControllerSession,
    ) -> Result<RuntimeHandle, ApiError> {
        validate_create(&*self.profile.read().await, request)?;
        if sandbox.profile != request.profile
            || sandbox.image != request.image
            || sandbox.resources != request.resources
            || expired(sandbox, Utc::now())
            || !valid_deadline(sandbox.created_at, sandbox.expires_at, request.ttl_seconds)
            || sandbox.id != network.native.identity.sandbox_id
            || sandbox.expires_at != network.native.expires_at
        {
            return Err(conflict());
        }
        self.quarantine_for_bootstrap(network, session).await?;
        self.prepare_runtime(sandbox, request, Some(network)).await
    }

    /// Start only the fixed trusted supervisor under a freshly confirmed deny floor.
    /// This is not workload Ready; source/DNS/destination enforcement must follow.
    pub async fn start_quarantined(
        &self,
        handle: &RuntimeHandle,
        network: &WorkloadNetworkPlan,
        session: &mut ControllerSession,
    ) -> Result<WorkloadEndpoint, ApiError> {
        network.validate()?;
        if handle.sandbox_id != network.native.identity.sandbox_id {
            return Err(conflict());
        }
        let actual = self.owned(handle).await?.ok_or_else(conflict)?;
        match_requested_plan(&actual, Some(network))?;
        admit_placement(&actual, network, self.config.profile.runtime())?;
        if actual.state.as_ref().and_then(|s| s.status) != Some(ContainerStateStatusEnum::CREATED) {
            return Err(conflict());
        }
        self.quarantine_for_bootstrap(network, session).await?;
        self.start_prepared(handle).await?;
        let endpoint = self.observe_quarantined_endpoint(handle, network).await;
        if endpoint.is_err() {
            self.remove(handle).await?;
        }
        endpoint
    }

    /// Cross-check the sole endpoint in actual container and owned-network inspections.
    pub async fn observe_quarantined_endpoint(
        &self,
        handle: &RuntimeHandle,
        network: &WorkloadNetworkPlan,
    ) -> Result<WorkloadEndpoint, ApiError> {
        network.validate()?;
        if handle.sandbox_id != network.native.identity.sandbox_id {
            return Err(conflict());
        }
        let actual = self.owned(handle).await?.ok_or_else(conflict)?;
        match_requested_plan(&actual, Some(network))?;
        admit_placement(&actual, network, self.config.profile.runtime())?;
        if actual.state.as_ref().and_then(|s| s.running) != Some(true) {
            return Err(conflict());
        }
        let provider = DockerNetworkProvider::connect().await?;
        let observed = provider
            .lookup(&network.provider_plan())
            .await?
            .ok_or_else(conflict)?;
        if observed.network_id != network.network_id || observed.attached_endpoints != 1 {
            return Err(conflict());
        }
        let native = self
            .docker
            .inspect_network(&network.network_id, None)
            .await
            .map_err(backend)?;
        endpoint(&actual, &native, network, &observed)
    }
}

fn admit_placement(
    actual: &ContainerInspectResponse,
    network: &WorkloadNetworkPlan,
    runtime: &str,
) -> Result<(), ApiError> {
    let config = actual.config.as_ref().ok_or_else(conflict)?;
    let host = actual.host_config.as_ref().ok_or_else(conflict)?;
    if host.network_mode.as_deref() != Some(&network.network_id)
        || host.runtime.as_deref() != Some(runtime)
        || host.privileged != Some(false)
        || host.readonly_rootfs != Some(true)
        || host.cap_drop.as_ref().is_none_or(|v| v != &["ALL"])
        || config
            .entrypoint
            .as_ref()
            .is_none_or(|v| v != &[AGENT_PATH, "serve"])
        || config
            .healthcheck
            .as_ref()
            .and_then(|h| h.test.as_ref())
            .is_none_or(|v| v != &["NONE"])
        || config.cmd.as_ref().is_some_and(|v| !v.is_empty())
        || config.user.as_deref() != Some("0:0")
        || host.cap_add.as_ref().is_none_or(|v| {
            v.len() != 6
                || v.iter().map(String::as_str).collect::<BTreeSet<_>>()
                    != BTreeSet::from([
                        "SETUID",
                        "SETGID",
                        "KILL",
                        "CHOWN",
                        "FOWNER",
                        "DAC_OVERRIDE",
                    ])
        })
        || host
            .security_opt
            .as_ref()
            .is_none_or(|v| v != &["no-new-privileges"])
        || host.binds.as_ref().is_some_and(|v| !v.is_empty())
        || host.pid_mode.as_ref().is_some_and(|v| !v.is_empty())
        || host.ipc_mode.as_deref() != Some("private")
        || host.devices.as_ref().is_some_and(|v| !v.is_empty())
        || host.device_requests.as_ref().is_some_and(|v| !v.is_empty())
        || actual.mounts.as_ref().is_none_or(|v| {
            v.len() != 1
                || v[0].typ.as_deref() != Some("volume")
                || v[0].destination.as_deref() != Some("/opt/goldenhoop")
                || v[0].rw != Some(false)
        })
    {
        return Err(conflict());
    }
    Ok(())
}

fn endpoint(
    actual: &ContainerInspectResponse,
    native: &NetworkInspect,
    network: &WorkloadNetworkPlan,
    observed: &NetworkObservation,
) -> Result<WorkloadEndpoint, ApiError> {
    let id = actual
        .id
        .as_deref()
        .filter(|s| physical_id(s))
        .ok_or_else(conflict)?;
    let settings = actual
        .network_settings
        .as_ref()
        .and_then(|n| n.networks.as_ref())
        .filter(|n| n.len() == 1)
        .ok_or_else(conflict)?;
    let link = settings
        .get(&network.native.identity.network_name())
        .ok_or_else(conflict)?;
    let endpoint_id = link
        .endpoint_id
        .as_deref()
        .filter(|s| physical_id(s))
        .ok_or_else(conflict)?;
    let mac: Mac = link.mac_address.as_deref().ok_or_else(conflict)?.parse()?;
    let ipv4: Ipv4Addr = link
        .ip_address
        .as_deref()
        .ok_or_else(conflict)?
        .parse()
        .map_err(|_| conflict())?;
    let ipv6: Ipv6Addr = link
        .global_ipv6_address
        .as_deref()
        .ok_or_else(conflict)?
        .parse()
        .map_err(|_| conflict())?;
    let net4: ipnet::Ipv4Net = observed.ipv4_subnet.parse().map_err(|_| conflict())?;
    let net6: ipnet::Ipv6Net = observed.ipv6_subnet.parse().map_err(|_| conflict())?;
    if link.network_id.as_deref() != Some(&network.network_id)
        || link.ip_prefix_len != Some(i64::from(net4.prefix_len()))
        || link.global_ipv6_prefix_len != Some(i64::from(net6.prefix_len()))
        || !net4.contains(&ipv4)
        || ipv4 == net4.network()
        || ipv4 == net4.broadcast()
        || ipv4 == observed.ipv4_gateway
        || !net6.contains(&ipv6)
        || ipv6 == net6.network()
        || ipv6 == observed.ipv6_gateway
        || link.gateway.as_deref() != Some(&observed.ipv4_gateway.to_string())
        || link.ipv6_gateway.as_deref() != Some(&observed.ipv6_gateway.to_string())
        || native.id.as_deref() != Some(&network.network_id)
    {
        return Err(conflict());
    }
    let peers = native
        .containers
        .as_ref()
        .filter(|c| c.len() == 1)
        .ok_or_else(conflict)?;
    let peer = peers.get(id).ok_or_else(conflict)?;
    if peer.endpoint_id.as_deref() != Some(endpoint_id)
        || peer.mac_address.as_deref() != Some(&mac.to_string())
        || peer.ipv4_address.as_deref() != Some(&format!("{ipv4}/{}", net4.prefix_len()))
        || peer.ipv6_address.as_deref() != Some(&format!("{ipv6}/{}", net6.prefix_len()))
    {
        return Err(conflict());
    }
    Ok(WorkloadEndpoint {
        container_id: id.into(),
        endpoint_id: endpoint_id.into(),
        mac,
        ipv4,
        ipv6,
    })
}
