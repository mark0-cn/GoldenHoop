//! Bind the independently checked provider addresses to the actual host port.
use super::*;
use goldenhoop_egress::{EndpointAddresses, SourceBindingReceipt};

pub(super) async fn call(
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
        Reply::Result(value) => Ok(value),
        Reply::Error(error) => Err(error),
    }
}
impl DockerDriver {
    /// Configure only the immutable source floor. This grants no packet lease
    /// or user execution, and the caller must keep the sandbox out of Ready.
    pub async fn bind_quarantined_source(
        &self,
        handle: &RuntimeHandle,
        network: &WorkloadNetworkPlan,
        session: &mut ControllerSession,
    ) -> Result<SourceBindingReceipt, ApiError> {
        network.validate()?;
        let controller = session.plan();
        controller.validate_dispatch_at(Utc::now())?;
        if controller.purpose != ControllerPurpose::Enforce
            || serde_json::to_value(&controller.native).map_err(|_| conflict())?
                != serde_json::to_value(&network.native).map_err(|_| conflict())?
            || network.native.identity.installation_id != self.config.installation_id
            || network.native.identity.profile != self.config.profile.id()
        {
            return Err(bootstrap_context("source controller identity", conflict()));
        }
        let endpoint = self.observe_quarantined_endpoint(handle, network).await?;
        let before = call(session, Request::Inspect {})
            .await
            .map_err(|e| bootstrap_context("source preflight readback", e))?;
        let revision = before["revision"].as_u64().ok_or_else(conflict)?;
        if before["installed"] != true
            || before["uncertain"] != false
            || before["ethernet_guarded"] != true
            || before["source_guarded"] != false
            || !before["source_binding_sha256"].is_null()
        {
            return Err(bootstrap_context("source preflight receipt", conflict()));
        }
        let mut attempt = ControllerAttempt {
            session,
            confirmed: false,
        };
        let session = &mut *attempt.session;
        let result = async {
            let value = call(
                session,
                Request::BindRuntimeSource {
                    expected_revision: revision,
                    addresses: EndpointAddresses {
                        mac: endpoint.mac,
                        ipv4: endpoint.ipv4,
                        ipv6: Some(endpoint.ipv6),
                    },
                },
            )
            .await?;
            let receipt: SourceBindingReceipt =
                serde_json::from_value(value).map_err(|_| conflict())?;
            let provider = DockerNetworkProvider::connect().await?;
            let native = provider
                .lookup(&network.provider_plan())
                .await?
                .ok_or_else(conflict)?;
            validate_receipt(network, &endpoint, &native, revision, &receipt)?;
            let after = self.observe_quarantined_endpoint(handle, network).await?;
            if serde_json::to_value(after).map_err(|_| conflict())?
                != serde_json::to_value(&endpoint).map_err(|_| conflict())?
            {
                return Err(conflict());
            }
            let state = call(session, Request::Inspect {}).await?;
            if state["uncertain"] != false
                || state["source_guarded"] != true
                || state["revision"].as_u64() != Some(revision)
                || state["source_binding_sha256"].as_str() != Some(receipt.source.digest().as_str())
            {
                return Err(conflict());
            }
            Ok(receipt)
        }
        .await;
        attempt.confirmed = result.is_ok();
        result.map_err(|e| bootstrap_context("source binding confirmation", e))
    }
}

pub(super) fn validate_receipt(
    network: &WorkloadNetworkPlan,
    endpoint: &WorkloadEndpoint,
    native: &NetworkObservation,
    revision: u64,
    receipt: &SourceBindingReceipt,
) -> Result<(), ApiError> {
    receipt.validate()?;
    if serde_json::to_value(&receipt.allocation).map_err(|_| conflict())?
        != serde_json::to_value(&network.native.allocation).map_err(|_| conflict())?
        || native.network_id != network.network_id
        || native.attached_endpoints != 1
        || receipt.revision != revision
        || receipt.source.endpoint.mac != endpoint.mac
        || receipt.source.endpoint.ipv4 != endpoint.ipv4
        || receipt.source.endpoint.ipv6 != Some(endpoint.ipv6)
        || receipt.source.gateway4 != native.ipv4_gateway
        || receipt.source.gateway6 != Some(native.ipv6_gateway)
    {
        return Err(conflict());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use goldenhoop_egress::{Endpoint, SourceScope};
    #[test]
    fn source_receipt_cannot_replace_the_frozen_allocation_endpoint_gateway_or_revision() {
        let (network, actual, native, observed) = super::super::tests::model();
        let endpoint = super::super::endpoint(
            &serde_json::from_value(actual).unwrap(),
            &serde_json::from_value(native).unwrap(),
            &network,
            &observed,
        )
        .unwrap();
        let receipt = SourceBindingReceipt {
            allocation: network.native.allocation.clone(),
            source: SourceScope {
                endpoint: Endpoint {
                    port: "veth42".into(),
                    ifindex: network.native.allocation.ifindex + 1,
                    mac: endpoint.mac,
                    ipv4: endpoint.ipv4,
                    ipv6: Some(endpoint.ipv6),
                },
                gateway_mac: "02:00:00:00:00:01".parse().unwrap(),
                gateway4: observed.ipv4_gateway,
                gateway6: Some(observed.ipv6_gateway),
            },
            revision: 2,
            observed_at: Utc::now(),
        };
        validate_receipt(&network, &endpoint, &observed, 2, &receipt).unwrap();
        for case in 0..6 {
            let mut wrong = receipt.clone();
            match case {
                0 => wrong.allocation.generation = Uuid::new_v4(),
                1 => wrong.allocation.ifindex += 1,
                2 => wrong.revision += 1,
                3 => wrong.source.endpoint.mac = "02:00:00:00:00:03".parse().unwrap(),
                4 => wrong.source.endpoint.ipv4 = "10.77.0.3".parse().unwrap(),
                _ => wrong.source.gateway4 = "10.77.0.4".parse().unwrap(),
            }
            assert!(
                validate_receipt(&network, &endpoint, &observed, 2, &wrong).is_err(),
                "case {case}"
            );
        }
    }
}
