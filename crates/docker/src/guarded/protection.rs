//! Compose DNS sockets and destination isolation while no lease is granted.
use super::*;
use goldenhoop_egress::{
    DestinationDefinition, DestinationListener, DestinationScope, ProtectedBindingReceipt,
    SourceBindingReceipt,
};
use source::call;

/// Administrator-owned resolver and destination intent, never workload input.
pub struct QuarantineProtection {
    pub upstream: std::net::SocketAddr,
    pub private_exceptions: Vec<String>,
    pub control_addresses: Vec<std::net::IpAddr>,
}
impl DockerDriver {
    pub async fn protect_quarantined_network(
        &self,
        handle: &RuntimeHandle,
        network: &WorkloadNetworkPlan,
        session: &mut ControllerSession,
        source: &SourceBindingReceipt,
        protection: &QuarantineProtection,
    ) -> Result<ProtectedBindingReceipt, ApiError> {
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
        goldenhoop_egress::dns::Upstream::new(protection.upstream)?;
        let endpoint = self.observe_quarantined_endpoint(handle, network).await?;
        let provider = DockerNetworkProvider::connect().await?;
        let native = provider
            .lookup(&network.provider_plan())
            .await?
            .ok_or_else(conflict)?;
        source::validate_receipt(network, &endpoint, &native, source.revision, source)?;
        let before = call(session, Request::Inspect {}).await?;
        if before["installed"] != true
            || before["uncertain"] != false
            || before["ethernet_guarded"] != true
            || before["source_guarded"] != true
            || before["source_binding_sha256"].as_str() != Some(source.source.digest().as_str())
            || before["revision"].as_u64() != Some(source.revision)
            || before["destinations_guarded"] != false
            || !before["destination_binding_sha256"].is_null()
        {
            return Err(conflict());
        }
        let started = Utc::now();
        let mut attempt = ControllerAttempt {
            session,
            confirmed: false,
        };
        let session = &mut *attempt.session;
        let result = async {
            call(
                session,
                Request::ConfigureDns {
                    expected_revision: source.revision,
                    upstream: protection.upstream,
                },
            )
            .await?;
            let listening = call(
                session,
                Request::ListenDns {
                    expected_revision: source.revision,
                },
            )
            .await?;
            let revision = source.revision.checked_add(1).ok_or_else(conflict)?;
            if listening["uncertain"] != false || listening["revision"].as_u64() != Some(revision) {
                return Err(conflict());
            }
            let mut listeners = vec![
                serde_json::from_value::<DestinationListener>(listening["binding"].clone())
                    .map_err(|_| conflict())?,
            ];
            if !listening["ipv6_binding"].is_null() {
                listeners.push(
                    serde_json::from_value(listening["ipv6_binding"].clone())
                        .map_err(|_| conflict())?,
                );
            }
            call(
                session,
                Request::ProtectDestinations {
                    expected_revision: revision,
                    private_exceptions: protection.private_exceptions.clone(),
                    control_addresses: protection.control_addresses.clone(),
                },
            )
            .await?;
            let receipt: ProtectedBindingReceipt = serde_json::from_value(
                call(
                    session,
                    Request::InspectBinding {
                        expected_revision: revision,
                    },
                )
                .await?,
            )
            .map_err(|_| conflict())?;
            validate_receipt(network, source, protection, &listeners, started, &receipt)?;
            let after = self.observe_quarantined_endpoint(handle, network).await?;
            if serde_json::to_value(after).map_err(|_| conflict())?
                != serde_json::to_value(&endpoint).map_err(|_| conflict())?
            {
                return Err(conflict());
            }
            let native = provider
                .lookup(&network.provider_plan())
                .await?
                .ok_or_else(conflict)?;
            source::validate_receipt(network, &endpoint, &native, source.revision, source)?;
            let final_receipt: ProtectedBindingReceipt = serde_json::from_value(
                call(
                    session,
                    Request::InspectBinding {
                        expected_revision: revision,
                    },
                )
                .await?,
            )
            .map_err(|_| conflict())?;
            validate_receipt(
                network,
                source,
                protection,
                &listeners,
                receipt.observed_at,
                &final_receipt,
            )?;
            if final_receipt.destinations != receipt.destinations {
                return Err(conflict());
            }
            Ok(final_receipt)
        }
        .await;
        attempt.confirmed = result.is_ok();
        result
    }
}

fn validate_receipt(
    network: &WorkloadNetworkPlan,
    source: &SourceBindingReceipt,
    intent: &QuarantineProtection,
    listeners: &[DestinationListener],
    started: chrono::DateTime<Utc>,
    receipt: &ProtectedBindingReceipt,
) -> Result<(), ApiError> {
    receipt.validate()?;
    let expected = DestinationDefinition {
        scope: DestinationScope {
            host_addresses: receipt.destinations.scope.host_addresses.clone(),
            control_addresses: intent.control_addresses.clone(),
            private_exceptions: intent.private_exceptions.clone(),
        },
        dns: listeners.to_vec(),
    }
    .canonical()?;
    if receipt.allocation.owner() != network.native.allocation.owner()
        || receipt.source != source.source
        || receipt.revision != source.revision.checked_add(1).ok_or_else(conflict)?
        || receipt.expires_at != network.native.expires_at
        || receipt.observed_at < started
        || receipt.observed_at > Utc::now()
        || receipt.destinations != expected
    {
        return Err(conflict());
    }
    network.native.validate_at(Utc::now())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use goldenhoop_egress::{Endpoint, SourceScope};
    #[test]
    fn protected_receipt_refuses_changed_identity_expiry_dns_intent_and_stale_readbacks() {
        let (mut network, _, _, native) = super::super::tests::model();
        let now = Utc::now();
        network.native.expires_at = now + chrono::Duration::seconds(3600);
        let source = SourceBindingReceipt {
            allocation: network.native.allocation.clone(),
            source: SourceScope {
                endpoint: Endpoint {
                    port: "veth42".into(),
                    ifindex: network.native.allocation.ifindex + 1,
                    mac: "02:00:00:00:00:02".parse().unwrap(),
                    ipv4: "10.77.0.2".parse().unwrap(),
                    ipv6: Some((u128::from(native.ipv6_gateway) + 1).into()),
                },
                gateway_mac: "02:00:00:00:00:01".parse().unwrap(),
                gateway4: native.ipv4_gateway,
                gateway6: Some(native.ipv6_gateway),
            },
            revision: 0,
            observed_at: now,
        };
        let intent = QuarantineProtection {
            upstream: "127.0.0.1:19004".parse().unwrap(),
            private_exceptions: vec!["10.88.0.0/24".into()],
            control_addresses: vec!["192.0.2.100".parse().unwrap()],
        };
        let listeners = vec![
            DestinationListener {
                address: native.ipv4_gateway.into(),
                port: 40000,
            },
            DestinationListener {
                address: native.ipv6_gateway.into(),
                port: 40001,
            },
        ];
        let receipt = ProtectedBindingReceipt {
            allocation: source.allocation.clone(),
            source: source.source.clone(),
            revision: 1,
            destinations: DestinationDefinition {
                scope: DestinationScope {
                    host_addresses: vec![native.ipv4_gateway.into(), native.ipv6_gateway.into()],
                    control_addresses: intent.control_addresses.clone(),
                    private_exceptions: intent.private_exceptions.clone(),
                },
                dns: listeners.clone(),
            }
            .canonical()
            .unwrap(),
            expires_at: network.native.expires_at,
            observed_at: now,
        };
        let started = now - chrono::Duration::milliseconds(10);
        validate_receipt(&network, &source, &intent, &listeners, started, &receipt).unwrap();
        for case in 0..10 {
            let mut wrong = receipt.clone();
            match case {
                0 => wrong.allocation.generation = Uuid::new_v4(),
                1 => wrong.source.endpoint.mac = "02:00:00:00:00:03".parse().unwrap(),
                2 => wrong.revision += 1,
                3 => wrong.expires_at += chrono::Duration::seconds(1),
                4 => wrong.observed_at = started - chrono::Duration::milliseconds(1),
                5 => wrong.destinations.dns[0].port += 1,
                6 => wrong.destinations.scope.private_exceptions.clear(),
                7 => wrong.destinations.scope.control_addresses.clear(),
                8 => {
                    wrong.destinations.dns.pop();
                }
                _ => wrong.observed_at = now + chrono::Duration::seconds(60),
            }
            assert!(
                validate_receipt(&network, &source, &intent, &listeners, started, &wrong).is_err(),
                "case {case}"
            );
        }
    }
}
