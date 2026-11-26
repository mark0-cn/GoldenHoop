//! Policy changes and bounded live leases on an already protected endpoint.
//! The caller retains the control session; this type never publishes Ready.
use super::*;
use goldenhoop_egress::{Config, EffectivePolicyReceipt, ProtectedBindingReceipt};
use source::call;
use tokio::time::Instant;

/// Process-local proof with a conservative monotonic deadline. It cannot be
/// serialized into restart authority or constructed from a public receipt.
pub struct VerifiedPolicyLease {
    receipt: EffectivePolicyReceipt,
    until: Instant,
}
impl VerifiedPolicyLease {
    pub fn receipt(&self) -> &EffectivePolicyReceipt {
        &self.receipt
    }
    pub fn remaining(&self) -> Duration {
        self.until.saturating_duration_since(Instant::now())
    }
}

impl DockerDriver {
    pub async fn apply_protected_policy(
        &self,
        handle: &RuntimeHandle,
        network: &WorkloadNetworkPlan,
        session: &mut ControllerSession,
        frozen: &ProtectedBindingReceipt,
        config: &Config,
    ) -> Result<VerifiedPolicyLease, ApiError> {
        self.policy_exchange(handle, network, session, frozen, None, Some(config))
            .await
    }
    pub async fn replace_protected_policy(
        &self,
        handle: &RuntimeHandle,
        network: &WorkloadNetworkPlan,
        session: &mut ControllerSession,
        previous: &VerifiedPolicyLease,
        config: &Config,
    ) -> Result<VerifiedPolicyLease, ApiError> {
        self.policy_exchange(
            handle,
            network,
            session,
            &previous.receipt.binding,
            Some(previous),
            Some(config),
        )
        .await
    }
    pub async fn renew_protected_policy(
        &self,
        handle: &RuntimeHandle,
        network: &WorkloadNetworkPlan,
        session: &mut ControllerSession,
        previous: &VerifiedPolicyLease,
    ) -> Result<VerifiedPolicyLease, ApiError> {
        self.policy_exchange(
            handle,
            network,
            session,
            &previous.receipt.binding,
            Some(previous),
            None,
        )
        .await
    }

    async fn policy_exchange(
        &self,
        handle: &RuntimeHandle,
        network: &WorkloadNetworkPlan,
        session: &mut ControllerSession,
        frozen: &ProtectedBindingReceipt,
        previous: Option<&VerifiedPolicyLease>,
        config: Option<&Config>,
    ) -> Result<VerifiedPolicyLease, ApiError> {
        network.validate()?;
        frozen.validate()?;
        let controller = session.plan();
        controller.validate_dispatch_at(Utc::now())?;
        if controller.purpose != ControllerPurpose::Enforce
            || serde_json::to_value(&controller.native).map_err(|_| conflict())?
                != serde_json::to_value(&network.native).map_err(|_| conflict())?
            || network.native.identity.installation_id != self.config.installation_id
            || network.native.identity.profile != self.config.profile.id()
            || frozen.allocation.owner() != network.native.allocation.owner()
            || frozen.expires_at != network.native.expires_at
            || previous.is_some_and(|p| p.remaining().is_zero())
        {
            return Err(conflict());
        }
        let digest = if let Some(config) = config {
            config.digest()?
        } else {
            previous.ok_or_else(conflict)?.receipt.config_sha256.clone()
        };
        if self.inspect(handle).await?.state != ObservedState::Running {
            return Err(conflict());
        }
        let endpoint = self.observe_quarantined_endpoint(handle, network).await?;
        endpoint_matches(frozen, &endpoint)?;
        // Read-only preflight precedes the mutation fence. A duplicate initial
        // apply refuses without shutting down an otherwise healthy session.
        let preflight = Utc::now();
        if let Some(previous) = previous.filter(|_| config.is_some()) {
            let receipt: EffectivePolicyReceipt = serde_json::from_value(
                call(
                    session,
                    Request::InspectPolicy {
                        expected_revision: frozen.revision,
                    },
                )
                .await?,
            )
            .map_err(|_| conflict())?;
            validate_policy(
                network,
                frozen,
                frozen.revision,
                &previous.receipt.config_sha256,
                preflight,
                &receipt,
            )?;
        } else if previous.is_none() {
            let actual: ProtectedBindingReceipt = serde_json::from_value(
                call(
                    session,
                    Request::InspectBinding {
                        expected_revision: frozen.revision,
                    },
                )
                .await?,
            )
            .map_err(|_| conflict())?;
            binding_matches(network, frozen, frozen.revision, preflight, &actual)?;
        }
        let mut attempt = ControllerAttempt {
            session,
            confirmed: false,
        };
        let session = &mut *attempt.session;
        let result = async {
            let (revision, first) = if let Some(config) = config {
                let next = frozen.revision.checked_add(1).ok_or_else(conflict)?;
                call(
                    session,
                    Request::Apply {
                        expected_revision: frozen.revision,
                        config: config.clone(),
                    },
                )
                .await?;
                (
                    next,
                    read_policy(session, network, frozen, next, &digest, false).await?,
                )
            } else {
                // RenewPolicy performs the complete native preflight, mutation
                // and postflight. Its sampled receipt replaces the former
                // repeated preflight/first read; the independent final read
                // still follows actual provider/endpoint reobservation.
                (
                    frozen.revision,
                    read_policy(session, network, frozen, frozen.revision, &digest, true).await?,
                )
            };
            if self.inspect(handle).await?.state != ObservedState::Running {
                return Err(conflict());
            }
            let after = self.observe_quarantined_endpoint(handle, network).await?;
            if serde_json::to_value(&after).map_err(|_| conflict())?
                != serde_json::to_value(&endpoint).map_err(|_| conflict())?
            {
                return Err(conflict());
            }
            endpoint_matches(frozen, &after)?;
            let mut final_read =
                read_policy(session, network, frozen, revision, &digest, false).await?;
            final_read.until = final_read.until.min(first.until);
            if final_read.remaining().is_zero() {
                return Err(conflict());
            }
            Ok(final_read)
        }
        .await;
        attempt.confirmed = result.is_ok();
        result.map_err(|e| bootstrap_context("policy authority confirmation", e))
    }
}

fn endpoint_matches(
    binding: &ProtectedBindingReceipt,
    endpoint: &WorkloadEndpoint,
) -> Result<(), ApiError> {
    if binding.source.endpoint.mac != endpoint.mac
        || binding.source.endpoint.ipv4 != endpoint.ipv4
        || binding.source.endpoint.ipv6 != Some(endpoint.ipv6)
    {
        return Err(conflict());
    }
    Ok(())
}
fn binding_matches(
    network: &WorkloadNetworkPlan,
    frozen: &ProtectedBindingReceipt,
    revision: u64,
    started: chrono::DateTime<Utc>,
    actual: &ProtectedBindingReceipt,
) -> Result<(), ApiError> {
    actual.validate()?;
    if actual.allocation.owner() != network.native.allocation.owner()
        || actual.source != frozen.source
        || actual.destinations != frozen.destinations
        || actual.expires_at != network.native.expires_at
        || actual.revision != revision
        || actual.observed_at < started
        || actual.observed_at > Utc::now()
    {
        return Err(conflict());
    }
    network.native.validate_at(Utc::now())?;
    Ok(())
}
fn validate_policy(
    network: &WorkloadNetworkPlan,
    frozen: &ProtectedBindingReceipt,
    revision: u64,
    digest: &str,
    started: chrono::DateTime<Utc>,
    actual: &EffectivePolicyReceipt,
) -> Result<(), ApiError> {
    actual.validate()?;
    binding_matches(network, frozen, revision, started, &actual.binding)?;
    if actual.config_sha256 != digest {
        return Err(conflict());
    }
    Ok(())
}
async fn read_policy(
    session: &mut ControllerSession,
    network: &WorkloadNetworkPlan,
    frozen: &ProtectedBindingReceipt,
    revision: u64,
    digest: &str,
    renew: bool,
) -> Result<VerifiedPolicyLease, ApiError> {
    let start = Instant::now();
    let wall = Utc::now();
    let receipt: EffectivePolicyReceipt = serde_json::from_value(
        call(
            session,
            if renew {
                Request::RenewPolicy {
                    expected_revision: revision,
                }
            } else {
                Request::InspectPolicy {
                    expected_revision: revision,
                }
            },
        )
        .await?,
    )
    .map_err(|_| conflict())?;
    validate_policy(network, frozen, revision, digest, wall, &receipt)?;
    // The server's verified budget begins when it starts sampling, after this
    // request starts. Anchoring here conservatively includes transport without
    // requiring matching monotonic epochs or extending the native deadline.
    // Never anchor a receipt's duration at receive time.
    let until = start + Duration::from_millis(u64::from(receipt.lease_remaining_milliseconds));
    if until <= Instant::now() {
        return Err(conflict());
    }
    Ok(VerifiedPolicyLease { receipt, until })
}

#[cfg(test)]
mod tests {
    use super::*;
    use goldenhoop_egress::{
        DestinationDefinition, DestinationListener, DestinationScope, Endpoint, SourceScope,
    };
    #[test]
    fn effective_receipt_cannot_change_configuration_floor_identity_expiry_or_sampling_window() {
        let (mut network, _, _, native) = super::super::tests::model();
        let now = Utc::now();
        network.native.expires_at = now + chrono::Duration::seconds(3600);
        let frozen = ProtectedBindingReceipt {
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
            destinations: DestinationDefinition {
                scope: DestinationScope {
                    host_addresses: vec![native.ipv4_gateway.into(), native.ipv6_gateway.into()],
                    control_addresses: vec![],
                    private_exceptions: vec![],
                },
                dns: vec![
                    DestinationListener {
                        address: native.ipv4_gateway.into(),
                        port: 40000,
                    },
                    DestinationListener {
                        address: native.ipv6_gateway.into(),
                        port: 40001,
                    },
                ],
            }
            .canonical()
            .unwrap(),
            revision: 1,
            expires_at: network.native.expires_at,
            observed_at: now,
        };
        let config: Config = serde_json::from_value(
            serde_json::json!({"policies":[{"default_action":"deny","rules":[]}]}),
        )
        .unwrap();
        let mut current = frozen.clone();
        current.revision = 2;
        let receipt = EffectivePolicyReceipt {
            binding: current,
            config_sha256: config.digest().unwrap(),
            native_sha256: "a".repeat(64),
            lease_remaining_milliseconds: 9000,
        };
        let started = now - chrono::Duration::milliseconds(1);
        validate_policy(
            &network,
            &frozen,
            2,
            &config.digest().unwrap(),
            started,
            &receipt,
        )
        .unwrap();
        receipt.validate_config(&config).unwrap();
        for case in 0..12 {
            let mut wrong = receipt.clone();
            match case {
                0 => wrong.config_sha256 = "b".repeat(64),
                1 => wrong.native_sha256 = "G".repeat(64),
                2 => wrong.lease_remaining_milliseconds = 0,
                3 => wrong.lease_remaining_milliseconds = 10001,
                4 => wrong.binding.observed_at = started - chrono::Duration::milliseconds(1),
                5 => wrong.binding.observed_at = now + chrono::Duration::seconds(60),
                6 => wrong.binding.revision += 1,
                7 => wrong.binding.expires_at += chrono::Duration::seconds(1),
                8 => wrong.binding.destinations.dns[0].port += 1,
                9 => wrong.binding.source.endpoint.mac = "02:00:00:00:00:03".parse().unwrap(),
                10 => wrong.binding.allocation.ifindex += 1,
                _ => wrong.binding.expires_at = now + chrono::Duration::milliseconds(100),
            }
            assert!(
                validate_policy(
                    &network,
                    &frozen,
                    2,
                    &config.digest().unwrap(),
                    started,
                    &wrong
                )
                .is_err(),
                "case {case}"
            );
        }
    }
}
