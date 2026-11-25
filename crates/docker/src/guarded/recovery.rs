//! Restore the exact DNS sockets in a new owned controller, always under deny.
use super::*;
use goldenhoop_egress::{DestinationListener, ProtectedBindingReceipt, SourceBindingReceipt};
use source::call;

impl DockerDriver {
    /// The previous controller must be positively settled and collected before
    /// its journal authorizes this new session. This method never replays start.
    pub async fn recover_quarantined_network(
        &self,
        handle: &RuntimeHandle,
        network: &WorkloadNetworkPlan,
        session: &mut ControllerSession,
        frozen: &ProtectedBindingReceipt,
        intent: &QuarantineProtection,
    ) -> Result<ProtectedBindingReceipt, ApiError> {
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
        {
            return Err(conflict());
        }
        goldenhoop_egress::dns::Upstream::new(intent.upstream)?;
        let endpoint = self.observe_quarantined_endpoint(handle, network).await?;
        // Refuse duplicate recovery without dispatching a native mutation or
        // closing a healthy already-open session.
        let unopened = call(session, Request::Inspect {}).await;
        if !matches!(unopened, Err(ref e) if e.code == goldenhoop_protocol::ErrorCode::InvalidState)
            || session.is_uncertain()
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
                Request::BindNative {
                    plan: network.native.clone(),
                },
            )
            .await?;
            let before = call(
                session,
                Request::Open {
                    allocation: network.native.allocation.clone(),
                },
            )
            .await?;
            let revision = before["revision"].as_u64().ok_or_else(conflict)?;
            if before["installed"] != true
                || before["uncertain"] != false
                || before["ethernet_guarded"] != true
                || before["source_guarded"] != true
                || before["destinations_guarded"] != true
                || before["source_binding_sha256"].as_str() != Some(frozen.source.digest().as_str())
                || before["destination_binding_sha256"].as_str()
                    != Some(frozen.destinations.digest().as_str())
            {
                return Err(conflict());
            }
            let source = SourceBindingReceipt {
                allocation: frozen.allocation.clone(),
                source: frozen.source.clone(),
                revision,
                observed_at: started,
            };
            let provider = DockerNetworkProvider::connect().await?;
            let native = provider
                .lookup(&network.provider_plan())
                .await?
                .ok_or_else(conflict)?;
            source::validate_receipt(network, &endpoint, &native, revision, &source)?;
            let listening = call(
                session,
                Request::RecoverDns {
                    expected_revision: revision,
                    upstream: intent.upstream,
                    source: frozen.source.clone(),
                    destinations: frozen.destinations.clone(),
                },
            )
            .await?;
            let next = revision.checked_add(1).ok_or_else(conflict)?;
            if listening["revision"].as_u64() != Some(next) || listening["uncertain"] != false {
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
            let receipt: ProtectedBindingReceipt = serde_json::from_value(
                call(
                    session,
                    Request::InspectBinding {
                        expected_revision: next,
                    },
                )
                .await?,
            )
            .map_err(|_| conflict())?;
            protection::validate_receipt(network, &source, intent, &listeners, started, &receipt)?;
            if receipt.destinations != frozen.destinations || listeners != frozen.destinations.dns {
                return Err(conflict());
            }
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
            source::validate_receipt(network, &endpoint, &native, revision, &source)?;
            let final_receipt: ProtectedBindingReceipt = serde_json::from_value(
                call(
                    session,
                    Request::InspectBinding {
                        expected_revision: next,
                    },
                )
                .await?,
            )
            .map_err(|_| conflict())?;
            protection::validate_receipt(
                network,
                &source,
                intent,
                &listeners,
                receipt.observed_at,
                &final_receipt,
            )?;
            if final_receipt.destinations != frozen.destinations {
                return Err(conflict());
            }
            Ok(final_receipt)
        }
        .await;
        attempt.confirmed = result.is_ok();
        result
    }
}
