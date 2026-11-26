use super::*;
use crate::{
    CredentialRedirect, CredentialRedirectPlan, NativePacketAuthority,
    credential_packets::PacketSnapshot,
};
use goldenhoop_credentials::Scheme;
use std::collections::BTreeMap;

impl Manager {
    pub fn publish_credential_packets(&self, target: &NativePacketAuthority) {
        let snapshot = (|| {
            if self.uncertain
                || !self.can_renew
                || self.credential_redirect.is_none()
                || !self.ethernet_required
                || self.source_scope.is_none()
            {
                return None;
            }
            let dns = self.dns.as_ref()?;
            let book = dns.book.as_ref()?;
            if book.is_unknown() {
                return None;
            }
            Some(PacketSnapshot {
                sandbox: self.allocation.sandbox_id,
                epoch: self.packet_epoch,
                revision: self.revision?,
                config: self.effective_policy.clone()?,
                book: book.clone(),
                floor: crate::ProtectedDestinations::new(self.destinations.as_ref()?.scope.clone())
                    .ok()?,
                lease_until: self.lease_until?,
                sandbox_deadline: dns.deadline,
            })
        })();
        target.publish(snapshot);
    }

    pub(super) async fn credential_guard(&self) -> Result<Option<CredentialRedirect>, ApiError> {
        let table = self.allocation.credential_table();
        let inventory: Value = serde_json::from_slice(
            &nft(&["--json", "list", "tables"], None).await?,
        )
        .map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "invalid credential table inventory",
            )
        })?;
        let rows = inventory["nftables"].as_array().ok_or_else(|| {
            error(
                ErrorCode::BackendUnavailable,
                "missing credential table inventory",
            )
        })?;
        if !rows
            .iter()
            .any(|v| v["table"]["family"] == "inet" && v["table"]["name"] == table)
        {
            return Ok(None);
        }
        let native: Value =
            serde_json::from_slice(&nft(&["--json", "list", "table", "inet", &table], None).await?)
                .map_err(|_| {
                    error(
                        ErrorCode::BackendUnavailable,
                        "invalid credential table observation",
                    )
                })?;
        Ok(Some(CredentialRedirectPlan::descriptor(
            &self.allocation,
            &native,
        )?))
    }
    pub(super) async fn verify_credential_guard(&self) -> Result<(), ApiError> {
        if let Some(expected) = &self.credential_redirect {
            let native: Value = serde_json::from_slice(
                &nft(
                    &[
                        "--json",
                        "list",
                        "table",
                        "inet",
                        &self.allocation.credential_table(),
                    ],
                    None,
                )
                .await?,
            )
            .map_err(|_| {
                error(
                    ErrorCode::BackendUnavailable,
                    "invalid credential redirect observation",
                )
            })?;
            CredentialRedirectPlan::new(&self.allocation, expected.clone())?
                .verify(&self.allocation, &native)?;
        }
        Ok(())
    }
    pub fn credential_source(&self) -> Result<crate::EndpointAddresses, ApiError> {
        let source = self.source_scope.as_ref().ok_or_else(|| {
            error(
                ErrorCode::InvalidState,
                "credential ingress requires a protected source",
            )
        })?;
        Ok(crate::EndpointAddresses {
            mac: source.endpoint.mac,
            ipv4: source.endpoint.ipv4,
            ipv6: source.endpoint.ipv6,
        })
    }
    pub async fn disable_credential_redirect(&mut self, expected: u64) -> Result<(), ApiError> {
        self.check_lifetime()?;
        if self.uncertain || self.can_renew || self.revision != Some(expected) {
            return Err(error(
                ErrorCode::InvalidState,
                "remove credential ingress only under known quarantine",
            ));
        }
        self.expected(expected).await?;
        if self.credential_guard().await?.is_some() {
            self.uncertain = true;
            self.lease_until = None;
            nft(
                &["--file", "-"],
                Some(
                    format!("delete table inet {}\n", self.allocation.credential_table())
                        .as_bytes(),
                ),
            )
            .await?;
            if self.credential_guard().await?.is_some() {
                return Err(error(
                    ErrorCode::BackendUnavailable,
                    "credential ingress removal is unconfirmed",
                ));
            }
            self.credential_redirect = None;
            self.uncertain = false;
        }
        Ok(())
    }
    /// Configure only while the recovered workload is quarantined. Existing
    /// owned redirect descriptors can be replaced only after the old controller
    /// was physically collected by the worker's epoch-recovery path.
    pub async fn install_credential_redirect(
        &mut self,
        expected: u64,
        ports: BTreeMap<u16, Scheme>,
    ) -> Result<CredentialRedirect, ApiError> {
        self.check_lifetime()?;
        if self.uncertain
            || self.can_renew
            || self.revision != Some(expected)
            || !self.ethernet_required
            || self.source_scope.is_none()
            || self.destinations.is_none()
        {
            return Err(error(
                ErrorCode::InvalidState,
                "credential ingress requires known protected quarantine",
            ));
        }
        self.expected(expected).await?;
        let dns = self
            .dns
            .as_ref()
            .and_then(|d| d.binding.as_ref())
            .ok_or_else(|| {
                error(
                    ErrorCode::InvalidState,
                    "credential ingress requires bound trusted sockets",
                )
            })?;
        let definition = CredentialRedirect {
            v4: dns.v4.clone(),
            v6: dns.v6.clone(),
            ports,
        };
        let plan = CredentialRedirectPlan::new(&self.allocation, definition.clone())?;
        let mut script = String::new();
        if self.credential_guard().await?.is_some() {
            script.push_str(&format!(
                "delete table inet {}\n",
                self.allocation.credential_table()
            ));
        }
        script.push_str(plan.script());
        self.uncertain = true;
        self.can_renew = false;
        self.lease_until = None;
        nft(&["--file", "-"], Some(script.as_bytes())).await?;
        let native: Value = serde_json::from_slice(
            &nft(
                &[
                    "--json",
                    "list",
                    "table",
                    "inet",
                    &self.allocation.credential_table(),
                ],
                None,
            )
            .await?,
        )
        .map_err(|_| {
            error(
                ErrorCode::BackendUnavailable,
                "invalid installed credential observation",
            )
        })?;
        plan.verify(&self.allocation, &native)?;
        self.check_bridge()?;
        self.credential_redirect = Some(definition.clone());
        self.uncertain = false;
        Ok(definition)
    }
}
