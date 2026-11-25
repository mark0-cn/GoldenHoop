//! Fresh protected quarantine observation. This is neither a lease nor Ready.
use crate::{Allocation, DestinationDefinition, SourceScope, error};
use chrono::{DateTime, Utc};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedBindingReceipt {
    pub allocation: Allocation,
    pub source: SourceScope,
    pub destinations: DestinationDefinition,
    pub revision: u64,
    pub expires_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
}
impl ProtectedBindingReceipt {
    pub fn validate(&self) -> Result<(), ApiError> {
        listeners(&self.allocation, &self.source, &self.destinations)?;
        if self.observed_at >= self.expires_at {
            return Err(error(ErrorCode::Conflict, "protected binding differs"));
        }
        Ok(())
    }
}

/// A recovered destination floor pins the exact original DNS tuples. No new
/// address, port or family can be selected while reconstructing these sockets.
pub(crate) fn listeners(
    allocation: &Allocation,
    source: &SourceScope,
    destinations: &DestinationDefinition,
) -> Result<crate::DnsBindings, ApiError> {
    source.validate(allocation)?;
    let canonical = destinations.canonical()?;
    let gateways = std::iter::once(source.gateway4.into())
        .chain(source.gateway6.map(std::net::IpAddr::V6))
        .collect::<Vec<_>>();
    if canonical != *destinations
        || canonical.dns.iter().map(|d| d.address).collect::<Vec<_>>() != gateways
    {
        return Err(error(ErrorCode::Conflict, "protected DNS binding differs"));
    }
    let v4 = &canonical.dns[0];
    let v6 = canonical.dns.get(1);
    crate::DnsBindings::new(
        crate::DnsBinding::new(v4.address, v4.port)?,
        v6.map(|d| crate::DnsBinding::new(d.address, d.port))
            .transpose()?,
    )
}

/// Freeze the monotonic deadline before any asynchronous native observation.
/// The upper bound preserves the public maximum TTL without accepting an
/// arbitrary longer expiry on this private path.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn remaining_lifetime(
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<std::time::Duration, ApiError> {
    let remaining = expires_at.signed_duration_since(now);
    if remaining <= chrono::Duration::zero() {
        return Err(error(
            ErrorCode::DeadlineExceeded,
            "sandbox lifetime elapsed",
        ));
    }
    if remaining > chrono::Duration::seconds(86400) {
        return Err(error(
            ErrorCode::InvalidRequest,
            "sandbox lifetime exceeds maximum",
        ));
    }
    remaining
        .to_std()
        .map_err(|_| error(ErrorCode::InvalidRequest, "invalid sandbox lifetime"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_listener_ports_require_exact_gateway_families_and_canonical_scope() {
        let allocation = Allocation {
            installation_id: uuid::Uuid::new_v4(),
            sandbox_id: uuid::Uuid::new_v4(),
            generation: uuid::Uuid::new_v4(),
            bridge: "ghrecovery".into(),
            ifindex: 20,
        };
        let source = SourceScope {
            endpoint: crate::Endpoint {
                port: "veth42".into(),
                ifindex: 21,
                mac: "02:00:00:00:00:02".parse().unwrap(),
                ipv4: "192.0.2.2".parse().unwrap(),
                ipv6: Some("fd42::2".parse().unwrap()),
            },
            gateway_mac: "02:00:00:00:00:01".parse().unwrap(),
            gateway4: "192.0.2.1".parse().unwrap(),
            gateway6: Some("fd42::1".parse().unwrap()),
        };
        let destinations = DestinationDefinition {
            scope: crate::DestinationScope {
                host_addresses: vec![source.gateway4.into(), source.gateway6.unwrap().into()],
                control_addresses: vec![],
                private_exceptions: vec![],
            },
            dns: vec![
                crate::DestinationListener {
                    address: source.gateway4.into(),
                    port: 40000,
                },
                crate::DestinationListener {
                    address: source.gateway6.unwrap().into(),
                    port: 40001,
                },
            ],
        }
        .canonical()
        .unwrap();
        let bindings = listeners(&allocation, &source, &destinations).unwrap();
        assert_eq!(
            bindings
                .iter()
                .map(|d| (d.address(), d.port()))
                .collect::<Vec<_>>(),
            destinations
                .dns
                .iter()
                .map(|d| (d.address, d.port))
                .collect::<Vec<_>>()
        );
        for case in 0..7 {
            let mut wrong = destinations.clone();
            match case {
                0 => {
                    wrong.dns.pop();
                }
                1 => wrong.dns[0].port = 53,
                2 => wrong.dns[0].address = "192.0.2.3".parse().unwrap(),
                3 => wrong.dns[1].address = "fd42::3".parse().unwrap(),
                4 => wrong.dns.reverse(),
                5 => wrong.dns.push(wrong.dns[0].clone()),
                _ => wrong.scope.host_addresses.clear(),
            }
            assert!(
                listeners(&allocation, &source, &wrong).is_err(),
                "case {case}"
            );
        }
    }
    #[test]
    fn original_expiry_supports_full_ttl_without_rounding_or_extension() {
        let now = Utc::now();
        for seconds in [1, 1801, 65536, 86400] {
            assert_eq!(
                remaining_lifetime(now + chrono::Duration::seconds(seconds), now).unwrap(),
                std::time::Duration::from_secs(seconds as u64)
            );
        }
        assert_eq!(
            remaining_lifetime(now + chrono::Duration::milliseconds(1), now).unwrap(),
            std::time::Duration::from_millis(1)
        );
        assert!(remaining_lifetime(now, now).is_err());
        assert!(remaining_lifetime(now - chrono::Duration::seconds(1), now).is_err());
        assert!(remaining_lifetime(now + chrono::Duration::seconds(86401), now).is_err());
    }
}
