//! Process-local packet authority, published only by native manager readback.
//! Neither durable records nor a credential binding can construct a live lease.
use crate::{
    Config, ProtectedDestinations,
    dns::{Authority, LeaseBook},
    error,
};
use async_trait::async_trait;
use goldenhoop_credentials::{PacketAuthority, PacketWitness, RequestIdentity};
use goldenhoop_policy::{DecisionOrigin, Domain, Packet, Transport};
use goldenhoop_protocol::{ApiError, ErrorCode, NetworkAction};
use std::{
    net::{IpAddr, SocketAddr},
    sync::RwLock,
    time::Instant,
};
use uuid::Uuid;

pub(crate) struct PacketSnapshot {
    pub sandbox: Uuid,
    pub epoch: Uuid,
    pub revision: u64,
    pub config: Config,
    pub book: LeaseBook,
    pub floor: ProtectedDestinations,
    pub lease_until: Instant,
    pub sandbox_deadline: Instant,
}

#[derive(Default)]
pub struct NativePacketAuthority {
    snapshot: RwLock<Option<PacketSnapshot>>,
}

fn denied() -> ApiError {
    error(
        ErrorCode::Forbidden,
        "native credential packet authority is unavailable",
    )
}

impl NativePacketAuthority {
    pub fn fence(&self) {
        if let Ok(mut snapshot) = self.snapshot.write() {
            *snapshot = None;
        }
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn publish(&self, snapshot: Option<PacketSnapshot>) {
        if let Ok(mut slot) = self.snapshot.write() {
            *slot = snapshot;
        }
    }
}

impl PacketSnapshot {
    fn live(&self, now: Instant) -> Result<(), ApiError> {
        if now >= self.lease_until || now >= self.sandbox_deadline || self.book.is_unknown() {
            return Err(denied());
        }
        Ok(())
    }
    fn authorize(
        &self,
        host: Option<&str>,
        destination: SocketAddr,
        now: Instant,
    ) -> Result<(Option<String>, Instant), ApiError> {
        self.live(now)?;
        let address = destination.ip();
        if address != address.to_canonical() || self.floor.classify(address).blocked() {
            return Err(denied());
        }
        // The immutable floor's FIB predicate covers host-address additions.
        // Recheck that live inventory for the broker's independently opened
        // host socket, which does not traverse the workload's input hook.
        #[cfg(target_os = "linux")]
        if crate::frontend::host_addresses()?.contains(&address) {
            return Err(denied());
        }
        let packet = Packet::new(address, Transport::Tcp, Some(destination.port()))?;
        let model = self.config.model()?;
        let (decision, name, deadline) = if let Some(host) = host {
            if let Ok(literal) = host.parse::<IpAddr>() {
                if literal != address {
                    return Err(denied());
                }
                (
                    model.address_candidate(&packet),
                    None,
                    self.sandbox_deadline,
                )
            } else {
                let name = Domain::parse(host)?;
                let (authority, until) = self
                    .book
                    .source_address(&name, address, now)?
                    .ok_or_else(denied)?;
                let candidate = model.dns_candidate(&name);
                let origin = match (authority, candidate.action, candidate.origin) {
                    (Authority::User, NetworkAction::Allow, DecisionOrigin::UserAgreement) => {
                        DecisionOrigin::UserAgreement
                    }
                    (
                        Authority::OperatorAllow,
                        NetworkAction::Allow,
                        origin @ DecisionOrigin::AllowAlways(_),
                    ) => origin,
                    _ => return Err(denied()),
                };
                (
                    model.leased_address_candidate(&packet, origin)?,
                    Some(name.as_str().to_owned()),
                    until,
                )
            }
        } else {
            (
                model.address_candidate(&packet),
                None,
                self.sandbox_deadline,
            )
        };
        if decision.action != NetworkAction::Allow {
            return Err(denied());
        }
        Ok((name, deadline))
    }
}

#[async_trait]
impl PacketAuthority for NativePacketAuthority {
    async fn admit(&self, request: &RequestIdentity) -> Result<PacketWitness, ApiError> {
        let snapshot = self.snapshot.read().map_err(|_| denied())?;
        let snapshot = snapshot.as_ref().ok_or_else(denied)?;
        if request.sandbox_id != snapshot.sandbox {
            return Err(denied());
        }
        let destination = SocketAddr::new(request.destination, request.port);
        let (source_name, expires_at) =
            snapshot.authorize(Some(&request.host), destination, Instant::now())?;
        Ok(PacketWitness {
            epoch: snapshot.epoch,
            revision: snapshot.revision,
            destination,
            source_name,
            expires_at,
        })
    }
    async fn current(&self, witness: &PacketWitness) -> Result<(), ApiError> {
        let snapshot = self.snapshot.read().map_err(|_| denied())?;
        let snapshot = snapshot.as_ref().ok_or_else(denied)?;
        let now = Instant::now();
        if snapshot.epoch != witness.epoch
            || snapshot.revision != witness.revision
            || witness.expires_at <= now
        {
            return Err(denied());
        }
        let (name, _) =
            snapshot.authorize(witness.source_name.as_deref(), witness.destination, now)?;
        if name != witness.source_name {
            return Err(denied());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goldenhoop_credentials::Scheme;
    use std::time::Duration;
    fn snapshot() -> PacketSnapshot {
        let now = Instant::now();
        PacketSnapshot {sandbox:Uuid::new_v4(),epoch:Uuid::new_v4(),revision:9,
            config:serde_json::from_value(serde_json::json!({"policies":[{"default_action":"deny","rules":[{"destination":"api.example.test","ports":[],"action":"allow"}]}]})).unwrap(),
            book:LeaseBook::new(9,now+Duration::from_secs(300)),floor:ProtectedDestinations::new(crate::DestinationScope::default()).unwrap(),
            lease_until:now+Duration::from_secs(5),sandbox_deadline:now+Duration::from_secs(300)}
    }
    fn grant(snapshot: &mut PacketSnapshot, name: &str, address: &str) {
        let now = Instant::now();
        snapshot
            .book
            .fixture_source(name, address.parse().unwrap(), now);
    }
    fn request(snapshot: &PacketSnapshot) -> RequestIdentity {
        RequestIdentity {
            sandbox_id: snapshot.sandbox,
            scheme: Scheme::Https,
            host: "api.example.test".into(),
            port: 443,
            destination: "192.0.2.44".parse().unwrap(),
            tls_server_name: Some("api.example.test".into()),
            method: "POST".parse().unwrap(),
            path_and_query: "/v1/test".into(),
        }
    }
    #[tokio::test]
    async fn exact_dns_source_and_current_native_lease_are_both_required() {
        let mut snapshot = snapshot();
        let request = request(&snapshot);
        grant(&mut snapshot, "other.example.test", "192.0.2.44");
        let authority = NativePacketAuthority::default();
        assert!(authority.admit(&request).await.is_err());
        *authority.snapshot.write().unwrap() = Some(snapshot);
        assert!(authority.admit(&request).await.is_err());
        grant(
            authority.snapshot.write().unwrap().as_mut().unwrap(),
            "api.example.test",
            "192.0.2.44",
        );
        let witness = authority.admit(&request).await.unwrap();
        authority.current(&witness).await.unwrap();
        // A renewable native lease is checked separately from the source TTL.
        assert!(
            witness.expires_at
                > authority
                    .snapshot
                    .read()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .lease_until
        );
        authority
            .snapshot
            .write()
            .unwrap()
            .as_mut()
            .unwrap()
            .lease_until = Instant::now() - Duration::from_millis(1);
        assert!(authority.current(&witness).await.is_err());
        authority
            .snapshot
            .write()
            .unwrap()
            .as_mut()
            .unwrap()
            .lease_until = Instant::now() + Duration::from_secs(5);
        authority.current(&witness).await.unwrap();
        authority.fence();
        assert!(authority.current(&witness).await.is_err());
    }
    #[tokio::test]
    async fn static_denials_port_floors_destination_floors_and_epoch_changes_cannot_borrow_dns() {
        let mut snapshot = snapshot();
        grant(&mut snapshot, "api.example.test", "192.0.2.44");
        let request = request(&snapshot);
        let authority = NativePacketAuthority::default();
        *authority.snapshot.write().unwrap() = Some(snapshot);
        let witness = authority.admit(&request).await.unwrap();
        authority
            .snapshot
            .write()
            .unwrap()
            .as_mut()
            .unwrap()
            .config
            .tcp_cap = Some(vec![80]);
        assert!(authority.admit(&request).await.is_err());
        assert!(authority.current(&witness).await.is_err());
        {
            let mut guard = authority.snapshot.write().unwrap();
            let snapshot = guard.as_mut().unwrap();
            snapshot.config.tcp_cap = None;
            snapshot.config.deny_always = vec![goldenhoop_protocol::NetworkRule {
                destination: request.destination.to_string(),
                ports: vec![443],
                action: NetworkAction::Deny,
            }];
        }
        assert!(authority.admit(&request).await.is_err());
        {
            let mut guard = authority.snapshot.write().unwrap();
            let snapshot = guard.as_mut().unwrap();
            snapshot.config.deny_always.clear();
            snapshot.epoch = Uuid::new_v4();
        }
        assert!(authority.current(&witness).await.is_err());
        let mut protected = request.clone();
        protected.host = "127.0.0.1".into();
        protected.destination = "127.0.0.1".parse().unwrap();
        assert!(authority.admit(&protected).await.is_err());
        let mut wrong = request;
        wrong.sandbox_id = Uuid::new_v4();
        assert!(authority.admit(&wrong).await.is_err());
    }
}
