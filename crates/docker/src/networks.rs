//! Private owned bridge provider. It does not attach workloads or grant policy.
use super::{EXPIRY_LABEL, INSTALL_LABEL, PROFILE_LABEL, ROLE_LABEL, SANDBOX_LABEL, backend};
use bollard::{Docker, models::*, query_parameters::ListNetworksOptions};
use chrono::{DateTime, Utc};
use goldenhoop_egress::NetworkIdentity;
use goldenhoop_protocol::{ApiError, ErrorCode};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;
use uuid::Uuid;

const GENERATION: &str = "dev.goldenhoop.network-generation";
const IDENTITY: &str = "dev.goldenhoop.network-identity-sha256";
const PROVISION: &str = "dev.goldenhoop.network-provisioning";
const ROLE: &str = "egress-network";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPlan {
    pub identity: NetworkIdentity,
    pub provisioning_token: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn captured() -> (NetworkPlan, Value) {
        let value: Value =
            serde_json::from_str(include_str!("../tests/fixtures/owned-network.json")).unwrap();
        (
            serde_json::from_value(value["plan"].clone()).unwrap(),
            value["observation"].clone(),
        )
    }
    #[test]
    fn actual_owned_network_inspection_keeps_identity_ipam_and_known_endpoint_presence() {
        let (plan, mut value) = captured();
        plan.validate().unwrap();
        let observed = observe(&plan, &serde_json::from_value(value.clone()).unwrap()).unwrap();
        assert_eq!(observed.attached_endpoints, 0);
        assert_eq!(observed.ipv6_subnet, plan.identity.ipv6_subnet());
        value["Containers"] = json!({"controlled":{"Name":"controlled","EndpointID":"c".repeat(64),"MacAddress":"02:00:00:00:00:02","IPv4Address":"10.0.0.2/24","IPv6Address":""}});
        assert_eq!(
            observe(&plan, &serde_json::from_value(value).unwrap())
                .unwrap()
                .attached_endpoints,
            1
        );
    }
    #[test]
    fn actual_inspection_mutations_cannot_forge_ownership_weaken_topology_or_infer_absence() {
        let (plan, original) = captured();
        let mut candidates = Vec::new();
        for (field, value) in [
            ("Name", json!("foreign")),
            ("Id", json!("alias")),
            ("Driver", json!("overlay")),
            ("Scope", json!("swarm")),
            ("EnableIPv4", json!(false)),
            ("EnableIPv6", json!(false)),
            ("Internal", json!(true)),
            ("Attachable", json!(true)),
            ("Ingress", json!(true)),
            ("ConfigOnly", json!(true)),
            ("ConfigFrom", json!({"Network":"foreign"})),
            ("Containers", Value::Null),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            candidates.push(changed);
        }
        let mut absent = original.clone();
        absent.as_object_mut().unwrap().remove("Containers");
        candidates.push(absent);
        for label in [
            INSTALL_LABEL,
            SANDBOX_LABEL,
            PROFILE_LABEL,
            ROLE_LABEL,
            GENERATION,
            IDENTITY,
            PROVISION,
            EXPIRY_LABEL,
        ] {
            let mut changed = original.clone();
            changed["Labels"][label] = json!("foreign");
            candidates.push(changed);
        }
        for (option, value) in [
            ("com.docker.network.bridge.name", "ghforeign"),
            ("com.docker.network.bridge.enable_icc", "true"),
            ("com.docker.network.bridge.enable_ip_masquerade", "false"),
            ("com.docker.network.bridge.host_binding_ipv4", "0.0.0.0"),
            ("com.docker.network.bridge.gateway_mode_ipv4", "routed"),
            ("com.docker.network.bridge.gateway_mode_ipv6", "routed"),
            ("unconfigured-option", "true"),
        ] {
            let mut changed = original.clone();
            changed["Options"][option] = json!(value);
            candidates.push(changed);
        }
        for field in 0..6 {
            let mut changed = original.clone();
            let ipam = &mut changed["IPAM"];
            match field {
                0 => ipam["Driver"] = json!("foreign"),
                1 => ipam["Config"] = json!([]),
                2 => {
                    ipam["Config"][0]["Subnet"] = json!("192.0.2.0/24");
                    ipam["Config"][0]["Gateway"] = json!("192.0.2.1");
                }
                3 => ipam["Config"][0]["Gateway"] = json!("127.0.0.1"),
                4 => ipam["Config"][0]["AuxiliaryAddresses"] = json!({"hidden":"10.0.0.9"}),
                _ => ipam["Config"][0]["IPRange"] = json!("10.0.0.0/25"),
            }
            candidates.push(changed);
        }
        for changed in candidates {
            let parsed: NetworkInspect = serde_json::from_value(changed).unwrap();
            assert!(observe(&plan, &parsed).is_err());
        }
    }
}
impl NetworkPlan {
    pub fn validate(&self) -> Result<(), ApiError> {
        self.identity.validate()?;
        if self.provisioning_token.is_nil() {
            return Err(invalid());
        }
        Ok(())
    }
    fn labels(&self) -> HashMap<String, String> {
        HashMap::from([
            (
                INSTALL_LABEL.into(),
                self.identity.installation_id.to_string(),
            ),
            (SANDBOX_LABEL.into(), self.identity.sandbox_id.to_string()),
            (PROFILE_LABEL.into(), self.identity.profile.clone()),
            (ROLE_LABEL.into(), ROLE.into()),
            (GENERATION.into(), self.identity.generation.to_string()),
            (IDENTITY.into(), self.identity.digest()),
            (PROVISION.into(), self.provisioning_token.to_string()),
            (EXPIRY_LABEL.into(), self.expires_at.to_rfc3339()),
        ])
    }
    fn options(&self) -> HashMap<String, String> {
        HashMap::from([
            (
                "com.docker.network.bridge.name".into(),
                self.identity.bridge_name(),
            ),
            (
                "com.docker.network.bridge.enable_icc".into(),
                "false".into(),
            ),
            (
                "com.docker.network.bridge.enable_ip_masquerade".into(),
                "true".into(),
            ),
            (
                "com.docker.network.bridge.host_binding_ipv4".into(),
                "127.0.0.1".into(),
            ),
            (
                "com.docker.network.bridge.gateway_mode_ipv4".into(),
                "nat".into(),
            ),
            (
                "com.docker.network.bridge.gateway_mode_ipv6".into(),
                "nat".into(),
            ),
        ])
    }
    fn request(&self) -> NetworkCreateRequest {
        NetworkCreateRequest {
            name: self.identity.network_name(),
            driver: Some("bridge".into()),
            scope: Some("local".into()),
            internal: Some(false),
            attachable: Some(false),
            ingress: Some(false),
            config_only: Some(false),
            enable_ipv4: Some(true),
            enable_ipv6: Some(true),
            labels: Some(self.labels()),
            options: Some(self.options()),
            ipam: Some(Ipam {
                driver: Some("default".into()),
                config: Some(vec![IpamConfig {
                    subnet: Some(self.identity.ipv6_subnet()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NetworkObservation {
    pub network_id: String,
    pub ipv4_subnet: String,
    pub ipv4_gateway: Ipv4Addr,
    pub ipv6_subnet: String,
    pub ipv6_gateway: Ipv6Addr,
    pub attached_endpoints: usize,
    pub observed_at: DateTime<Utc>,
}
#[derive(Clone, Debug, Serialize)]
pub struct NetworkRemoval {
    pub network_id: Option<String>,
    pub provider_absent: bool,
    pub observed_at: DateTime<Utc>,
}
fn invalid() -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest, "invalid planned Docker network")
}
fn conflict() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "owned Docker network identity or scope differs",
    )
}
fn unknown() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "Docker network observation is incomplete",
    )
}
fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn observe(plan: &NetworkPlan, value: &NetworkInspect) -> Result<NetworkObservation, ApiError> {
    let id = value
        .id
        .as_deref()
        .filter(|id| valid_id(id))
        .ok_or_else(unknown)?;
    if value.name.as_deref() != Some(plan.identity.network_name().as_str())
        || value.driver.as_deref() != Some("bridge")
        || value.scope.as_deref() != Some("local")
        || value.enable_ipv4 != Some(true)
        || value.enable_ipv6 != Some(true)
        || value.internal != Some(false)
        || value.attachable != Some(false)
        || value.ingress != Some(false)
        || value.config_only != Some(false)
        || value
            .config_from
            .as_ref()
            .is_some_and(|c| c.network.as_ref().is_some_and(|name| !name.is_empty()))
        || value.labels.as_ref() != Some(&plan.labels())
        || value.options.as_ref() != Some(&plan.options())
    {
        return Err(conflict());
    }
    // Network list responses do not establish endpoint absence. Full inspection
    // must contain its actual endpoint map, including an explicit empty map.
    let containers = value.containers.as_ref().ok_or_else(unknown)?;
    if containers.len() > 4096 {
        return Err(unknown());
    }
    let ipam = value.ipam.as_ref().ok_or_else(unknown)?;
    if ipam.driver.as_deref() != Some("default")
        || ipam.options.as_ref().is_some_and(|m| !m.is_empty())
    {
        return Err(conflict());
    }
    let configs = ipam
        .config
        .as_ref()
        .filter(|c| c.len() == 2)
        .ok_or_else(unknown)?;
    let mut v4 = None;
    let mut v6 = None;
    for c in configs {
        if c.ip_range.as_ref().is_some_and(|s| !s.is_empty())
            || c.auxiliary_addresses
                .as_ref()
                .is_some_and(|m| !m.is_empty())
        {
            return Err(conflict());
        }
        let subnet = c
            .subnet
            .as_deref()
            .ok_or_else(unknown)?
            .parse::<IpNet>()
            .map_err(|_| unknown())?;
        let gateway = c
            .gateway
            .as_deref()
            .ok_or_else(unknown)?
            .parse::<IpAddr>()
            .map_err(|_| unknown())?;
        if subnet.addr() != subnet.network()
            || !subnet.contains(&gateway)
            || gateway == subnet.network()
        {
            return Err(conflict());
        }
        match (subnet, gateway) {
            (IpNet::V4(net), IpAddr::V4(ip))
                if v4.is_none()
                    && (8..=30).contains(&net.prefix_len())
                    && net.network().is_private()
                    && net.broadcast().is_private()
                    && ip != net.broadcast() =>
            {
                v4 = Some((net, ip))
            }
            (IpNet::V6(net), IpAddr::V6(ip))
                if v6.is_none() && net.to_string() == plan.identity.ipv6_subnet() =>
            {
                v6 = Some((net, ip))
            }
            _ => return Err(conflict()),
        }
    }
    let (net4, ip4) = v4.ok_or_else(unknown)?;
    let (net6, ip6) = v6.ok_or_else(unknown)?;
    Ok(NetworkObservation {
        network_id: id.into(),
        ipv4_subnet: net4.to_string(),
        ipv4_gateway: ip4,
        ipv6_subnet: net6.to_string(),
        ipv6_gateway: ip6,
        attached_endpoints: containers.len(),
        observed_at: Utc::now(),
    })
}

#[derive(Clone)]
pub struct DockerNetworkProvider {
    docker: Docker,
    writes: Arc<Mutex<()>>,
}
impl DockerNetworkProvider {
    /// Local socket/named pipe only; no daemon TCP or alternate runtime fallback.
    pub async fn connect() -> Result<Self, ApiError> {
        let docker = Docker::connect_with_socket_defaults()
            .map_err(backend)?
            .negotiate_version()
            .await
            .map_err(backend)?;
        let version = docker.version().await.map_err(backend)?;
        let api = version
            .api_version
            .as_deref()
            .and_then(|s| s.split_once('.'))
            .and_then(|(major, minor)| {
                Some((major.parse::<u16>().ok()?, minor.parse::<u16>().ok()?))
            });
        if version.os.as_deref() != Some("linux")
            || version.arch.as_deref() != Some("amd64")
            || api.is_none_or(|v| v < (1, 53))
        {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "owned bridge provider requires Linux x86_64 Docker API 1.53 or newer",
            ));
        }
        Ok(Self {
            docker,
            writes: Arc::new(Mutex::new(())),
        })
    }
    async fn inventory(&self, key: &str, value: &str) -> Result<Vec<Network>, ApiError> {
        let options = ListNetworksOptions {
            filters: Some(HashMap::from([(key.to_owned(), vec![value.to_owned()])])),
        };
        let rows = tokio::time::timeout(
            Duration::from_secs(15),
            self.docker.list_networks(Some(options)),
        )
        .await
        .map_err(|_| unknown())?
        .map_err(backend)?;
        if rows.len() > 4096 {
            return Err(unknown());
        }
        Ok(rows)
    }
    /// Recovery uses positive provider inventory and full inspection; it never
    /// creates a missing resource or infers absence from a failed inspection.
    pub async fn lookup(&self, plan: &NetworkPlan) -> Result<Option<NetworkObservation>, ApiError> {
        plan.validate()?;
        let name = plan.identity.network_name();
        let rows = self.inventory("name", &name).await?;
        let candidates = rows
            .iter()
            .filter(|n| n.name.as_deref() == Some(&name))
            .collect::<Vec<_>>();
        if candidates.len() > 1 {
            return Err(conflict());
        }
        let Some(candidate) = candidates.first() else {
            return Ok(None);
        };
        let id = candidate
            .id
            .as_deref()
            .filter(|id| valid_id(id))
            .ok_or_else(unknown)?;
        let actual = tokio::time::timeout(
            Duration::from_secs(15),
            self.docker.inspect_network(id, None),
        )
        .await
        .map_err(|_| unknown())?
        .map_err(backend)?;
        let observation = observe(plan, &actual)?;
        if observation.network_id != id {
            return Err(conflict());
        }
        Ok(Some(observation))
    }
    /// Only after a newly committed provisioning dispatch. Never call this to
    /// recover a lost response: lookup the journaled name and owner instead.
    pub async fn create_fresh(&self, plan: &NetworkPlan) -> Result<NetworkObservation, ApiError> {
        plan.validate()?;
        let remaining = plan.expires_at.signed_duration_since(Utc::now());
        if remaining <= chrono::Duration::zero() || remaining > chrono::Duration::days(1) {
            return Err(invalid());
        }
        let _serial = self.writes.lock().await;
        if self.lookup(plan).await?.is_some() {
            return Err(conflict());
        }
        let response = tokio::time::timeout(
            Duration::from_secs(30),
            self.docker.create_network(plan.request()),
        )
        .await
        .map_err(|_| unknown())?
        .map_err(backend)?;
        if !valid_id(&response.id) || !response.warning.is_empty() {
            return Err(unknown());
        }
        let observation = self.lookup(plan).await?.ok_or_else(unknown)?;
        if observation.network_id != response.id || observation.attached_endpoints != 0 {
            return Err(conflict());
        }
        Ok(observation)
    }
    /// Remove only a completely inspected owned empty network. This proves
    /// provider absence only; kernel bridge/table collection is a separate gate.
    pub async fn remove_empty(
        &self,
        plan: &NetworkPlan,
        expected_id: Option<&str>,
    ) -> Result<NetworkRemoval, ApiError> {
        plan.validate()?;
        if expected_id.is_some_and(|id| !valid_id(id)) {
            return Err(invalid());
        }
        let _serial = self.writes.lock().await;
        let actual = self.lookup(plan).await?;
        let mut collected = expected_id.map(str::to_owned);
        if let Some(actual) = actual {
            if expected_id.is_some_and(|id| id != actual.network_id)
                || actual.attached_endpoints != 0
            {
                return Err(conflict());
            }
            tokio::time::timeout(
                Duration::from_secs(30),
                self.docker.remove_network(&actual.network_id),
            )
            .await
            .map_err(|_| unknown())?
            .map_err(backend)?;
            collected = Some(actual.network_id);
        }
        if self.lookup(plan).await?.is_some() {
            return Err(unknown());
        }
        if let Some(id) = &collected
            && self
                .inventory("id", id)
                .await?
                .iter()
                .any(|n| n.id.as_deref() == Some(id))
        {
            return Err(unknown());
        }
        Ok(NetworkRemoval {
            network_id: collected,
            provider_absent: true,
            observed_at: Utc::now(),
        })
    }
}
