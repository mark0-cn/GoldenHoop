use goldenhoop_egress::{Allocation, NetworkIdentity};
use uuid::Uuid;

#[test]
fn planned_identity_is_bounded_stable_and_isolated_across_each_owner_field() {
    let identity = NetworkIdentity {
        installation_id: Uuid::new_v4(),
        sandbox_id: Uuid::new_v4(),
        generation: Uuid::new_v4(),
        profile: "local-gvisor".into(),
    };
    identity.validate().unwrap();
    assert_eq!(identity.bridge_name().len(), 15);
    assert!(identity.network_name().len() <= 63);
    assert_eq!(identity.digest().len(), 64);
    let subnet: ipnet::IpNet = identity.ipv6_subnet().parse().unwrap();
    assert_eq!(subnet.prefix_len(), 64);
    assert!(
        "fc00::/7"
            .parse::<ipnet::IpNet>()
            .unwrap()
            .contains(&subnet)
    );
    assert_eq!(
        identity.digest(),
        serde_json::from_str::<NetworkIdentity>(&serde_json::to_string(&identity).unwrap())
            .unwrap()
            .digest()
    );
    Allocation {
        installation_id: identity.installation_id,
        sandbox_id: identity.sandbox_id,
        generation: identity.generation,
        bridge: identity.bridge_name(),
        ifindex: 1,
    }
    .validate()
    .unwrap();
    for field in 0..4 {
        let mut other = identity.clone();
        match field {
            0 => other.installation_id = Uuid::new_v4(),
            1 => other.sandbox_id = Uuid::new_v4(),
            2 => other.generation = Uuid::new_v4(),
            _ => other.profile = "local-runc-dev".into(),
        }
        other.validate().unwrap();
        assert_ne!(other.digest(), identity.digest());
        assert_ne!(other.ipv6_subnet(), identity.ipv6_subnet());
    }
    for profile in ["", "../bad/name", "a\nrole", "角色", &"a".repeat(129)] {
        let mut bad = identity.clone();
        bad.profile = profile.into();
        assert!(bad.validate().is_err());
    }
    let mut bad = identity.clone();
    bad.generation = Uuid::nil();
    assert!(bad.validate().is_err());
    assert!(serde_json::from_value::<NetworkIdentity>(serde_json::json!({"installation_id":identity.installation_id,"sandbox_id":identity.sandbox_id,"generation":identity.generation,"profile":identity.profile,"runtime":"host"})).is_err());
}
