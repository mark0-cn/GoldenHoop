use goldenhoop_egress::{Allocation, Endpoint, Mac, SourcePlan, SourceScope};
use goldenhoop_protocol::ErrorCode;
use uuid::Uuid;

fn allocation() -> Allocation {
    Allocation {
        installation_id: Uuid::new_v4(),
        sandbox_id: Uuid::new_v4(),
        generation: Uuid::new_v4(),
        bridge: "ghsourcebridge".into(),
        ifindex: 10,
    }
}
fn scope() -> SourceScope {
    SourceScope {
        endpoint: Endpoint {
            port: "veth1234".into(),
            ifindex: 20,
            mac: "02:25:96:12:34:56".parse().unwrap(),
            ipv4: "192.0.2.2".parse().unwrap(),
            ipv6: Some("fd42::2".parse().unwrap()),
        },
        gateway_mac: "02:01:02:03:04:05".parse().unwrap(),
        gateway4: "192.0.2.1".parse().unwrap(),
        gateway6: Some("fd42::1".parse().unwrap()),
    }
}
#[test]
fn canonical_mac_and_link_local_binding_have_independent_byte_vectors() {
    let address = "00:25:96:12:34:56".parse::<Mac>().unwrap();
    assert_eq!(address.to_string(), "00:25:96:12:34:56");
    assert_eq!(address.link_local().to_string(), "fe80::225:96ff:fe12:3456");
    for text in [
        "",
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
        "01:02:03:04:05:06",
        "2:25:96:12:34:56",
        "02:25:96:12:34:zz",
        "02:25:96:12:34:56;drop",
    ] {
        assert!(
            matches!(text.parse::<Mac>(),Err(e) if e.code==ErrorCode::InvalidRequest),
            "{text}"
        );
    }
}
#[test]
fn endpoint_scope_rejects_command_text_self_impersonation_and_family_mismatch() {
    let a = allocation();
    let original = scope();
    assert!(SourcePlan::new(&a, &original).is_ok());
    for text in [
        "../eth0",
        "veth;accept",
        "veth\nflush ruleset",
        "ghsourcebridge",
        "a",
    ] {
        let mut candidate = original.clone();
        candidate.endpoint.port = text.into();
        assert!(SourcePlan::new(&a, &candidate).is_err());
    }
    for index in [0, u32::MAX, a.ifindex] {
        let mut candidate = original.clone();
        candidate.endpoint.ifindex = index;
        assert!(SourcePlan::new(&a, &candidate).is_err());
    }
    for index in 0..5 {
        let mut candidate = original.clone();
        match index {
            0 => candidate.endpoint.mac = candidate.gateway_mac,
            1 => candidate.endpoint.ipv4 = candidate.gateway4,
            2 => candidate.endpoint.ipv6 = candidate.gateway6,
            3 => candidate.endpoint.ipv6 = None,
            _ => candidate.endpoint.ipv6 = Some("::ffff:192.0.2.2".parse().unwrap()),
        }
        assert!(SourcePlan::new(&a, &candidate).is_err());
    }
    let encoded = serde_json::to_value(&original).unwrap();
    let mut supplied = encoded["endpoint"].clone();
    supplied["allow_spoofing"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Endpoint>(supplied).is_err());
    let mut foreign = original;
    foreign.endpoint.mac = "02:25:96:12:34:57".parse().unwrap();
    assert_ne!(foreign.digest(), scope().digest());
}
