use goldenhoop_egress::{DestinationClass as Class, DestinationScope, ProtectedDestinations};
use goldenhoop_protocol::ErrorCode;
use std::net::IpAddr;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn native_boundaries_and_standard_metadata_translation_vectors_remain_protected() {
    let floor = ProtectedDestinations::new(DestinationScope::default()).unwrap();
    for text in [
        "0.1.2.3",
        "127.255.255.255",
        "169.254.169.254",
        "224.0.0.1",
        "255.255.255.255",
        "100.100.100.200",
        "168.63.129.16",
        "::",
        "::1",
        "::ffff:8.8.8.8",
        "fe80::1",
        "febf:ffff::1",
        "fec0::1",
        "ff02::1",
        "fd00:ec2::254",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b:1:ffff::1",
    ] {
        assert_eq!(floor.classify(ip(text)), Class::Protected, "{text}");
    }
    for text in [
        "10.0.0.0",
        "172.31.255.255",
        "192.168.0.1",
        "100.64.0.0",
        "100.127.255.255",
        "fc00::1",
        "fdff:ffff::1",
    ] {
        assert_eq!(floor.classify(ip(text)), Class::PrivateDenied, "{text}");
    }
    for text in [
        "11.0.0.1",
        "172.32.0.1",
        "192.169.0.1",
        "100.128.0.1",
        "203.0.113.7",
        "2001:db8::7",
    ] {
        assert_eq!(floor.classify(ip(text)), Class::Other, "{text}");
    }
}

#[test]
fn trusted_private_exceptions_cannot_exempt_host_control_or_metadata_addresses() {
    let floor = ProtectedDestinations::new(DestinationScope {
        host_addresses: vec![ip("10.20.0.1"), ip("2001:db8::1")],
        control_addresses: vec![ip("10.20.0.8"), ip("fd42::8")],
        private_exceptions: vec![
            "10.20.0.0/16".into(),
            "fc00::/7".into(),
            "100.64.0.0/10".into(),
        ],
    })
    .unwrap();
    for text in [
        "10.20.0.1",
        "10.20.0.8",
        "fd42::8",
        "2001:db8::1",
        "fd00:ec2::254",
        "100.100.100.200",
    ] {
        assert_eq!(floor.classify(ip(text)), Class::Protected, "{text}");
    }
    for text in ["10.20.0.9", "fd42::9", "100.100.100.201"] {
        assert_eq!(floor.classify(ip(text)), Class::PrivateException, "{text}");
        assert!(!floor.classify(ip(text)).blocked());
    }
    assert!(floor.classify(ip("10.21.0.9")).blocked());
}

#[test]
fn private_scope_refuses_public_overbroad_noncanonical_or_command_text_exceptions() {
    for text in [
        "0.0.0.0/0",
        "8.8.8.0/24",
        "10.1.2.3/8",
        "172.0.0.0/8",
        "fe80::/10",
        "2001:db8::/32",
        "FC00::/7",
        "::ffff:10.0.0.0/104",
        "10.0.0.0/8;flush ruleset",
    ] {
        let result = ProtectedDestinations::new(DestinationScope {
            private_exceptions: vec![text.into()],
            ..Default::default()
        });
        assert!(
            matches!(result, Err(e) if e.code==ErrorCode::InvalidRequest),
            "{text}"
        );
    }
    assert!(
        ProtectedDestinations::new(DestinationScope {
            host_addresses: vec![ip("::ffff:192.0.2.1")],
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        matches!(ProtectedDestinations::new(DestinationScope { private_exceptions: vec!["10.0.0.0/8".into();33], ..Default::default() }),Err(e) if e.code==ErrorCode::QuotaExceeded)
    );
    let supplied = serde_json::json!({"host_addresses":[],"control_addresses":[],"private_exceptions":[],"allow_metadata":true});
    assert!(serde_json::from_value::<DestinationScope>(supplied).is_err());
}

#[test]
fn canonical_scope_digest_is_order_independent_and_changes_with_trusted_intent() {
    let scope = DestinationScope {
        host_addresses: vec![ip("192.0.2.2"), ip("192.0.2.1"), ip("192.0.2.1")],
        control_addresses: vec![ip("192.0.2.8")],
        private_exceptions: vec!["fd42::/16".into(), "10.0.0.0/8".into(), "10.0.0.0/8".into()],
    };
    let original = ProtectedDestinations::new(scope.clone()).unwrap();
    let mut reordered = scope.clone();
    reordered.host_addresses.reverse();
    reordered.private_exceptions.reverse();
    assert_eq!(
        original.digest(),
        ProtectedDestinations::new(reordered).unwrap().digest()
    );
    let mut changed = scope;
    changed.control_addresses.push(ip("192.0.2.9"));
    assert_ne!(
        original.digest(),
        ProtectedDestinations::new(changed).unwrap().digest()
    );
    let roundtrip = ProtectedDestinations::new(
        serde_json::from_value(serde_json::to_value(original.scope()).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(roundtrip.digest(), original.digest());
}
