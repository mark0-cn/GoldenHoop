use goldenhoop_egress::{Allocation, Config, DnsBinding, DnsBindings, Plan};
use goldenhoop_protocol::{ErrorCode, NetworkAction, NetworkPolicy, NetworkRule};
use uuid::Uuid;

fn allocation() -> Allocation {
    Allocation {
        installation_id: Uuid::new_v4(),
        sandbox_id: Uuid::new_v4(),
        generation: Uuid::new_v4(),
        bridge: "ghtestbridge".into(),
        ifindex: 20,
    }
}

fn config(destination: &str) -> Config {
    Config {
        policies: vec![NetworkPolicy {
            default_action: NetworkAction::Deny,
            rules: vec![NetworkRule {
                destination: destination.into(),
                action: NetworkAction::Allow,
                ports: vec![],
            }],
        }],
        ..Config::default()
    }
}

#[test]
fn untrusted_allocation_text_cannot_become_a_kernel_command() {
    for bridge in [
        "eth0",
        "ghx\"\nflush ruleset",
        "ghfoo;",
        "gh/slash",
        "ghUPPER",
        "gh桥",
        "gh1234567890123456",
    ] {
        let mut scope = allocation();
        scope.bridge = bridge.into();
        assert!(Plan::quarantine(scope, 0).is_err());
    }
    for index in [0, u32::MAX] {
        let mut scope = allocation();
        scope.ifindex = index;
        assert!(Plan::quarantine(scope, 0).is_err());
    }
    let mut scope = allocation();
    scope.installation_id = Uuid::nil();
    assert!(Plan::quarantine(scope, 0).is_err());
}

#[test]
fn unsupported_names_and_invalid_policy_never_get_silently_widened() {
    for target in ["example.test", "*.example.test"] {
        let result = Plan::compile(allocation(), 1, &config(target));
        assert!(matches!(result, Err(e) if e.code == ErrorCode::UnsupportedCapability));
    }
    for target in [
        "192.0.2.1/24",
        "https://example.test",
        "*; accept",
        "::ffff:192.0.2.1/24",
    ] {
        assert!(Plan::compile(allocation(), 1, &config(target)).is_err());
    }
    assert!(Plan::compile(allocation(), 1, &Config::default()).is_err());
    let mut nested = config("192.0.2.0/24");
    nested.policies = vec![nested.policies[0].clone(); 6];
    assert!(Plan::compile(allocation(), 1, &nested).is_err());
    for target in ["192.0.2.0/24", "2001:db8::/32", "::ffff:192.0.2.1"] {
        assert!(Plan::compile(allocation(), 1, &config(target)).is_ok());
    }
}

#[test]
fn ownership_is_bound_to_every_allocation_field() {
    let original = allocation();
    let owner = original.owner();
    for field in 0..5 {
        let mut altered = original.clone();
        match field {
            0 => altered.installation_id = Uuid::new_v4(),
            1 => altered.sandbox_id = Uuid::new_v4(),
            2 => altered.generation = Uuid::new_v4(),
            3 => altered.bridge = "ghotherbridge".into(),
            _ => altered.ifindex += 1,
        }
        assert_ne!(owner, altered.owner());
    }
}

#[test]
fn dns_endpoint_families_and_ambiguous_local_addresses_cannot_widen_a_binding() {
    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "255.255.255.255",
        "224.0.0.1",
        "::",
        "::1",
        "ff02::1",
        "fe80::1",
        "::ffff:192.0.2.1",
    ] {
        assert!(
            DnsBinding::new(address.parse::<std::net::IpAddr>().unwrap(), 32000).is_err(),
            "{address}"
        );
    }
    let v4 = DnsBinding::new("192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap(), 32000).unwrap();
    let v6 = DnsBinding::new("fd42::1".parse::<std::net::Ipv6Addr>().unwrap(), 32001).unwrap();
    assert!(DnsBindings::new(v6.clone(), None).is_err());
    assert!(DnsBindings::new(v4.clone(), Some(v4.clone())).is_err());
    let bindings = DnsBindings::new(v4, Some(v6)).unwrap();
    assert_eq!(bindings.iter().count(), 2);
}
