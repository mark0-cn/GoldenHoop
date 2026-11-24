use goldenhoop_policy::*;
use goldenhoop_protocol::{NetworkAction as A, NetworkPolicy, NetworkRule};

fn rule(destination: &str, ports: &[u16], action: A) -> NetworkRule {
    NetworkRule {
        destination: destination.into(),
        ports: ports.to_vec(),
        action,
    }
}
fn policy(default: A, rules: Vec<NetworkRule>) -> Policy {
    Policy::compile(&NetworkPolicy {
        default_action: default,
        rules,
    })
    .unwrap()
}
fn model(default: A, rules: Vec<NetworkRule>) -> Model {
    Model::new(vec![policy(default, rules)], Overlays::default()).unwrap()
}
fn packet(address: &str, transport: Transport, port: Option<u16>) -> Packet {
    Packet::new(address.parse().unwrap(), transport, port).unwrap()
}

#[test]
fn a_user_deny_wins_over_a_broader_allow_in_either_rule_order() {
    let allow = rule("*.example.test", &[], A::Allow);
    let deny = rule("blocked.example.test", &[], A::Deny);
    for rules in [vec![allow.clone(), deny.clone()], vec![deny, allow]] {
        let p = model(A::Deny, rules);
        assert_eq!(
            p.dns_candidate(&Domain::parse("ok.example.test").unwrap())
                .action,
            A::Allow
        );
        assert_eq!(
            p.dns_candidate(&Domain::parse("blocked.example.test").unwrap())
                .action,
            A::Deny
        );
        assert_eq!(
            p.dns_candidate(&Domain::parse("example.test").unwrap())
                .action,
            A::Deny
        );
        assert_eq!(
            p.dns_candidate(&Domain::parse("badexample.test").unwrap())
                .action,
            A::Deny
        );
    }
}

#[test]
fn port_only_and_address_allows_do_not_resolve_names_or_admit_udp() {
    let p = model(
        A::Deny,
        vec![
            rule("*", &[443], A::Allow),
            rule("192.0.2.0/24", &[22], A::Allow),
        ],
    );
    assert_eq!(
        p.dns_candidate(&Domain::parse("example.test").unwrap())
            .action,
        A::Deny
    );
    assert_eq!(
        p.address_candidate(&packet("192.0.2.3", Transport::Tcp, Some(443)))
            .action,
        A::Allow
    );
    assert_eq!(
        p.address_candidate(&packet("192.0.2.3", Transport::Tcp, Some(22)))
            .action,
        A::Allow
    );
    assert_eq!(
        p.address_candidate(&packet("192.0.2.3", Transport::Udp, Some(443)))
            .action,
        A::Deny
    );
    let names = model(A::Deny, vec![rule("example.test", &[], A::Allow)]);
    assert_eq!(
        names
            .dns_candidate(&Domain::parse("example.test").unwrap())
            .action,
        A::Allow
    );
    assert_eq!(
        names
            .address_candidate(&packet("192.0.2.3", Transport::Tcp, Some(443)))
            .action,
        A::Deny
    );
}

#[test]
fn operator_deny_allow_and_tcp_cap_follow_their_authority_order() {
    let user = policy(A::Deny, vec![rule("*", &[], A::Deny)]);
    let overlay = Overlays::compile(
        &[rule("127.0.0.0/8", &[], A::Deny)],
        &[rule("*", &[], A::Allow)],
        Some(&[443]),
    )
    .unwrap();
    let p = Model::new(vec![user], overlay).unwrap();
    assert_eq!(
        p.address_candidate(&packet("127.0.0.1", Transport::Tcp, Some(443)))
            .origin,
        DecisionOrigin::DenyAlways(0)
    );
    assert_eq!(
        p.address_candidate(&packet("192.0.2.1", Transport::Tcp, Some(443)))
            .origin,
        DecisionOrigin::AllowAlways(0)
    );
    assert_eq!(
        p.address_candidate(&packet("192.0.2.1", Transport::Tcp, Some(80)))
            .origin,
        DecisionOrigin::PortFloor
    );
    assert_eq!(
        p.address_candidate(&packet("192.0.2.1", Transport::Udp, Some(80)))
            .origin,
        DecisionOrigin::AllowAlways(0)
    );
    assert_eq!(
        p.address_candidate(&packet("::ffff:127.0.0.1", Transport::Tcp, Some(443)))
            .origin,
        DecisionOrigin::DenyAlways(0)
    );
    assert!(Overlays::compile(&[rule("*", &[], A::Allow)], &[], None).is_err());
    assert!(Overlays::compile(&[], &[], Some(&[0])).is_err());
}

#[test]
fn user_layers_intersect_and_missing_hierarchy_never_means_unrestricted() {
    let root = policy(A::Deny, vec![rule("*.example.test", &[], A::Allow)]);
    let child = policy(A::Deny, vec![rule("one.example.test", &[], A::Allow)]);
    let p = Model::new(vec![root.clone(), child], Overlays::default()).unwrap();
    assert_eq!(
        p.dns_candidate(&Domain::parse("one.example.test").unwrap())
            .action,
        A::Allow
    );
    assert_eq!(
        p.dns_candidate(&Domain::parse("two.example.test").unwrap())
            .origin,
        DecisionOrigin::UserDeny {
            level: 1,
            rule: None
        }
    );
    assert!(Model::new(vec![], Overlays::default()).is_err());
    assert!(Model::new(vec![root; 6], Overlays::default()).is_err());
}

#[test]
fn transport_shape_is_validated_and_empty_operator_cap_means_no_floor() {
    for (transport, port) in [
        (Transport::Tcp, None),
        (Transport::Udp, None),
        (Transport::Tcp, Some(0)),
        (Transport::Other, Some(443)),
    ] {
        assert!(Packet::new("192.0.2.1".parse().unwrap(), transport, port).is_err());
    }
    let p = Model::new(
        vec![policy(A::Allow, vec![rule("*", &[25], A::Deny)])],
        Overlays::compile(&[], &[], Some(&[])).unwrap(),
    )
    .unwrap();
    assert_eq!(
        p.address_candidate(&packet("192.0.2.1", Transport::Tcp, Some(25)))
            .action,
        A::Deny
    );
    assert_eq!(
        p.address_candidate(&packet("192.0.2.1", Transport::Udp, Some(25)))
            .action,
        A::Allow
    );
    assert_eq!(
        p.address_candidate(&packet("192.0.2.1", Transport::Other, None))
            .action,
        A::Allow
    );
}
