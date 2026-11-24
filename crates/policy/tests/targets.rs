use goldenhoop_policy::{Destination, Domain, MAX_PORTS_PER_RULE, MAX_RULES, Policy};
use goldenhoop_protocol::{ErrorCode, NetworkAction, NetworkPolicy, NetworkRule};
use std::net::{IpAddr, Ipv4Addr};

fn policy(destination: &str, ports: Vec<u16>) -> NetworkPolicy {
    NetworkPolicy {
        default_action: NetworkAction::Deny,
        rules: vec![NetworkRule {
            destination: destination.into(),
            ports,
            action: NetworkAction::Allow,
        }],
    }
}

#[test]
fn idna_mapping_dns_bounds_and_real_world_hyphens_are_preserved() {
    for (source, expected) in [
        ("BÜCHER.Example.", "xn--bcher-kva.example"),
        ("例え。テスト。", "xn--r8jz45g.xn--zckzah"),
        ("foo--bar.GitHub.io", "foo--bar.github.io"),
        ("EXAMPLE.com", "example.com"),
    ] {
        let name = Domain::parse(source).unwrap();
        assert_eq!(name.as_str(), expected);
        assert_eq!(Domain::parse(name.as_str()).unwrap(), name);
    }
    let longest = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(longest.len(), 253);
    assert!(Domain::parse(&longest).is_ok());
    assert!(Domain::parse(&(longest + "x")).is_err());
}

#[test]
fn shortened_integer_hex_octal_and_unicode_numeric_hosts_cannot_be_names() {
    for value in [
        "127.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "127.0.0.01",
        "127.0.0.0x1",
        "example.123",
        "example.0Xff",
        "１２７.０.０.１",
    ] {
        assert!(Destination::parse(value).is_err(), "{value}");
    }
    assert_eq!(
        Destination::parse("127.0.0.1.").unwrap(),
        Destination::Address(IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    assert!(Domain::parse("127.0.0.1").is_err());
}

#[test]
fn wildcard_matching_requires_a_complete_subdomain_label_and_excludes_the_apex() {
    let base = Domain::parse("Example.com.").unwrap();
    for name in ["a.example.com", "b.a.example.com"] {
        assert!(Domain::parse(name).unwrap().is_subdomain_of(&base));
    }
    for name in ["example.com", "notexample.com", "example.com.evil.test"] {
        assert!(!Domain::parse(name).unwrap().is_subdomain_of(&base));
    }
    assert_eq!(
        Destination::parse("*.EXAMPLE.com.").unwrap(),
        Destination::Subdomains(base)
    );
    for bad in [
        "*example.com",
        "a.*.example.com",
        "*.192.0.2.1",
        "*.*.example.com",
    ] {
        assert!(Destination::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn address_and_cidr_canonicalization_does_not_hide_mapped_ipv4_or_host_bits() {
    assert_eq!(
        Destination::parse("::ffff:127.0.0.1").unwrap(),
        Destination::Address(IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    assert_eq!(
        Destination::parse("::ffff:192.0.2.0/120").unwrap(),
        Destination::parse("192.0.2.0/24").unwrap()
    );
    assert!(matches!(
        Destination::parse("2001:db8::/32").unwrap(),
        Destination::Network(_)
    ));
    for bad in [
        "192.0.2.1/24",
        "2001:db8::1/64",
        "::ffff:192.0.2.128/120",
        "::ffff:0:0/80",
        "[::1]",
        "fe80::1%eth0",
        "192.0.2.0/33",
        "::/129",
    ] {
        assert!(Destination::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn malformed_uri_control_label_and_length_inputs_are_refused_without_echoing_them() {
    for bad in [
        "",
        ".",
        "example..com",
        "example.com..",
        "-bad.test",
        "bad-.test",
        "_bad.test",
        "https://user:private-secret@example.test/path",
        "example.test:443",
        "example.test/path",
        "example\n.test",
        "example\0.test",
        " example.test",
        "example.test ",
        "[::1]:443",
    ] {
        let error = Destination::parse(bad).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert!(!error.message.contains("private-secret"));
    }
    assert!(Destination::parse(&("a".repeat(64) + ".test")).is_err());
    assert!(Destination::parse(&"a".repeat(1025)).is_err());
    assert!(Domain::parse("example\t.test").is_err());
}

#[test]
fn compiled_rules_preserve_actions_and_bound_port_scope_to_supported_targets() {
    let compiled = Policy::compile(&policy("192.0.2.0/24", vec![443, 80, 443])).unwrap();
    assert_eq!(compiled.default_action(), NetworkAction::Deny);
    assert_eq!(compiled.rules()[0].action(), NetworkAction::Allow);
    assert_eq!(
        compiled.rules()[0]
            .ports()
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        vec![80, 443]
    );
    assert_eq!(
        compiled.rules()[0].destination(),
        &Destination::parse("192.0.2.0/24").unwrap()
    );
    assert!(Policy::compile(&policy("*", vec![443])).is_ok());
    assert!(Policy::compile(&policy("example.com", vec![])).is_ok());
    for name in ["example.com", "*.example.com"] {
        assert_eq!(
            Policy::compile(&policy(name, vec![443])).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }
    assert_eq!(
        Policy::compile(&policy("192.0.2.1", vec![0]))
            .unwrap_err()
            .code,
        ErrorCode::InvalidRequest
    );
}

#[test]
fn raw_rule_and_port_budgets_are_checked_before_canonical_deduplication() {
    let rule = policy("*", vec![443]).rules.remove(0);
    let mut value = NetworkPolicy {
        default_action: NetworkAction::Allow,
        rules: vec![rule; MAX_RULES],
    };
    assert!(Policy::compile(&value).is_ok());
    value.rules.push(value.rules[0].clone());
    assert_eq!(
        Policy::compile(&value).unwrap_err().code,
        ErrorCode::QuotaExceeded
    );
    assert!(Policy::compile(&policy("*", (1..=MAX_PORTS_PER_RULE as u16).collect())).is_ok());
    assert_eq!(
        Policy::compile(&policy("*", vec![443; MAX_PORTS_PER_RULE + 1]))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
}
