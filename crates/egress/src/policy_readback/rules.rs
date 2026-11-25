use super::*;
use goldenhoop_policy::{Destination, Policy, Rule};
use goldenhoop_protocol::{NetworkAction, NetworkPolicy, NetworkRule};

fn matched(left: Value, right: Value) -> Value {
    json!({"match":{"op":"==","left":left,"right":right}})
}
fn meta(key: &str, right: Value) -> Value {
    matched(json!({"meta":{"key":key}}), right)
}
fn payload(protocol: &str, field: &str, right: Value) -> Value {
    matched(
        json!({"payload":{"protocol":protocol,"field":field}}),
        right,
    )
}
fn verdict(name: &str) -> Value {
    json!({name:null})
}
fn jump(target: &str) -> Value {
    json!({"jump":{"target":target}})
}

pub(super) fn expected(
    allocation: &Allocation,
    revision: u64,
    config: &Config,
    bindings: Option<&DnsBindings>,
    dns: Option<&SetNames>,
) -> Result<Shape, ApiError> {
    let mut s = Shape {
        chains: BTreeMap::new(),
        rules: BTreeMap::new(),
    };
    for name in [
        allocation.owner_chain(),
        format!("revision_{revision}"),
        "guard".into(),
        "decision".into(),
    ] {
        s.chain(&name, json!({}));
    }
    for name in ["input", "forward"] {
        s.chain(
            name,
            json!({"type":"filter","hook":name,"prio":-190,"policy":"accept"}),
        );
    }
    if let Some(token) = dns.and_then(SetNames::token) {
        s.chain(&format!("dns_txn_{}", token.simple()), json!({}));
    }
    let iif = meta("iif", json!(allocation.ifindex));
    s.rule(
        "input",
        vec![
            iif.clone(),
            payload("ip6", "hoplimit", json!(255)),
            payload("icmpv6", "type", json!({"set":[135,136]})),
            payload("icmpv6", "code", json!(0)),
            verdict("accept"),
        ],
    );
    if bindings.is_some() {
        for name in ["dns_pre", "dns_out"] {
            s.chain(name,json!({"type":"nat","hook":if name=="dns_pre"{"prerouting"}else{"output"},"prio":-110,"policy":"accept"}));
        }
    }
    for listener in bindings.into_iter().flat_map(DnsBindings::iter) {
        let family = if listener.address().is_ipv4() {
            "ip"
        } else {
            "ip6"
        };
        for protocol in ["udp", "tcp"] {
            let endpoint = vec![
                payload(family, "daddr", json!(listener.address())),
                payload(protocol, "dport", json!(listener.port())),
            ];
            for source in [iif.clone(), meta("iifname", json!("lo"))] {
                let mut rule = vec![source];
                rule.extend(endpoint.clone());
                rule.push(verdict("accept"));
                s.rule("input", rule);
            }
            let mut blocked = endpoint;
            blocked.push(verdict("drop"));
            s.rule("input", blocked);
            let dnat =
                json!({"dnat":{"addr":listener.address(),"port":listener.port(),"family":family}});
            s.rule(
                "dns_pre",
                vec![
                    meta(
                        "nfproto",
                        json!(if family == "ip" { "ipv4" } else { "ipv6" }),
                    ),
                    iif.clone(),
                    payload(protocol, "dport", json!(53)),
                    dnat.clone(),
                ],
            );
            s.rule(
                "dns_out",
                vec![
                    payload(family, "daddr", json!(listener.address())),
                    payload(protocol, "dport", json!(53)),
                    dnat,
                ],
            );
        }
    }
    s.rule("input", vec![iif.clone(), verdict("drop")]);
    s.rule(
        "forward",
        vec![
            iif,
            meta("iifname", json!(allocation.bridge)),
            jump("guard"),
        ],
    );
    s.rule(
        "guard",
        vec![meta("iifname", json!("@live")), jump("decision")],
    );
    s.rule("guard", vec![verdict("drop")]);
    if let Some(ports) = config.tcp_cap.as_ref().filter(|p| !p.is_empty()) {
        let ports = ports.iter().copied().collect::<BTreeSet<_>>();
        let mut port = payload("tcp", "dport", json!({"set":ports}));
        port["match"]["op"] = json!("!=");
        s.rule(
            "decision",
            vec![meta("l4proto", json!("tcp")), port, verdict("drop")],
        );
    }
    let overlay = |rules: &[NetworkRule]| {
        Policy::compile(&NetworkPolicy {
            default_action: NetworkAction::Deny,
            rules: rules.to_vec(),
        })
    };
    for (rules, decision) in [
        (&config.deny_always, "drop"),
        (&config.allow_always, "accept"),
    ] {
        for rule in overlay(rules)?.rules() {
            policy_rule(&mut s, "decision", rule, decision, dns.is_some())?;
        }
    }
    if let Some(dns) = dns {
        s.rule(
            "decision",
            vec![
                payload("ip", "daddr", json!(format!("@{}", dns.operator_v4()))),
                verdict("accept"),
            ],
        );
        s.rule(
            "decision",
            vec![
                payload("ip6", "daddr", json!(format!("@{}", dns.operator_v6()))),
                verdict("accept"),
            ],
        );
    }
    for (level, definition) in config.policies.iter().enumerate() {
        let policy = Policy::compile(definition)?;
        let name = format!("level_{level}");
        s.chain(&name, json!({}));
        s.rule("decision", vec![jump(&name)]);
        for rule in policy
            .rules()
            .iter()
            .filter(|r| r.action() == NetworkAction::Deny)
        {
            policy_rule(&mut s, &name, rule, "drop", dns.is_some())?;
        }
        if let Some(dns) = dns {
            s.rule(
                &name,
                vec![
                    payload("ip", "daddr", json!(format!("@{}", dns.user_v4()))),
                    verdict("return"),
                ],
            );
            s.rule(
                &name,
                vec![
                    payload("ip6", "daddr", json!(format!("@{}", dns.user_v6()))),
                    verdict("return"),
                ],
            );
        }
        for rule in policy
            .rules()
            .iter()
            .filter(|r| r.action() == NetworkAction::Allow)
        {
            policy_rule(&mut s, &name, rule, "return", dns.is_some())?;
        }
        s.rule(
            &name,
            vec![verdict(if policy.default_action() == NetworkAction::Deny {
                "drop"
            } else {
                "return"
            })],
        );
    }
    s.rule("decision", vec![verdict("accept")]);
    Ok(s)
}

fn policy_rule(
    s: &mut Shape,
    chain: &str,
    rule: &Rule,
    decision: &str,
    names_enabled: bool,
) -> Result<(), ApiError> {
    let mut expressions = Vec::new();
    match rule.destination() {
        Destination::Any => {}
        Destination::Address(ip) => expressions.push(payload(
            if ip.is_ipv4() { "ip" } else { "ip6" },
            "daddr",
            json!(ip),
        )),
        Destination::Network(network) => expressions.push(payload(
            if network.addr().is_ipv4() {
                "ip"
            } else {
                "ip6"
            },
            "daddr",
            json!({"prefix":{"addr":network.addr(),"len":network.prefix_len()}}),
        )),
        Destination::Domain(_) | Destination::Subdomains(_) => {
            if names_enabled {
                return Ok(());
            }
            return Err(error(
                ErrorCode::UnsupportedCapability,
                "policy domains require trusted DNS",
            ));
        }
    }
    if !rule.ports().is_empty() {
        expressions.push(meta("l4proto", json!("tcp")));
        expressions.push(payload("tcp", "dport", json!({"set":rule.ports()})));
    }
    expressions.push(verdict(decision));
    s.rule(chain, expressions);
    Ok(())
}
