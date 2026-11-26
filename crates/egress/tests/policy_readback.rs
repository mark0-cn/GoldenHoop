//! Actual kernel captures; mutations and monotonic clocks below are models.
use goldenhoop_egress::{
    Allocation, Config, DestinationListener, DnsBinding, DnsBindings, dns::SetNames,
    policy_readback,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct Fixture {
    observations: Vec<Sample>,
}
#[derive(Deserialize)]
struct Sample {
    mode: String,
    input: Input,
    native: Value,
    #[serde(default)] // JSON-display captures do not establish a textual lease.
    native_text: String,
}
#[derive(Deserialize)]
struct Input {
    allocation: Allocation,
    revision: u64,
    config: Config,
    dns_enabled: bool,
    dns: Vec<DestinationListener>,
    dns_token: Option<uuid::Uuid>,
}
fn samples() -> Vec<Sample> {
    serde_json::from_str::<Fixture>(include_str!("fixtures/effective-policy-kernel-tables.json"))
        .unwrap()
        .observations
}
fn verify(sample: &Sample, native: &Value) -> bool {
    let i = &sample.input;
    let bindings = i
        .dns
        .first()
        .map(|v4| {
            DnsBindings::new(
                DnsBinding::new(v4.address, v4.port).unwrap(),
                i.dns
                    .get(1)
                    .map(|v6| DnsBinding::new(v6.address, v6.port).unwrap()),
            )
        })
        .transpose()
        .unwrap();
    let names = i
        .dns_token
        .map(|id| SetNames::staged(id).unwrap())
        .or_else(|| i.dns_enabled.then(SetNames::bootstrap));
    policy_readback::verify_structure(
        &i.allocation,
        i.revision,
        &i.config,
        bindings.as_ref(),
        names.as_ref(),
        native,
    )
    .is_ok()
}
fn row<'a>(value: &'a mut Value, kind: &str, name: &str) -> &'a mut Value {
    value["nftables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find_map(|row| {
            row.get_mut(kind)
                .filter(|row| row["name"] == name || row["chain"] == name)
        })
        .unwrap()
}
#[test]
fn actual_static_bootstrap_staged_dns_and_deny_only_kernel_tables_match() {
    let samples = samples();
    assert_eq!(samples.len(), 4);
    for sample in samples {
        assert!(verify(&sample, &sample.native), "{}", sample.mode);
    }
}
#[test]
fn paired_native_symbolic_and_numeric_code_zero_preserve_the_same_strict_policy() {
    let capture: Fixture = serde_json::from_str(include_str!(
        "fixtures/policy-symbolic-numeric-kernel-tables.json"
    ))
    .unwrap();
    assert_eq!(capture.observations.len(), 2);
    for sample in capture.observations {
        assert!(verify(&sample, &sample.native), "{}", sample.mode);
        for code in [json!(1), json!("addr-unreachable"), json!({"set":[0,1]})] {
            let mut changed = sample.native.clone();
            let expression = changed["nftables"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .filter_map(|row| row.get_mut("rule"))
                .filter_map(|rule| rule["expr"].as_array_mut())
                .flatten()
                .find(|expression| {
                    expression["match"]["left"]
                        == json!({"payload":{"protocol":"icmpv6","field":"code"}})
                })
                .unwrap();
            expression["match"]["right"] = code;
            assert!(!verify(&sample, &changed));
        }
    }
}
#[test]
fn changed_policy_authority_hooks_order_dns_and_live_set_are_refused() {
    let sample = samples().into_iter().find(|s| s.mode == "dns").unwrap();
    for case in 0..27 {
        let mut v = sample.native.clone();
        match case {
            0 => row(&mut v, "rule", "decision")["expr"] = json!([{"accept":null}]),
            1 => row(&mut v, "chain", "forward")["prio"] = json!(-189),
            2 => row(&mut v, "chain", "dns_pre")["hook"] = json!("output"),
            3 => row(&mut v, "chain", "input")["policy"] = json!("drop"),
            4 => {
                row(&mut v, "set", "live")["elem"] =
                    json!([{"elem":{"val":sample.input.allocation.bridge,"expires":11}}])
            }
            5 => {
                row(&mut v, "set", "live")["elem"][0]["elem"]
                    .as_object_mut()
                    .unwrap()
                    .remove("expires");
            }
            6 => row(&mut v, "set", "live")["elem"][0]["elem"]["val"] = json!("ghforeign"),
            7 => row(&mut v, "set", "live")["flags"] = json!(["timeout", "dynamic"]),
            8 => row(&mut v, "set", "dns_u4")["type"] = json!("ipv6_addr"),
            9 => row(&mut v, "set", "dns_o6")["timeout"] = json!(300),
            10 => {
                row(&mut v, "rule", "level_0")["expr"][0]["match"]["right"] =
                    json!({"prefix":{"addr":"198.51.100.0","len":25}})
            }
            11 => row(&mut v, "rule", "level_0")["expr"][1]["match"]["right"] = json!({"set":[80]}),
            12 => row(&mut v, "rule", "guard")["expr"][1]["jump"]["target"] = json!("input"),
            13 => row(&mut v, "rule", "input")["expr"][0]["match"]["op"] = json!("!="),
            14 => row(&mut v, "chain", "revision_3")["name"] = json!("revision_4"),
            15 => {
                row(&mut v, "chain", &sample.input.allocation.owner_chain())["name"] =
                    json!("foreign_owner")
            }
            16 => row(&mut v, "rule", "dns_pre")["expr"][3]["dnat"]["port"] = json!(40103),
            17 => {
                row(&mut v, "table", &sample.input.allocation.table())["flags"] = json!(["dormant"])
            }
            18 => v["nftables"].as_array_mut().unwrap().push(
                json!({"flowtable":{"family":"inet","table":sample.input.allocation.table()}}),
            ),
            19 => {
                let extra = row(&mut v, "rule", "decision").clone();
                v["nftables"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"rule":extra}));
            }
            20 => v["nftables"]
                .as_array_mut()
                .unwrap()
                .retain(|r| r.get("rule").is_none_or(|r| r["chain"] != "level_1")),
            21 => {
                row(&mut v, "rule", "level_0")["expr"] = json!([{"match":{"left":{"meta":{"key":"l4proto"}},"op":"==","right":17}},{"accept":null}])
            }
            22 => row(&mut v, "rule", "input")["expr"] = json!([0]),
            23 => row(&mut v, "rule", "input")["expr"] = json!([{"match":{"left":null,"right":3}}]),
            24 => {
                row(&mut v, "rule", "input")["expr"] = json!([{"match":{"left":{"meta":{"key":"iif"}},"right":sample.input.allocation.bridge,"op":"=="}},null])
            }
            25 => {
                row(&mut v, "rule", "input")["expr"] = json!([{"match":{"left":{"payload":{"protocol":"icmpv6","field":"type"}},"right":3,"op":"=="}}])
            }
            _ => {
                row(&mut v, "rule", "input")["expr"] =
                    json!([{"counter":{"packets":0,"bytes":0,"foreign":true}},{"accept":null}])
            }
        }
        assert!(!verify(&sample, &v), "mutation {case}");
    }
}
#[test]
fn staged_dns_token_and_each_timed_source_declaration_are_bound_to_actual_authority() {
    let sample = samples()
        .into_iter()
        .find(|s| s.mode == "staged-dns")
        .unwrap();
    let token = sample.input.dns_token.unwrap().simple().to_string();
    for case in 0..5 {
        let mut v = sample.native.clone();
        let name = format!("d_{token}_u4");
        match case {
            0 => row(&mut v, "set", &name)["elem"][0]["elem"]["timeout"] = json!(301),
            1 => {
                row(&mut v, "set", &name)["elem"][0]["elem"]
                    .as_object_mut()
                    .unwrap()
                    .remove("expires");
            }
            2 => row(&mut v, "set", &name)["elem"][0]["elem"]["val"] = json!("fd42::2"),
            3 => {
                row(&mut v, "chain", &format!("dns_txn_{token}"))["name"] = json!("dns_txn_foreign")
            }
            _ => row(&mut v, "set", &name)["name"] = json!("d_foreign_u4"),
        }
        assert!(!verify(&sample, &v), "mutation {case}");
    }
}
#[test]
fn precise_native_live_expiry_is_bounded_by_original_deadline_and_read_latency() {
    let sample = samples().remove(0);
    let start = Instant::now();
    let end = start + Duration::from_millis(1);
    let until = policy_readback::verify_native_lease(
        &sample.input.allocation,
        &sample.native_text,
        start,
        end,
        None,
    )
    .unwrap();
    assert!(until > end && until < start + Duration::from_secs(10));
    for candidate in [
        sample.native_text.replace("timeout 10s", "timeout 11s"),
        sample
            .native_text
            .replace("type ifname", "type ifname\n\t\tflags interval"),
        sample.native_text.replace("expires ", "remaining "),
        sample.native_text.replace(
            &format!("\"{}\"", sample.input.allocation.bridge),
            "\"ghforeign\"",
        ),
    ] {
        assert!(
            policy_readback::verify_native_lease(
                &sample.input.allocation,
                &candidate,
                start,
                end,
                None
            )
            .is_err()
        );
    }
    assert!(
        policy_readback::verify_native_lease(
            &sample.input.allocation,
            &sample.native_text,
            start,
            start + Duration::from_secs(11),
            None
        )
        .is_err()
    );
    assert!(
        policy_readback::verify_native_lease(
            &sample.input.allocation,
            &sample.native_text,
            start,
            end,
            Some(end + Duration::from_secs(1))
        )
        .is_err()
    );
}

#[test]
fn periodic_dns_observation_allows_only_a_subset_of_original_source_authority() {
    use goldenhoop_egress::dns::{Authority, KernelLease, StagedSets};
    let sample = samples()
        .into_iter()
        .find(|s| s.mode == "staged-dns")
        .unwrap();
    let start = Instant::now();
    let end = start + Duration::from_millis(1);
    let mut members = vec![
        KernelLease {
            authority: Authority::User,
            address: "192.0.2.2".parse().unwrap(),
            expires_at: start + Duration::from_secs(20),
        },
        KernelLease {
            authority: Authority::OperatorAllow,
            address: "2001:db8::2".parse().unwrap(),
            expires_at: start + Duration::from_secs(20),
        },
        KernelLease {
            authority: Authority::User,
            address: "203.0.113.2".parse().unwrap(),
            expires_at: start + Duration::from_secs(20),
        },
    ];
    let names = SetNames::staged(sample.input.dns_token.unwrap()).unwrap();
    let observation =
        StagedSets::observation(&sample.input.allocation, names.clone(), &members).unwrap();
    observation
        .confirm_current_native(&sample.native_text, start, end)
        .unwrap();
    let mut short = sample.native_text.clone();
    let fields = sample.native_text.split_whitespace().collect::<Vec<_>>();
    for pair in fields.windows(2) {
        if pair[0] == "expires" {
            short = short.replace(pair[1], "1ms");
        }
    }
    let subset =
        StagedSets::observation(&sample.input.allocation, names.clone(), &members[..2]).unwrap();
    subset.confirm_current_native(&short, start, end).unwrap();
    assert!(
        subset.confirm_native(&short, start, end).is_err(),
        "an expiring observation cannot acknowledge a new grant"
    );
    assert!(
        observation
            .confirm_native(&sample.native_text, start, end)
            .is_err(),
        "a partial observation cannot acknowledge a new grant"
    );
    members[0].authority = Authority::OperatorAllow;
    assert!(
        StagedSets::observation(&sample.input.allocation, names.clone(), &members)
            .unwrap()
            .confirm_current_native(&sample.native_text, start, end)
            .is_err()
    );
    members[0].authority = Authority::User;
    members[0].expires_at = end + Duration::from_millis(1);
    assert!(
        StagedSets::observation(&sample.input.allocation, names, &members)
            .unwrap()
            .confirm_current_native(&sample.native_text, start, end)
            .is_err()
    );
}

#[test]
fn private_policy_inspection_cannot_supply_expiry_lease_or_missing_guard_authority() {
    use goldenhoop_egress::controller::Request;
    let request = json!({"operation":"inspect_policy","expected_revision":3});
    serde_json::from_value::<Request>(request.clone()).unwrap();
    for (name, value) in [
        ("expires_at", json!("2099-01-01T00:00:00Z")),
        ("lease_remaining_milliseconds", json!(10000)),
        ("allow_missing_guards", json!(true)),
        ("config_sha256", json!("a".repeat(64))),
    ] {
        let mut wrong = request.clone();
        wrong[name] = value;
        assert!(serde_json::from_value::<Request>(wrong).is_err());
    }
}
