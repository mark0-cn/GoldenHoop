use goldenhoop_egress::{
    Allocation, DestinationDefinition, DestinationListener, DestinationPlan, DestinationScope,
};
use serde_json::{Value, json};

fn capture() -> (Allocation, DestinationDefinition, Value) {
    let v: Value =
        serde_json::from_str(include_str!("fixtures/destination-kernel-table.json")).unwrap();
    (
        serde_json::from_value(v["input"]["allocation"].clone()).unwrap(),
        serde_json::from_value(v["input"]["definition"].clone()).unwrap(),
        v["observation"].clone(),
    )
}
#[test]
fn actual_native_destination_table_matches_ownership_infrastructure_and_pre_post_hooks() {
    let (a, definition, mut value) = capture();
    let plan = DestinationPlan::new(&a, &definition).unwrap();
    assert_eq!(
        DestinationPlan::descriptor(&a, &value).unwrap(),
        *plan.definition()
    );
    plan.verify(&a, &value).unwrap();
    for entry in value["nftables"].as_array_mut().unwrap() {
        if let Some(rule) = entry.get_mut("rule") {
            rule["handle"] = json!(12345);
            for expr in rule["expr"].as_array_mut().unwrap() {
                if let Some(counter) = expr.get_mut("counter") {
                    counter["packets"] = json!(9876);
                    counter["bytes"] = json!(123456);
                }
            }
        }
    }
    plan.verify(&a, &value).unwrap();
    let bad = DestinationDefinition {
        scope: DestinationScope::default(),
        dns: vec![DestinationListener {
            address: "192.0.2.1".parse().unwrap(),
            port: 15053,
        }],
    };
    assert!(DestinationPlan::new(&a, &bad).is_err());
    let bad = DestinationDefinition {
        scope: definition.scope.clone(),
        dns: vec![definition.dns[0].clone(); 2],
    };
    assert!(DestinationPlan::new(&a, &bad).is_err());
}
#[test]
fn native_destination_mutations_cannot_omit_guards_widen_exemptions_or_enable_dormancy() {
    let (a, definition, value) = capture();
    let plan = DestinationPlan::new(&a, &definition).unwrap();
    let mut candidates = Vec::new();
    let rows = value["nftables"].as_array().unwrap();
    let rules = rows
        .iter()
        .enumerate()
        .filter_map(|(i, v)| v.get("rule").map(|_| i))
        .collect::<Vec<_>>();
    let mut missing = value.clone();
    missing["nftables"].as_array_mut().unwrap().remove(rules[0]);
    candidates.push(missing);
    let mut reordered = value.clone();
    reordered["nftables"]
        .as_array_mut()
        .unwrap()
        .swap(rules[0], rules[1]);
    candidates.push(reordered);
    let mut dormant = value.clone();
    dormant["nftables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find_map(|v| v.get_mut("table"))
        .unwrap()["flags"] = json!(["dormant"]);
    candidates.push(dormant);
    let mut hook = value.clone();
    hook["nftables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .filter_map(|v| v.get_mut("chain"))
        .find(|v| v["name"] == "prerouting")
        .unwrap()["prio"] = json!(-104);
    candidates.push(hook);
    let mut owner = value.clone();
    owner["nftables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .filter_map(|v| v.get_mut("chain"))
        .find(|v| {
            v["name"]
                .as_str()
                .is_some_and(|s| s.starts_with("goldenhoop_"))
        })
        .unwrap()["name"] = json!("goldenhoop_foreign");
    candidates.push(owner);
    for kind in 0..4 {
        let mut changed = value.clone();
        let mut found = false;
        'rules: for entry in changed["nftables"].as_array_mut().unwrap() {
            let Some(rule) = entry.get_mut("rule") else {
                continue;
            };
            for part in rule["expr"].as_array_mut().unwrap() {
                if kind == 3 && part.get("drop").is_some() {
                    *part = json!({"accept":null});
                    found = true;
                    break 'rules;
                }
                let Some(m) = part.get_mut("match") else {
                    continue;
                };
                if kind == 0 && m["left"]["payload"]["field"] == "dport" {
                    m["right"] = json!(15054);
                } else if kind == 1 && m["right"] == "100.100.100.200" {
                    m["right"] = json!("100.100.100.201");
                } else if kind == 2 && m["right"]["prefix"]["addr"] == "10.20.0.0" {
                    m["right"] = json!({"prefix":{"addr":"10.0.0.0","len":8}});
                } else {
                    continue;
                }
                found = true;
                break 'rules;
            }
        }
        assert!(found);
        candidates.push(changed);
    }
    for candidate in candidates {
        assert!(plan.verify(&a, &candidate).is_err());
    }
}

#[test]
fn original_dns_and_neighbor_exemptions_cannot_be_widened_or_moved_after_translation() {
    let (a, definition, value) = capture();
    let plan = DestinationPlan::new(&a, &definition).unwrap();
    for field in ["nexthdr", "hoplimit", "type", "code", "dport"] {
        let mut changed = value.clone();
        let mut found = false;
        for rule in changed["nftables"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .filter_map(|e| e.get_mut("rule"))
            .filter(|r| r["chain"] == "prerouting")
        {
            if let Some(predicate) = rule["expr"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|e| e["match"]["left"]["payload"]["field"] == field)
            {
                predicate["match"]["right"] = json!(1);
                found = true;
                break;
            }
        }
        assert!(found, "missing independent {field} capture");
        assert!(
            plan.verify(&a, &changed).is_err(),
            "accepted widened {field}"
        );
    }
    let mut moved = value.clone();
    let original = moved["nftables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .filter_map(|e| e.get_mut("rule"))
        .find(|r| {
            r["chain"] == "prerouting"
                && r["expr"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["match"]["left"]["payload"]["field"] == "dport")
        })
        .unwrap();
    original["chain"] = json!("forward");
    assert!(plan.verify(&a, &moved).is_err());
}

#[test]
fn local_route_guard_cannot_limit_to_ingress_or_yield_to_private_exceptions() {
    let (a, definition, value) = capture();
    let plan = DestinationPlan::new(&a, &definition).unwrap();
    let index = value["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .position(|e| {
            e["rule"]["expr"].as_array().is_some_and(|parts| {
                parts
                    .iter()
                    .any(|p| p["match"]["left"].get("fib").is_some())
            })
        })
        .unwrap();
    let mut absent = value.clone();
    absent["nftables"].as_array_mut().unwrap().remove(index);
    assert!(plan.verify(&a, &absent).is_err());
    for flags in [json!(["daddr", "iif"]), json!(["saddr"]), json!([])] {
        let mut changed = value.clone();
        changed["nftables"][index]["rule"]["expr"][0]["match"]["left"]["fib"]["flags"] = flags;
        assert!(plan.verify(&a, &changed).is_err());
    }
    let mut reordered = value.clone();
    let exception = reordered["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .position(|e| e["rule"]["expr"][0]["match"]["right"]["prefix"]["addr"] == "10.20.0.0")
        .unwrap();
    reordered["nftables"]
        .as_array_mut()
        .unwrap()
        .swap(index, exception);
    assert!(plan.verify(&a, &reordered).is_err());
}

#[test]
fn historical_v1_descriptor_is_recognized_for_collection_but_never_a_current_guard() {
    let legacy: Value =
        serde_json::from_str(include_str!("fixtures/destination-kernel-v1-table.json")).unwrap();
    let a: Allocation = serde_json::from_value(legacy["input"]["allocation"].clone()).unwrap();
    let definition: DestinationDefinition =
        serde_json::from_value(legacy["input"]["definition"].clone()).unwrap();
    assert_eq!(
        DestinationPlan::descriptor(&a, &legacy["observation"]).unwrap(),
        definition
    );
    assert!(
        DestinationPlan::new(&a, &definition)
            .unwrap()
            .verify(&a, &legacy["observation"])
            .is_err()
    );
    for version in ["destination_version_3", "destination_version_0"] {
        let mut changed = legacy["observation"].clone();
        let chain = changed["nftables"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .filter_map(|e| e.get_mut("chain"))
            .find(|c| c["name"] == "destination_version_1")
            .unwrap();
        chain["name"] = json!(version);
        assert!(DestinationPlan::descriptor(&a, &changed).is_err());
    }
}
