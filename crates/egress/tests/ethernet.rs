use goldenhoop_egress::{Allocation, EthernetPlan};
use serde_json::{Value, json};
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

fn kernel_observation(a: &Allocation) -> Value {
    let table = a.ethernet_table();
    json!({"nftables":[
        {"metainfo":{"json_schema_version":1}},
        {"table":{"family":"bridge","name":table,"handle":90}},
        {"chain":{"family":"bridge","table":table,"name":a.owner_chain()}},
        {"chain":{"family":"bridge","table":table,"name":"guard_version_1"}},
        {"chain":{"family":"bridge","table":table,"name":"input","type":"filter","hook":"input","prio":-300,"policy":"accept"}},
        {"chain":{"family":"bridge","table":table,"name":"forward","type":"filter","hook":"forward","prio":-300,"policy":"accept"}},
        {"rule":{"family":"bridge","table":table,"chain":"input","expr":[
            {"match":{"op":"==","left":{"meta":{"key":"ibrname"}},"right":a.bridge}},
            {"match":{"op":"!=","left":{"payload":{"protocol":"ether","field":"type"}},"right":{"set":["ip6","arp","ip"]}}},
            {"counter":{"packets":10,"bytes":1000}}, {"drop":null}]}},
        {"rule":{"family":"bridge","table":table,"chain":"forward","expr":[
            {"match":{"op":"==","left":{"meta":{"key":"ibrname"}},"right":a.bridge}},
            {"counter":{"packets":20,"bytes":2000}}, {"drop":null}]}}
    ]})
}

#[test]
fn owned_ethernet_readback_checks_semantics_not_handles_or_counter_values() {
    let a = allocation();
    let mut observed = kernel_observation(&a);
    assert!(EthernetPlan::verify(&a, &observed).is_ok());
    observed["nftables"][6]["rule"]["expr"][1]["match"]["right"]["set"] =
        json!([34525, 2048, 2054]);
    observed["nftables"][7]["rule"]["expr"][1]["counter"]["packets"] = json!(999);
    assert!(EthernetPlan::verify(&a, &observed).is_ok());
    let mut foreign = a.clone();
    foreign.installation_id = Uuid::new_v4();
    assert!(EthernetPlan::verify(&foreign, &observed).is_err());
}

#[test]
fn missing_widened_or_injected_ethernet_rules_never_confirm_installation() {
    let a = allocation();
    let original = kernel_observation(&a);
    let changes = [
        ("/nftables/7/rule/expr/2", json!({"accept":null})),
        ("/nftables/7/rule/expr/0/match/right", json!("*")),
        ("/nftables/5/chain/hook", json!("input")),
        ("/nftables/5/chain/prio", json!(0)),
        ("/nftables/6/rule/expr/1/match/op", json!("==")),
        (
            "/nftables/6/rule/expr/1/match/right/set",
            json!(["arp", "ip", "ip6", "vlan"]),
        ),
        (
            "/nftables/7/rule/expr/1",
            json!({"counter":{"packets":1,"bytes":1},"accept":null}),
        ),
        ("/nftables/3/chain/name", json!("guard_version_2")),
    ];
    for (pointer, value) in changes {
        let mut altered = original.clone();
        *altered.pointer_mut(pointer).unwrap() = value;
        assert!(EthernetPlan::verify(&a, &altered).is_err(), "{pointer}");
    }
    let mut missing = original.clone();
    missing["nftables"].as_array_mut().unwrap().pop();
    assert!(EthernetPlan::verify(&a, &missing).is_err());
    let mut injected = original;
    let duplicate = injected["nftables"][7].clone();
    injected["nftables"].as_array_mut().unwrap().push(duplicate);
    assert!(EthernetPlan::verify(&a, &injected).is_err());
}
