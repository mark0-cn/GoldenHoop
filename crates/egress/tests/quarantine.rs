//! Real local nftables snapshot; mutations model weakened or foreign state.
use goldenhoop_egress::{Allocation, DestinationListener, DnsBinding, DnsBindings, quarantine};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Fixture {
    allocation: Allocation,
    revision: u64,
    dns: Vec<DestinationListener>,
    native: Value,
}
fn fixture() -> (Fixture, DnsBindings) {
    let f: Fixture =
        serde_json::from_str(include_str!("fixtures/quarantine-kernel-table.json")).unwrap();
    let bindings = DnsBindings::new(
        DnsBinding::new(f.dns[0].address, f.dns[0].port).unwrap(),
        Some(DnsBinding::new(f.dns[1].address, f.dns[1].port).unwrap()),
    )
    .unwrap();
    (f, bindings)
}
fn row<'a>(v: &'a mut Value, kind: &str, name: &str) -> &'a mut Value {
    v["nftables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find_map(|r| {
            r.get_mut(kind)
                .filter(|r| r["name"] == name || r["chain"] == name)
        })
        .unwrap()
}
#[test]
fn actual_numeric_kernel_snapshot_and_resolved_interface_names_are_accepted() {
    let (f, b) = fixture();
    quarantine::verify(&f.allocation, f.revision, &b, &f.native).unwrap();
    let mut numeric = f.native.clone();
    for row in numeric["nftables"].as_array_mut().unwrap() {
        if let Some(expr) = row
            .get_mut("rule")
            .and_then(|r| r.get_mut("expr"))
            .and_then(Value::as_array_mut)
        {
            for e in expr {
                if e["match"]["left"] == json!({"meta":{"key":"iif"}}) {
                    e["match"]["right"] = json!(f.allocation.ifindex);
                }
            }
        }
    }
    quarantine::verify(&f.allocation, f.revision, &b, &numeric).unwrap();
}
#[test]
fn changed_quarantine_rules_leases_owners_hooks_and_endpoints_are_refused() {
    let (f, b) = fixture();
    for case in 0..22 {
        let mut wrong = f.native.clone();
        match case {
            0 => row(&mut wrong, "table", &f.allocation.table())["flags"] = json!(["dormant"]),
            1 => row(&mut wrong, "set", "live")["elem"] = json!([f.allocation.bridge]),
            2 => row(&mut wrong, "set", "live")["timeout"] = json!(11),
            3 => row(&mut wrong, "chain", "input")["prio"] = json!(-189),
            4 => row(&mut wrong, "chain", "forward")["hook"] = json!("output"),
            5 => {
                row(&mut wrong, "chain", &f.allocation.owner_chain())["name"] =
                    json!("foreign_owner")
            }
            6 => row(&mut wrong, "chain", "revision_1")["name"] = json!("revision_2"),
            7 => row(&mut wrong, "rule", "guard")["expr"] = json!([{"accept":null}]),
            8 => row(&mut wrong, "rule", "forward")["expr"][2]["jump"]["target"] = json!("input"),
            9 => row(&mut wrong, "rule", "input")["expr"][0]["match"]["right"] = json!("ghforeign"),
            10 => row(&mut wrong, "rule", "input")["expr"][1]["match"]["right"] = json!(254),
            11 => row(&mut wrong, "rule", "input")["expr"][3]["match"]["right"] = json!(1),
            12 => {
                let mut extra = row(&mut wrong, "rule", "input").clone();
                extra["expr"] = json!([{"accept":null}]);
                wrong["nftables"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"rule":extra}));
            }
            13 => {
                let rule = wrong["nftables"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .filter_map(|r| r.get_mut("rule"))
                    .filter(|r| r["chain"] == "input")
                    .nth(1)
                    .unwrap();
                rule["expr"][1]["match"]["right"] = json!(40103);
            }
            14 => {
                row(&mut wrong, "rule", "input")["expr"][0]["match"]["right"] =
                    json!(f.allocation.ifindex + 1)
            }
            15 => row(&mut wrong, "chain", "guard")["hook"] = json!("forward"),
            16 => row(&mut wrong, "table", &f.allocation.table())["family"] = json!("bridge"),
            17 => wrong["nftables"]
                .as_array_mut()
                .unwrap()
                .retain(|r| r.get("rule").is_none_or(|v| v["chain"] != "guard")),
            18 => wrong["nftables"]
                .as_array_mut()
                .unwrap()
                .push(json!({"flowtable":{"family":"inet","table":f.allocation.table()}})),
            19 => row(&mut wrong, "set", "live")["flags"] = json!(["dynamic", "timeout"]),
            20 => row(&mut wrong, "rule", "guard")["expr"]
                .as_array_mut()
                .unwrap()
                .insert(0, json!({"accept":null})),
            _ => {
                row(&mut wrong, "rule", "input")["expr"][2]["match"]["right"] =
                    json!({"set":[134,135,136]})
            }
        }
        assert!(
            quarantine::verify(&f.allocation, f.revision, &b, &wrong).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn private_configuration_wire_cannot_supply_or_extend_the_original_expiry() {
    use goldenhoop_egress::controller::Request;
    let value =
        json!({"operation":"configure_dns","expected_revision":0,"upstream":"127.0.0.1:19004"});
    serde_json::from_value::<Request>(value.clone()).unwrap();
    for (field, data) in [
        ("expires_at", json!("2099-01-01T00:00:00Z")),
        ("remaining_seconds", json!(86400)),
        ("allocation", json!({})),
    ] {
        let mut wrong = value.clone();
        wrong[field] = data;
        assert!(serde_json::from_value::<Request>(wrong).is_err());
    }
}
