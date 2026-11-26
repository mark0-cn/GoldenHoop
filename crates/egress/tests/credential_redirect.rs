//! Independent captured native inet rules; mutations below are portable models.
use goldenhoop_egress::{Allocation, CredentialRedirect, CredentialRedirectPlan};
use serde_json::{Value, json};

#[test]
fn actual_redirect_capture_preserves_both_families_and_refuses_foreign_order_or_endpoints() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/credential-redirect-kernel-table.json"
    ))
    .unwrap();
    let allocation: Allocation =
        serde_json::from_value(fixture["input"]["allocation"].clone()).unwrap();
    let definition: CredentialRedirect =
        serde_json::from_value(fixture["input"]["definition"].clone()).unwrap();
    let plan = CredentialRedirectPlan::new(&allocation, definition).unwrap();
    plan.verify(&allocation, &fixture["native"]).unwrap();
    for case in 0..5 {
        let mut native = fixture["native"].clone();
        let rows = native["nftables"].as_array_mut().unwrap();
        let rule = rows.iter_mut().find_map(|r| r.get_mut("rule")).unwrap();
        match case {
            0 => rule["expr"][0]["match"]["right"] = json!("ghforeign"),
            1 => rule["expr"][1]["match"]["right"] = json!(allocation.ifindex + 1),
            2 => rule["expr"][5]["dnat"]["port"] = json!(1),
            3 => rule["expr"].as_array_mut().unwrap().swap(0, 1),
            _ => {
                rows.pop();
            }
        }
        assert!(
            plan.verify(&allocation, &native).is_err(),
            "mutation {case}"
        );
    }
}
