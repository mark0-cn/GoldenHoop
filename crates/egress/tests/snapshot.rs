use goldenhoop_egress::{Allocation, ScopedKernelSnapshot};
use serde_json::json;
use uuid::Uuid;

#[test]
fn captured_bridge_source_tables_retain_their_real_family_and_rules() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/source-kernel-rules.json")).unwrap();
    for capture in fixture["captures"].as_array().unwrap() {
        let a: Allocation = serde_json::from_value(capture["allocation"].clone()).unwrap();
        let scope: goldenhoop_egress::SourceScope =
            serde_json::from_value(capture["scope"].clone()).unwrap();
        let mut all = vec![
            json!({"table":{"family":"inet","name":a.table()}}),
            json!({"table":{"family":"bridge","name":a.ethernet_table()}}),
            json!({"table":{"family":"inet","name":a.destination_table()}}),
        ];
        all.extend(
            capture["observation"]["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .cloned(),
        );
        let snapshot =
            ScopedKernelSnapshot::parse(&a, &serde_json::to_vec(&json!({"nftables":all})).unwrap())
                .unwrap();
        goldenhoop_egress::SourcePlan::new(&a, &scope)
            .unwrap()
            .verify(&a, snapshot.table(&a.source_table()).unwrap())
            .unwrap();
    }
}

fn allocation() -> Allocation {
    Allocation {
        installation_id: Uuid::new_v4(),
        sandbox_id: Uuid::new_v4(),
        generation: Uuid::new_v4(),
        bridge: "ghsnap1".into(),
        ifindex: 37,
    }
}
fn entries(a: &Allocation) -> Vec<serde_json::Value> {
    vec![
        json!({"table":{"family":"inet","name":a.table()}}),
        json!({"table":{"family":"bridge","name":a.ethernet_table()}}),
        json!({"table":{"family":"bridge","name":a.source_table()}}),
        json!({"table":{"family":"inet","name":a.destination_table()}}),
    ]
}

#[test]
fn only_complete_unambiguous_owned_tables_reach_the_existing_rule_verifiers() {
    let a = allocation();
    let mut all = entries(&a);
    all.push(json!({"table":{"family":"inet","name":"unrelated"}}));
    all.push(json!({"rule":{"family":"inet","table":"unrelated","chain":"c","expr":[]}}));
    let snapshot =
        ScopedKernelSnapshot::parse(&a, &serde_json::to_vec(&json!({"nftables":all})).unwrap())
            .unwrap();
    assert_eq!(
        snapshot.table(&a.table()).unwrap()["nftables"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(snapshot.table("unrelated").is_err());
    // Parsing table identity does not verify any rules or grant a capability.
    let mut missing = entries(&a);
    missing.pop();
    assert!(
        ScopedKernelSnapshot::parse(
            &a,
            &serde_json::to_vec(&json!({"nftables":missing})).unwrap()
        )
        .is_err()
    );
    let mut duplicate = entries(&a);
    duplicate.push(duplicate[0].clone());
    assert!(
        ScopedKernelSnapshot::parse(
            &a,
            &serde_json::to_vec(&json!({"nftables":duplicate})).unwrap()
        )
        .is_err()
    );
    let mut wrong_family = entries(&a);
    wrong_family[0]["table"]["family"] = json!("bridge");
    assert!(
        ScopedKernelSnapshot::parse(
            &a,
            &serde_json::to_vec(&json!({"nftables":wrong_family})).unwrap()
        )
        .is_err()
    );
    let other = allocation();
    assert!(
        ScopedKernelSnapshot::parse(
            &other,
            &serde_json::to_vec(&json!({"nftables":entries(&a)})).unwrap()
        )
        .is_err()
    );
}
