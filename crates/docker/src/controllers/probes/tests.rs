use super::*;
use serde_json::{Value, json};

fn captured() -> (ProbePlan, ContainerCreateBody, Value) {
    let value: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/owned-native-probe.json"
    ))
    .unwrap();
    let plan: ProbePlan = serde_json::from_value(value["plan"].clone()).unwrap();
    let expected = request(
        &plan,
        &serde_json::from_value(value["image_labels"].clone()).unwrap(),
    );
    (plan, expected, value["observation"].clone())
}

#[test]
fn actual_probe_capture_preserves_zero_capabilities_and_bounded_metadata_logs() {
    let (plan, expected, value) = captured();
    plan.validate().unwrap();
    let observed = inspection::observe_process(
        &plan.name(),
        &plan.image_id,
        &serde_json::from_value(value.clone()).unwrap(),
        &expected,
    )
    .unwrap();
    assert_eq!(observed.container_id, value["Id"].as_str().unwrap());
    assert_eq!(observed.status, "created");
    assert!(!observed.running);
}

#[test]
fn probe_admission_refuses_added_authority_control_channels_or_unbounded_logs() {
    let (plan, expected, original) = captured();
    for (pointer, payload) in [
        ("/Config/User", json!("0:0")),
        ("/Config/OpenStdin", json!(true)),
        ("/Config/AttachStdin", json!(true)),
        ("/Config/Env", json!([ENV, "HOST_TOKEN=foreign"])),
        ("/Config/Labels/dev.goldenhoop.probe-plan", json!("{}")),
        ("/HostConfig/CapAdd", json!(["NET_ADMIN"])),
        ("/HostConfig/CapDrop", json!([])),
        ("/HostConfig/Privileged", json!(true)),
        ("/HostConfig/ReadonlyRootfs", json!(false)),
        ("/HostConfig/SecurityOpt", json!([])),
        ("/HostConfig/NetworkMode", json!("bridge")),
        ("/HostConfig/PidMode", json!("host")),
        ("/HostConfig/Runtime", json!("runsc")),
        ("/HostConfig/LogConfig/Type", json!("journald")),
        ("/HostConfig/LogConfig/Config/max-size", json!("0")),
        ("/HostConfig/LogConfig/Config/max-file", json!("2")),
        ("/HostConfig/Binds", json!(["/private:/host"])),
        ("/HostConfig/RestartPolicy/Name", json!("always")),
        ("/Args", json!(["--collection-only"])),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(pointer).expect("actual captured field") = payload;
        let parsed = serde_json::from_value(value);
        assert!(
            parsed.is_err()
                || inspection::observe_process(
                    &plan.name(),
                    &plan.image_id,
                    &parsed.unwrap(),
                    &expected,
                )
                .is_err(),
            "admitted altered probe configuration: {pointer}"
        );
    }
}
