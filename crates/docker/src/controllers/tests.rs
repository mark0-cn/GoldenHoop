use super::*;
use goldenhoop_egress::{Allocation, NetworkIdentity};
use uuid::Uuid;

fn captured() -> (ContainerCreateBody, ControllerPlan, serde_json::Value) {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/owned-controller.json")).unwrap();
    let plan: ControllerPlan = serde_json::from_value(value["plan"].clone()).unwrap();
    let expected = request(
        &plan,
        &serde_json::from_value(value["image_labels"].clone()).unwrap(),
    );
    (expected, plan, value["observation"].clone())
}

#[test]
fn unmodified_actual_inspection_keeps_immutable_identity_placement_and_created_state() {
    let (expected, plan, value) = captured();
    let observed = observe(
        &plan,
        &serde_json::from_value(value.clone()).unwrap(),
        &expected,
    )
    .unwrap();
    assert_eq!(observed.container_id, value["Id"].as_str().unwrap());
    assert_eq!(observed.image_id, plan.image_id);
    assert_eq!(observed.status, "created");
    assert!(!observed.running);
}

#[test]
fn historical_controller_identity_is_collectible_but_never_authorizes_dispatch() {
    let (_, plan, _) = captured();
    assert!(plan.controller_generation.is_none());
    plan.validate().unwrap();
    assert_eq!(
        plan.validate_dispatch_at(Utc::now()).unwrap_err().code,
        ErrorCode::InvalidState
    );
}

#[test]
fn collection_purpose_has_a_bounded_separate_deadline_and_cannot_extend_a_workload() {
    let (_, mut plan, _) = captured();
    plan.controller_generation = Some(Uuid::new_v4());
    let now = Utc::now();
    plan.native.expires_at = now - chrono::Duration::seconds(1);
    assert_eq!(
        plan.validate_dispatch_at(now).unwrap_err().code,
        ErrorCode::DeadlineExceeded
    );
    plan.purpose = ControllerPurpose::Collect;
    plan.collection_deadline = Some(now + chrono::Duration::seconds(60));
    plan.validate_dispatch_at(now).unwrap();
    assert!(plan.native.validate_at(now).is_err());
    plan.collection_deadline = Some(now + chrono::Duration::seconds(61));
    assert!(plan.validate_dispatch_at(now).is_err());
    plan.collection_deadline = Some(now);
    assert!(plan.validate_dispatch_at(now).is_err());
    plan.collection_deadline = None;
    assert!(plan.validate().is_err());
    plan.purpose = ControllerPurpose::Enforce;
    plan.collection_deadline = Some(now + chrono::Duration::seconds(60));
    assert!(plan.validate().is_err());
}

#[test]
fn actual_inspection_mutations_cannot_forge_ownership_weaken_placement_or_infer_process_success() {
    use serde_json::json;
    let (expected, plan, original) = captured();
    let mut mutations = Vec::new();
    for (pointer, payload) in [
        ("/Name", json!("/foreign")),
        ("/Image", json!(format!("sha256:{}", "b".repeat(64)))),
        ("/Config/Image", json!("goldenhoop-egress:test")),
        ("/Config/User", json!("1000:1000")),
        ("/Config/Env", json!([ENV, "HOST_TOKEN=foreign"])),
        ("/Config/Entrypoint", json!(["/bin/sh"])),
        ("/Config/OpenStdin", json!(false)),
        ("/Config/StdinOnce", json!(false)),
        ("/Config/Tty", json!(true)),
        ("/Config/AttachStderr", json!(false)),
        ("/Config/WorkingDir", json!("/workspace")),
        (
            "/Config/Labels/dev.goldenhoop.installation",
            json!(Uuid::new_v4().to_string()),
        ),
        ("/Config/Labels/dev.goldenhoop.controller-plan", json!("{}")),
        ("/HostConfig/NetworkMode", json!("bridge")),
        ("/HostConfig/Runtime", json!("runsc")),
        ("/HostConfig/ReadonlyRootfs", json!(false)),
        ("/HostConfig/Privileged", json!(true)),
        ("/HostConfig/CapAdd", json!(["NET_ADMIN", "NET_RAW"])),
        ("/HostConfig/CapDrop", json!([])),
        ("/HostConfig/SecurityOpt", json!([])),
        ("/HostConfig/Memory", json!(0)),
        ("/HostConfig/MemorySwap", json!(-1)),
        ("/HostConfig/NanoCpus", json!(0)),
        ("/HostConfig/PidsLimit", json!(0)),
        ("/HostConfig/PidMode", json!("host")),
        ("/HostConfig/IpcMode", json!("host")),
        ("/HostConfig/CgroupnsMode", json!("host")),
        (
            "/HostConfig/Binds",
            json!(["/var/run/docker.sock:/var/run/docker.sock"]),
        ),
        ("/HostConfig/AutoRemove", json!(true)),
        ("/HostConfig/RestartPolicy/Name", json!("always")),
        ("/HostConfig/LogConfig/Type", json!("json-file")),
        ("/Args", json!(["foreign"])),
        (
            "/Mounts",
            json!([{"Type":"bind","Source":"/private","Destination":"/host"}]),
        ),
    ] {
        let mut candidate = original.clone();
        *candidate.pointer_mut(pointer).unwrap() = payload;
        mutations.push(candidate);
    }
    for field in ["Mounts", "Args", "State"] {
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove(field);
        mutations.push(value);
    }
    for value in mutations {
        let observation = serde_json::from_value(value);
        assert!(observation.is_err() || observe(&plan, &observation.unwrap(), &expected).is_err());
    }
}

#[tokio::test]
async fn mutable_malformed_and_noncanonical_image_references_refuse_before_daemon_access() {
    for image in [
        "",
        "goldenhoop-egress:test",
        "sha256:abc",
        &format!("sha256:{}", "A".repeat(64)),
        &"0".repeat(64),
    ] {
        let error = DockerControllerProvider::connect(image)
            .await
            .err()
            .expect("untrusted image reference");
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }
}

#[test]
fn expired_controller_identity_remains_collectible_without_authorizing_new_dispatch() {
    let identity = NetworkIdentity {
        installation_id: Uuid::new_v4(),
        sandbox_id: Uuid::new_v4(),
        generation: Uuid::new_v4(),
        profile: "local-gvisor".into(),
    };
    let plan = ControllerPlan {
        purpose: ControllerPurpose::Enforce,
        collection_deadline: None,
        controller_generation: Some(Uuid::new_v4()),
        image_id: format!("sha256:{}", "a".repeat(64)),
        native: NativeBridgePlan {
            allocation: Allocation {
                installation_id: identity.installation_id,
                sandbox_id: identity.sandbox_id,
                generation: identity.generation,
                bridge: identity.bridge_name(),
                ifindex: 72,
            },
            identity,
            provisioning_token: Uuid::new_v4(),
            expires_at: Utc::now() - chrono::Duration::seconds(1),
        },
    };
    plan.validate().unwrap();
    assert_eq!(
        plan.native.validate_at(Utc::now()).unwrap_err().code,
        ErrorCode::DeadlineExceeded
    );
    let mut value = serde_json::to_value(&plan).unwrap();
    value["allow_recreation"] = true.into();
    assert!(serde_json::from_value::<ControllerPlan>(value).is_err());
    let mut foreign = plan.clone();
    foreign.native.allocation.generation = Uuid::new_v4();
    assert_eq!(
        foreign.validate().unwrap_err().code,
        ErrorCode::InvalidRequest
    );
}
