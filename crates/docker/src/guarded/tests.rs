//! Synthetic inspection mutations; actual runtime acceptance is a separate gate.
use super::*;
use serde_json::{Value, json};

pub(super) fn model() -> (WorkloadNetworkPlan, Value, Value, NetworkObservation) {
    let historical: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/owned-controller.json")).unwrap();
    let native: NativeBridgePlan =
        serde_json::from_value(historical["plan"]["native"].clone()).unwrap();
    let network = WorkloadNetworkPlan {
        native,
        network_id: "b".repeat(64),
    };
    let net6: ipnet::Ipv6Net = network.native.identity.ipv6_subnet().parse().unwrap();
    let gateway6 = Ipv6Addr::from(u128::from(net6.network()) + 1);
    let address6 = Ipv6Addr::from(u128::from(net6.network()) + 2);
    let id = "a".repeat(64);
    let endpoint_id = "c".repeat(64);
    let name = network.native.identity.network_name();
    let observed = NetworkObservation {
        network_id: network.network_id.clone(),
        ipv4_subnet: "10.77.0.0/24".into(),
        ipv4_gateway: "10.77.0.1".parse().unwrap(),
        ipv6_subnet: net6.to_string(),
        ipv6_gateway: gateway6,
        attached_endpoints: 1,
        observed_at: Utc::now(),
    };
    let actual = json!({"Id":id,"Config":{"Labels":{(NETWORK_PLAN_LABEL):serde_json::to_string(&network).unwrap()},"User":"0:0","Entrypoint":[AGENT_PATH,"serve"],"Cmd":[],"Healthcheck":{"Test":["NONE"]}},
        "HostConfig":{"NetworkMode":network.network_id,"Runtime":"runc","Privileged":false,"ReadonlyRootfs":true,"CapDrop":["ALL"],"CapAdd":["SETUID","SETGID","KILL","CHOWN","FOWNER","DAC_OVERRIDE"],"SecurityOpt":["no-new-privileges"],"IpcMode":"private"},
        "Mounts":[{"Type":"volume","Destination":"/opt/goldenhoop","RW":false}],
        "NetworkSettings":{"Networks":{(name):{"NetworkID":network.network_id,"EndpointID":endpoint_id,"MacAddress":"02:00:00:00:00:02","IPAddress":"10.77.0.2","IPPrefixLen":24,"Gateway":"10.77.0.1","GlobalIPv6Address":address6.to_string(),"GlobalIPv6PrefixLen":64,"IPv6Gateway":gateway6.to_string()}}}});
    let provider = json!({"Id":network.network_id,"Containers":{(id):{"EndpointID":endpoint_id,"MacAddress":"02:00:00:00:00:02","IPv4Address":"10.77.0.2/24","IPv6Address":format!("{address6}/64")}}});
    let mut actual = actual;
    let resolver = goldenhoop_core::resolver::ResolverConfig::new(observed.ipv4_gateway);
    let volume = "owned-agent-volume";
    let source = "/var/lib/docker/volumes/owned-agent-volume/_data";
    actual["HostConfig"]["Dns"] = json!([observed.ipv4_gateway.to_string()]);
    actual["HostConfig"]["Mounts"] = json!([
        {"Type":"volume","Target":"/opt/goldenhoop","Source":volume,"ReadOnly":true,"VolumeOptions":{"NoCopy":true}},
        {"Type":"volume","Target":"/etc/resolv.conf","Source":volume,"ReadOnly":true,"VolumeOptions":{"NoCopy":true,"Subpath":resolver.file_name()}}
    ]);
    actual["Mounts"] = json!([
        {"Type":"volume","Name":volume,"Source":source,"Destination":"/opt/goldenhoop","RW":false},
        {"Type":"volume","Name":volume,"Source":source,"Destination":"/etc/resolv.conf","RW":false}
    ]);
    (network, actual, provider, observed)
}
#[test]
fn guarded_plan_cannot_be_adopted_by_the_none_network_path_or_a_foreign_identity() {
    let (plan, actual, _, _) = model();
    plan.validate().unwrap();
    let value: ContainerInspectResponse = serde_json::from_value(actual.clone()).unwrap();
    match_requested_plan(&value, Some(&plan)).unwrap();
    assert!(match_requested_plan(&value, None).is_err());
    let mut foreign = plan.clone();
    foreign.native.provisioning_token = Uuid::new_v4();
    assert!(match_requested_plan(&value, Some(&foreign)).is_err());
    for id in ["alias".to_string(), "B".repeat(64), "0".repeat(63)] {
        let mut wrong = plan.clone();
        wrong.network_id = id;
        assert!(wrong.validate().is_err());
    }
    let mut extra = serde_json::to_value(&plan).unwrap();
    extra["fallback"] = json!("none");
    assert!(serde_json::from_value::<WorkloadNetworkPlan>(extra).is_err());
    let mut plain = actual;
    plain["Config"]["Labels"]
        .as_object_mut()
        .unwrap()
        .remove(NETWORK_PLAN_LABEL);
    let plain = serde_json::from_value(plain).unwrap();
    match_requested_plan(&plain, None).unwrap();
    assert!(match_requested_plan(&plain, Some(&plan)).is_err());
}
#[test]
fn guarded_start_admission_rejects_image_hooks_host_authority_and_other_networks() {
    let (plan, original, _, _) = model();
    admit_placement(
        &serde_json::from_value(original.clone()).unwrap(),
        &plan,
        "runc",
        "10.77.0.1".parse().unwrap(),
    )
    .unwrap();
    let mut changed = Vec::new();
    for (key, setting) in [
        ("NetworkMode", json!("none")),
        ("Runtime", json!("runsc")),
        ("Privileged", json!(true)),
        ("ReadonlyRootfs", json!(false)),
        ("CapAdd", json!(["NET_ADMIN"])),
        ("CapDrop", json!([])),
        ("SecurityOpt", json!([])),
        ("PidMode", json!("host")),
        ("IpcMode", json!("host")),
        ("Binds", json!(["/var/run/docker.sock:/sock"])),
        (
            "Devices",
            json!([{"PathOnHost":"/dev/kvm","PathInContainer":"/dev/kvm","CgroupPermissions":"rwm"}]),
        ),
    ] {
        let mut value = original.clone();
        value["HostConfig"][key] = setting;
        changed.push((key, value));
    }
    for (key, setting) in [
        ("Entrypoint", json!(["/bin/sh"])),
        ("Healthcheck", json!({"Test":["CMD","untrusted"]})),
        ("Cmd", json!(["untrusted"])),
        ("User", json!("1000:1000")),
    ] {
        let mut value = original.clone();
        value["Config"][key] = setting;
        changed.push((key, value));
    }
    for (name, value) in changed {
        assert!(
            admit_placement(
                &serde_json::from_value(value).unwrap(),
                &plan,
                "runc",
                "10.77.0.1".parse().unwrap()
            )
            .is_err(),
            "{name}"
        );
    }
    for setting in [
        json!([]),
        json!([{"Type":"bind","Destination":"/opt/goldenhoop","RW":false}]),
        json!([{"Type":"volume","Destination":"/opt/goldenhoop","RW":true}]),
    ] {
        let mut value = original.clone();
        value["Mounts"] = setting;
        assert!(
            admit_placement(
                &serde_json::from_value(value).unwrap(),
                &plan,
                "runc",
                "10.77.0.1".parse().unwrap()
            )
            .is_err()
        );
    }
}
#[test]
fn resolver_placement_refuses_missing_writable_foreign_or_wrong_gateway_configuration() {
    let (plan, original, _, observed) = model();
    let good: ContainerInspectResponse = serde_json::from_value(original.clone()).unwrap();
    admit_placement(&good, &plan, "runc", observed.ipv4_gateway).unwrap();
    assert!(admit_placement(&good, &plan, "runc", "10.77.0.2".parse().unwrap()).is_err());
    for (path, changed) in [
        ("/HostConfig/Dns", json!(["127.0.0.11"])),
        ("/HostConfig/Mounts/1/ReadOnly", json!(false)),
        ("/HostConfig/Mounts/1/Source", json!("foreign-volume")),
        (
            "/HostConfig/Mounts/1/VolumeOptions/Subpath",
            json!("../resolv.conf"),
        ),
        ("/HostConfig/Mounts/1/VolumeOptions/NoCopy", json!(false)),
        ("/Mounts/1/RW", json!(true)),
        ("/Mounts/1/Name", json!("foreign-volume")),
        ("/Mounts/1/Source", json!("/foreign")),
        ("/Mounts/1/Type", json!("bind")),
        ("/Mounts/1/Destination", json!("/etc/hosts")),
    ] {
        let mut bad = original.clone();
        *bad.pointer_mut(path).unwrap() = changed;
        assert!(
            admit_placement(
                &serde_json::from_value(bad).unwrap(),
                &plan,
                "runc",
                observed.ipv4_gateway
            )
            .is_err(),
            "{path}"
        );
    }
    let mut missing = original;
    missing["Mounts"].as_array_mut().unwrap().pop();
    assert!(
        admit_placement(
            &serde_json::from_value(missing).unwrap(),
            &plan,
            "runc",
            observed.ipv4_gateway
        )
        .is_err()
    );
}

#[test]
fn endpoint_requires_both_actual_views_to_agree_on_one_physical_dual_stack_attachment() {
    let (plan, actual, provider, observed) = model();
    let name = plan.native.identity.network_name();
    let id = "a".repeat(64);
    let native: NetworkInspect = serde_json::from_value(provider.clone()).unwrap();
    let valid = endpoint(
        &serde_json::from_value(actual.clone()).unwrap(),
        &native,
        &plan,
        &observed,
    )
    .unwrap();
    assert_eq!(valid.container_id, id);
    assert_eq!(valid.ipv4.to_string(), "10.77.0.2");
    for (key, setting) in [
        ("NetworkID", json!("foreign")),
        ("EndpointID", json!("alias")),
        ("MacAddress", json!("01:00:00:00:00:02")),
        ("IPAddress", json!("10.77.0.1")),
        ("IPPrefixLen", json!(16)),
        (
            "GlobalIPv6Address",
            json!(observed.ipv6_gateway.to_string()),
        ),
        ("GlobalIPv6PrefixLen", json!(48)),
        ("IPv6Gateway", json!("::1")),
    ] {
        let mut value = actual.clone();
        value["NetworkSettings"]["Networks"][&name][key] = setting;
        assert!(
            endpoint(
                &serde_json::from_value(value).unwrap(),
                &native,
                &plan,
                &observed
            )
            .is_err(),
            "{key}"
        );
    }
    for (key, setting) in [
        ("EndpointID", json!("d".repeat(64))),
        ("MacAddress", json!("02:00:00:00:00:03")),
        ("IPv4Address", json!("10.77.0.3/24")),
        ("IPv6Address", json!("::1/64")),
    ] {
        let mut value = provider.clone();
        value["Containers"][&id][key] = setting;
        assert!(
            endpoint(
                &serde_json::from_value(actual.clone()).unwrap(),
                &serde_json::from_value(value).unwrap(),
                &plan,
                &observed
            )
            .is_err(),
            "{key}"
        );
    }
    let mut value = provider;
    value["Containers"]["foreign"] = value["Containers"][&id].clone();
    assert!(
        endpoint(
            &serde_json::from_value(actual).unwrap(),
            &serde_json::from_value(value).unwrap(),
            &plan,
            &observed
        )
        .is_err()
    );
}
