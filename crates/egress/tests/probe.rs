//! Probe plans have no native-controller authority; all observations are models.
use chrono::{Duration, Utc};
use goldenhoop_egress::*;
use serde_json::json;
use uuid::Uuid;

fn plan() -> ProbePlan {
    ProbePlan {
        purpose: ProbePurpose::Discover,
        identity: NetworkIdentity {
            installation_id: Uuid::new_v4(),
            sandbox_id: Uuid::new_v4(),
            generation: Uuid::new_v4(),
            profile: "local-runc-dev".into(),
        },
        network_id: Some("b".repeat(64)),
        provisioning_token: Some(Uuid::new_v4()),
        expires_at: Utc::now() + Duration::seconds(600),
        image_id: format!("sha256:{}", "a".repeat(64)),
        controller_generation: Uuid::new_v4(),
        collection_deadline: None,
    }
}
#[test]
fn probe_context_cannot_be_deserialized_or_cast_as_a_native_controller() {
    let p = plan();
    p.validate_dispatch_at(Utc::now()).unwrap();
    let raw = serde_json::to_value(&p).unwrap();
    assert!(serde_json::from_value::<ControllerPlan>(raw.clone()).is_err());
    let host: HostProcessPlan = serde_json::from_value(raw.clone()).unwrap();
    assert!(host.controller().is_err());
    assert_eq!(serde_json::to_value(&host).unwrap(), raw);
    for case in 0..5 {
        let mut wrong = p.clone();
        match case {
            0 => wrong.network_id = None,
            1 => wrong.provisioning_token = None,
            2 => wrong.controller_generation = Uuid::nil(),
            3 => wrong.collection_deadline = Some(Utc::now() + Duration::seconds(60)),
            _ => wrong.image_id = "mutable:latest".into(),
        };
        assert!(wrong.validate().is_err());
    }
    let mut extra = raw;
    extra["ifindex"] = json!(0);
    assert!(serde_json::from_value::<HostProcessPlan>(extra).is_err());
}
#[test]
fn absence_context_keeps_original_expiry_and_bounded_read_only_dispatch() {
    let mut p = plan();
    let now = Utc::now();
    p.purpose = ProbePurpose::ObserveAbsence;
    p.expires_at = now - Duration::seconds(10);
    p.collection_deadline = Some(now + Duration::seconds(60));
    p.network_id = None;
    p.provisioning_token = None;
    p.validate_dispatch_at(now).unwrap();
    assert_eq!(p.expires_at, now - Duration::seconds(10));
    assert!(p.validate_dispatch_at(now + Duration::seconds(60)).is_err());
    p.collection_deadline = Some(now + Duration::seconds(61));
    assert!(p.validate_dispatch_at(now).is_err());
}
#[test]
fn probe_receipts_are_bound_to_the_full_plan_and_positive_original_allocation() {
    let p = plan();
    let native = NativeProbe {
        plan_sha256: p.digest(),
        allocation: Allocation {
            installation_id: p.identity.installation_id,
            sandbox_id: p.identity.sandbox_id,
            generation: p.identity.generation,
            bridge: p.identity.bridge_name(),
            ifindex: 42,
        },
        ipv4_gateway: "192.0.2.1".parse().unwrap(),
        ipv6_gateway: "fd42::1".parse().unwrap(),
        alias: String::new(),
        observed_at: Utc::now(),
    };
    ProbeObservation::Native(native.clone())
        .validate(&p)
        .unwrap();
    for case in 0..6 {
        let mut wrong = native.clone();
        match case {
            0 => wrong.plan_sha256 = "0".repeat(64),
            1 => wrong.allocation.ifindex = 0,
            2 => wrong.allocation.generation = Uuid::new_v4(),
            3 => wrong.alias = "foreign".into(),
            4 => wrong.ipv4_gateway = "127.0.0.1".parse().unwrap(),
            _ => wrong.ipv6_gateway = "::1".parse().unwrap(),
        };
        assert!(ProbeObservation::Native(wrong).validate(&p).is_err());
    }
    assert!(
        ProbeObservation::Absence(ProbeAbsence {
            plan_sha256: p.digest(),
            bridge_absent: true,
            owned_tables_absent: true,
            observed_at: Utc::now()
        })
        .validate(&p)
        .is_err()
    );
}
#[test]
fn historical_native_plan_serialization_remains_identical_in_the_host_union() {
    let captured: serde_json::Value = serde_json::from_str(include_str!(
        "../../docker/tests/fixtures/owned-controller.json"
    ))
    .unwrap();
    let plan: ControllerPlan = serde_json::from_value(captured["plan"].clone()).unwrap();
    let original = serde_json::to_vec(&plan).unwrap();
    let host: HostProcessPlan = plan.into();
    assert_eq!(serde_json::to_vec(&host).unwrap(), original);
    host.controller().unwrap().validate().unwrap();
}
