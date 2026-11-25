use chrono::{Duration, Utc};
use goldenhoop_egress::{Allocation, NetworkIdentity, native::NativeBridgePlan};
use goldenhoop_protocol::ErrorCode;
use uuid::Uuid;

fn plan() -> NativeBridgePlan {
    let identity = NetworkIdentity {
        installation_id: Uuid::new_v4(),
        sandbox_id: Uuid::new_v4(),
        generation: Uuid::new_v4(),
        profile: "local-gvisor".into(),
    };
    NativeBridgePlan {
        allocation: Allocation {
            installation_id: identity.installation_id,
            sandbox_id: identity.sandbox_id,
            generation: identity.generation,
            bridge: identity.bridge_name(),
            ifindex: 72,
        },
        identity,
        provisioning_token: Uuid::new_v4(),
        expires_at: Utc::now() + Duration::minutes(5),
    }
}

#[test]
fn native_plan_requires_matching_allocated_identity_and_a_live_dispatch() {
    let plan = plan();
    let now = Utc::now();
    plan.validate_at(now).unwrap();
    let mut variants = Vec::new();
    let mut bad = plan.clone();
    bad.allocation.installation_id = Uuid::new_v4();
    variants.push(bad);
    let mut bad = plan.clone();
    bad.allocation.sandbox_id = Uuid::new_v4();
    variants.push(bad);
    let mut bad = plan.clone();
    bad.allocation.generation = Uuid::new_v4();
    variants.push(bad);
    let mut bad = plan.clone();
    bad.allocation.bridge = "ghother".into();
    variants.push(bad);
    let mut bad = plan.clone();
    bad.allocation.ifindex = 0;
    variants.push(bad);
    let mut bad = plan.clone();
    bad.provisioning_token = Uuid::nil();
    variants.push(bad);
    for bad in variants {
        assert_eq!(
            bad.validate_at(now).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }
    for expired in [plan.expires_at, plan.expires_at + Duration::seconds(1)] {
        assert_eq!(
            plan.validate_at(expired).unwrap_err().code,
            ErrorCode::DeadlineExceeded
        );
    }
}

#[test]
fn native_private_control_shape_refuses_additional_authority_fields() {
    let value = serde_json::to_value(plan()).unwrap();
    serde_json::from_value::<NativeBridgePlan>(value.clone()).unwrap();
    let mut extra = value.clone();
    extra["allow_foreign_alias"] = true.into();
    assert!(serde_json::from_value::<NativeBridgePlan>(extra).is_err());
    let mut missing = value;
    missing
        .as_object_mut()
        .unwrap()
        .remove("provisioning_token");
    assert!(serde_json::from_value::<NativeBridgePlan>(missing).is_err());
}
