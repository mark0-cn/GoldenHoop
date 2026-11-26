//! Pure compiler/readback entry point. It never installs a rule or grants Ready.
use goldenhoop_egress::{Allocation, CredentialRedirect, CredentialRedirectPlan};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::Read;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    allocation: Allocation,
    definition: CredentialRedirect,
    native: Option<Value>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("oversized redirect readback input".into());
    }
    let input: Input = serde_json::from_slice(&bytes)?;
    let plan = CredentialRedirectPlan::new(&input.allocation, input.definition)?;
    let result = if let Some(native) = input.native {
        plan.verify(&input.allocation, &native)?;
        json!({"verified":true,"ready":false})
    } else {
        json!({"script":plan.script()})
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
