//! Read-only destination plan compilation and native observation verification.
//! Installation belongs to the trusted caller; this example writes no rules.
use goldenhoop_egress::{Allocation, DestinationDefinition, DestinationPlan};
use serde::Deserialize;
use serde_json::Value;
use std::io::Read;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    allocation: Allocation,
    definition: DestinationDefinition,
    #[serde(default)]
    observation: Option<Value>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(5 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 5 * 1024 * 1024 {
        return Err("destination preview exceeds input bound".into());
    }
    let input: Input =
        serde_json::from_slice(&bytes).map_err(|_| "invalid destination preview input")?;
    let plan = DestinationPlan::new(&input.allocation, &input.definition)
        .map_err(|_| "invalid destination preview definition")?;
    if let Some(value) = input.observation {
        plan.verify(&input.allocation, &value)
            .map_err(|_| "destination observation differs")?;
        println!("{{\"verified\":true}}");
    } else {
        print!("{}", plan.script());
    }
    Ok(())
}
