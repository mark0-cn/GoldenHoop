//! Read-only developer plan inspection; never installs a kernel rule.
use goldenhoop_egress::{Allocation, SourcePlan, SourceScope};
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    allocation: Allocation,
    scope: SourceScope,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err("source preview exceeds input bound".into());
    }
    let input: Input =
        serde_json::from_slice(&bytes).map_err(|_| "invalid source preview input")?;
    let plan = SourcePlan::new(&input.allocation, &input.scope)
        .map_err(|_| "invalid source preview scope")?;
    print!("{}", plan.script());
    Ok(())
}
