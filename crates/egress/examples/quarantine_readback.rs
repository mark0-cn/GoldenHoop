//! Private, unprivileged plan/readback contract. This never writes kernel state.
use goldenhoop_egress::{
    Allocation, DestinationListener, DnsBinding, DnsBindings, Plan, quarantine,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{Read, Write};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    allocation: Allocation,
    revision: u64,
    dns: Vec<DestinationListener>,
    native: Option<Value>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("oversized contract input".into());
    }
    let input: Input = serde_json::from_slice(&bytes)?;
    if input.dns.is_empty() || input.dns.len() > 2 {
        return Err("invalid listener count".into());
    }
    let v4 = DnsBinding::new(input.dns[0].address, input.dns[0].port)?;
    let v6 = input
        .dns
        .get(1)
        .map(|d| DnsBinding::new(d.address, d.port))
        .transpose()?;
    let bindings = DnsBindings::new(v4, v6)?;
    let result = if let Some(native) = input.native {
        quarantine::verify(&input.allocation, input.revision, &bindings, &native)?;
        json!({"verified":true})
    } else {
        json!({"script":Plan::quarantine_with_binding(input.allocation,input.revision,Some(&bindings))?.script()})
    };
    serde_json::to_writer(std::io::stdout().lock(), &result)?;
    std::io::stdout().write_all(b"\n")?;
    Ok(())
}
