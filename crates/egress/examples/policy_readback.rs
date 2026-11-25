//! Private unprivileged compiler/readback contract. No kernel mutation or Ready.
use goldenhoop_egress::{
    Allocation, Config, DestinationListener, DnsBinding, DnsBindings, Plan, dns::SetNames,
    policy_readback,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{Read, Write};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    allocation: Allocation,
    revision: u64,
    config: Config,
    #[serde(default)]
    dns_enabled: bool,
    #[serde(default)]
    dns: Vec<DestinationListener>,
    native: Option<Value>,
    dns_token: Option<uuid::Uuid>,
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
    if input.dns_token.is_some() && !input.dns_enabled {
        return Err("staged DNS requires trusted DNS mode".into());
    }
    if input.dns.len() > 2 {
        return Err("too many listeners".into());
    }
    let bindings = input
        .dns
        .first()
        .map(|v4| {
            DnsBindings::new(
                DnsBinding::new(v4.address, v4.port)?,
                input
                    .dns
                    .get(1)
                    .map(|v6| DnsBinding::new(v6.address, v6.port))
                    .transpose()?,
            )
        })
        .transpose()?;
    let names = if let Some(token) = input.dns_token {
        Some(SetNames::staged(token)?)
    } else {
        input.dns_enabled.then(SetNames::bootstrap)
    };
    if bindings.is_some() && names.is_none() {
        return Err("listeners require trusted DNS".into());
    }
    let result = if let Some(native) = input.native {
        policy_readback::verify_structure(
            &input.allocation,
            input.revision,
            &input.config,
            bindings.as_ref(),
            names.as_ref(),
            &native,
        )?;
        json!({"verified_structure":true,"ready":false})
    } else {
        if let Some(token) = input.dns_token {
            let names = SetNames::staged(token)?;
            json!({"script":format!("{}{}",names.declarations(&input.allocation)?,Plan::activate_dns(input.allocation,input.revision,&input.config,&SetNames::bootstrap(),&names)?.script())})
        } else {
            let plan = if input.dns_enabled {
                Plan::compile_with_dns(
                    input.allocation,
                    input.revision,
                    &input.config,
                    bindings.as_ref(),
                )?
            } else {
                Plan::compile(input.allocation, input.revision, &input.config)?
            };
            json!({"script":plan.script()})
        }
    };
    serde_json::to_writer(std::io::stdout().lock(), &result)?;
    std::io::stdout().write_all(b"\n")?;
    Ok(())
}
