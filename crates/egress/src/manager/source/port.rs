//! Read only the single bridge port. Production always uses actual sysfs;
//! the root parameter is private and permits filesystem race models in tests.
use crate::{Allocation, Endpoint, EndpointAddresses, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use std::path::Path;
#[cfg(test)]
mod tests;

fn conflict() -> ApiError {
    error(
        ErrorCode::Conflict,
        "the unique owned native bridge port is unavailable",
    )
}
fn index(path: &Path) -> Result<u32, ApiError> {
    let value = std::fs::read_to_string(path).map_err(|_| conflict())?;
    value
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|n| (1..=i32::MAX as u32).contains(n))
        .ok_or_else(conflict)
}
pub(super) fn observe(
    root: &Path,
    allocation: &Allocation,
    addresses: &EndpointAddresses,
) -> Result<Endpoint, ApiError> {
    allocation.validate()?;
    let bridge = root.join(&allocation.bridge);
    if index(&bridge.join("ifindex"))? != allocation.ifindex || !bridge.join("bridge").is_dir() {
        return Err(conflict());
    }
    let ports = std::fs::read_dir(bridge.join("brif"))
        .map_err(|_| conflict())?
        .take(2)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| conflict())?;
    if ports.len() != 1 {
        return Err(conflict());
    }
    let name = ports[0].file_name().into_string().map_err(|_| conflict())?;
    if !(2..=15).contains(&name.len())
        || name == allocation.bridge
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
    {
        return Err(conflict());
    }
    let port = root.join(&name);
    let ifindex = index(&port.join("ifindex"))?;
    if ifindex == allocation.ifindex
        || !ports[0].file_type().map_err(|_| conflict())?.is_symlink()
        || std::fs::canonicalize(ports[0].path()).map_err(|_| conflict())?
            != std::fs::canonicalize(port.join("brport")).map_err(|_| conflict())?
        || index(&port.join("master/ifindex"))? != allocation.ifindex
        || !port.join("brport").is_dir()
    {
        return Err(conflict());
    }
    // Re-read the bridge and port identity after traversing sysfs links.
    if index(&bridge.join("ifindex"))? != allocation.ifindex
        || index(&port.join("ifindex"))? != ifindex
        || index(&port.join("master/ifindex"))? != allocation.ifindex
        || std::fs::canonicalize(ports[0].path()).map_err(|_| conflict())?
            != std::fs::canonicalize(port.join("brport")).map_err(|_| conflict())?
    {
        return Err(conflict());
    }
    Ok(Endpoint {
        port: name,
        ifindex,
        mac: addresses.mac,
        ipv4: addresses.ipv4,
        ipv6: addresses.ipv6,
    })
}
