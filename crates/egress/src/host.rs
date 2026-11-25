use crate::{Allocation, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use std::os::{
    linux::net::SocketAddrExt,
    unix::net::{SocketAddr, UnixDatagram},
};

pub(crate) fn authority() -> Result<(), ApiError> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|_| {
        error(
            ErrorCode::BackendUnavailable,
            "cannot inspect manager credentials",
        )
    })?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
    };
    let only_net_admin =
        |value: Option<&str>| value.and_then(|v| u64::from_str_radix(v, 16).ok()) == Some(1 << 12);
    if !only_net_admin(field("CapEff:"))
        || !only_net_admin(field("CapPrm:"))
        || field("NoNewPrivs:") != Some("1")
    {
        return Err(error(
            ErrorCode::Forbidden,
            "manager requires only NET_ADMIN and no-new-privileges",
        ));
    }
    Ok(())
}

fn lock(name: &str) -> Result<UnixDatagram, ApiError> {
    let address = SocketAddr::from_abstract_name(name.as_bytes())
        .map_err(|_| error(ErrorCode::InvalidRequest, "invalid manager lock name"))?;
    UnixDatagram::bind_addr(&address).map_err(|_| {
        error(
            ErrorCode::Conflict,
            "allocation already has a packet-filter controller",
        )
    })
}

pub(crate) fn allocation_lock(allocation: &Allocation) -> Result<UnixDatagram, ApiError> {
    lock(&allocation.owner())
}

pub(crate) fn bridge_lock(allocation: &Allocation) -> Result<UnixDatagram, ApiError> {
    lock(&format!("goldenhoop:bridge-bind:{}", allocation.bridge))
}
