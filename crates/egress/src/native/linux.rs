use super::{NativeBridgeObservation, NativeBridgePlan};
use crate::{error, host};
use chrono::Utc;
use goldenhoop_protocol::{ApiError, ErrorCode};
use std::{
    mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::Path,
};

fn unavailable() -> ApiError {
    error(
        ErrorCode::BackendUnavailable,
        "native bridge alias exchange was not confirmed",
    )
}

fn observed_alias(plan: &NativeBridgePlan) -> Result<String, ApiError> {
    let path = Path::new("/sys/class/net").join(&plan.allocation.bridge);
    let index = std::fs::read_to_string(path.join("ifindex"))
        .map_err(|_| error(ErrorCode::Conflict, "native bridge is unavailable"))?;
    let alias = std::fs::read_to_string(path.join("ifalias"))
        .map_err(|_| error(ErrorCode::Conflict, "native bridge alias is unavailable"))?;
    if index.trim().parse::<u32>().ok() != Some(plan.allocation.ifindex)
        || !path.join("bridge").is_dir()
    {
        return Err(error(
            ErrorCode::Conflict,
            "native bridge name, index or kind changed",
        ));
    }
    // sysfs appends one newline; a newline supplied as an alias is still foreign.
    Ok(alias.strip_suffix('\n').unwrap_or(&alias).to_owned())
}

fn request(index: u32, owner: &str, port: u32) -> Vec<u8> {
    let attribute_length = 4 + owner.len() + 1;
    let length = 16 + 16 + attribute_length;
    let mut bytes = Vec::with_capacity((length + 3) & !3);
    bytes.extend_from_slice(&(length as u32).to_ne_bytes());
    bytes.extend_from_slice(&libc::RTM_NEWLINK.to_ne_bytes());
    bytes.extend_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16).to_ne_bytes());
    bytes.extend_from_slice(&1_u32.to_ne_bytes());
    bytes.extend_from_slice(&port.to_ne_bytes());
    // ifinfomsg, with only a physical index and no flags or rename attribute.
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&(index as i32).to_ne_bytes());
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&(attribute_length as u16).to_ne_bytes());
    bytes.extend_from_slice(&libc::IFLA_IFALIAS.to_ne_bytes());
    bytes.extend_from_slice(owner.as_bytes());
    bytes.push(0);
    bytes.resize((length + 3) & !3, 0);
    bytes
}

fn ack(bytes: &[u8], port: u32, request_length: u32) -> Result<(), ApiError> {
    if bytes.len() < 36 {
        return Err(unavailable());
    }
    let word = |offset| {
        u32::from_ne_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("checked header"),
        )
    };
    let short = |offset| {
        u16::from_ne_bytes(
            bytes[offset..offset + 2]
                .try_into()
                .expect("checked header"),
        )
    };
    let length = word(0) as usize;
    if length < 36
        || length > bytes.len()
        || bytes.len() > ((length + 3) & !3)
        || bytes[length..].iter().any(|b| *b != 0)
        || short(4) != libc::NLMSG_ERROR as u16
        || word(8) != 1
        || word(12) != port
        || i32::from_ne_bytes(bytes[16..20].try_into().expect("checked error")) != 0
        || word(20) != request_length
        || short(24) != libc::RTM_NEWLINK
        || word(28) != 1
        || word(32) != port
    {
        return Err(unavailable());
    }
    Ok(())
}

fn set_alias(index: u32, owner: &str) -> Result<(), ApiError> {
    // All unsafe calls operate on fixed C socket structs and bounded byte slices.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(unavailable());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut local: libc::sockaddr_nl = unsafe { mem::zeroed() };
    local.nl_family = libc::AF_NETLINK as u16;
    let size = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    if unsafe { libc::bind(socket.as_raw_fd(), std::ptr::from_ref(&local).cast(), size) } != 0 {
        return Err(unavailable());
    }
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                std::ptr::from_ref(&timeout).cast(),
                mem::size_of_val(&timeout) as libc::socklen_t,
            )
        } != 0
        {
            return Err(unavailable());
        }
    }
    let mut actual_size = size;
    if unsafe {
        libc::getsockname(
            socket.as_raw_fd(),
            std::ptr::from_mut(&mut local).cast(),
            &mut actual_size,
        )
    } != 0
        || actual_size != size
        || local.nl_pid == 0
    {
        return Err(unavailable());
    }
    let bytes = request(index, owner, local.nl_pid);
    let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            bytes.as_ptr().cast(),
            bytes.len(),
            0,
            std::ptr::from_ref(&kernel).cast(),
            size,
        )
    };
    if sent != bytes.len() as isize {
        return Err(unavailable());
    }
    let mut response = [0_u8; 4096];
    let mut peer: libc::sockaddr_nl = unsafe { mem::zeroed() };
    let mut peer_size = size;
    let received = unsafe {
        libc::recvfrom(
            socket.as_raw_fd(),
            response.as_mut_ptr().cast(),
            response.len(),
            libc::MSG_TRUNC,
            std::ptr::from_mut(&mut peer).cast(),
            &mut peer_size,
        )
    };
    if received < 0
        || received as usize > response.len()
        || peer_size != size
        || peer.nl_family != libc::AF_NETLINK as u16
        || peer.nl_pid != 0
        || peer.nl_groups != 0
    {
        return Err(unavailable());
    }
    ack(
        &response[..received as usize],
        local.nl_pid,
        u32::from_ne_bytes(bytes[..4].try_into().expect("request header")),
    )
}

fn bind_sync(plan: NativeBridgePlan) -> Result<NativeBridgeObservation, ApiError> {
    plan.validate_at(Utc::now())?;
    host::authority()?;
    let _bridge = host::bridge_lock(&plan.allocation)?;
    let _allocation = host::allocation_lock(&plan.allocation)?;
    plan.validate_at(Utc::now())?;
    let before = observed_alias(&plan)?;
    let owner = plan.allocation.owner();
    if !before.is_empty() && before != owner {
        return Err(error(
            ErrorCode::Conflict,
            "native bridge has a foreign alias",
        ));
    }
    let changed = before.is_empty();
    if changed {
        set_alias(plan.allocation.ifindex, &owner)?;
    }
    if observed_alias(&plan)? != owner {
        return Err(unavailable());
    }
    plan.validate_at(Utc::now())?;
    Ok(NativeBridgeObservation {
        identity_sha256: plan.identity.digest(),
        allocation: plan.allocation,
        provisioning_token: plan.provisioning_token,
        alias: owner,
        changed,
    })
}

pub async fn bind(plan: NativeBridgePlan) -> Result<NativeBridgeObservation, ApiError> {
    tokio::task::spawn_blocking(move || bind_sync(plan))
        .await
        .map_err(|_| unavailable())?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn alias_request_changes_only_the_indexed_link_alias() {
        let bytes = request(72, "goldenhoop:abc", 99);
        assert_eq!(
            u16::from_ne_bytes(bytes[4..6].try_into().unwrap()),
            libc::RTM_NEWLINK
        );
        assert_eq!(
            u16::from_ne_bytes(bytes[6..8].try_into().unwrap()),
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16
        );
        assert_eq!(i32::from_ne_bytes(bytes[20..24].try_into().unwrap()), 72);
        assert_eq!(&bytes[16..20], &[0; 4]);
        assert_eq!(&bytes[24..32], &[0; 8]);
        assert_eq!(
            u16::from_ne_bytes(bytes[34..36].try_into().unwrap()),
            libc::IFLA_IFALIAS
        );
        assert_eq!(&bytes[36..51], b"goldenhoop:abc\0");
    }
    #[test]
    fn only_complete_matching_success_acknowledgements_confirm_alias_writes() {
        let request = request(72, "goldenhoop:abc", 99);
        let length = u32::from_ne_bytes(request[..4].try_into().unwrap());
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&36_u32.to_ne_bytes());
        bytes.extend_from_slice(&(libc::NLMSG_ERROR as u16).to_ne_bytes());
        bytes.extend_from_slice(&0_u16.to_ne_bytes());
        bytes.extend_from_slice(&1_u32.to_ne_bytes());
        bytes.extend_from_slice(&99_u32.to_ne_bytes());
        bytes.extend_from_slice(&0_i32.to_ne_bytes());
        bytes.extend_from_slice(&request[..16]);
        ack(&bytes, 99, length).unwrap();
        for offset in [0, 4, 8, 12, 16, 20, 24, 28, 32] {
            let mut bad = bytes.clone();
            bad[offset] ^= 1;
            assert!(ack(&bad, 99, length).is_err(), "offset {offset}");
        }
        for length in 0..bytes.len() {
            assert!(
                ack(
                    &bytes[..length],
                    99,
                    u32::from_ne_bytes(request[..4].try_into().unwrap())
                )
                .is_err()
            );
        }
        bytes.push(0);
        assert!(ack(&bytes, 99, length).is_err());
    }
}
