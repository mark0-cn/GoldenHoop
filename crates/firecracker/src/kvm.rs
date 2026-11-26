use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KvmState {
    UnsupportedHost,
    MissingDevice,
    AccessDenied,
    InvalidDevice,
    DeviceQueryFailed,
    UnsupportedApi,
    VmCreationRefused,
    Ready,
}

#[derive(Debug, Serialize)]
pub struct KvmObservation {
    pub operating_system: &'static str,
    pub architecture: &'static str,
    pub state: KvmState,
    pub api_version: Option<i32>,
    pub error_errno: Option<i32>,
    pub observed_at: DateTime<Utc>,
    /// A device/empty-VM check cannot establish guest execution or isolation.
    pub runtime_capabilities_verified: bool,
}

/// Opens the actual fixed KVM device and creates/drops an empty VM fd. Does not
/// load modules, alter permissions, allocate guest RAM, start a VMM or fall back.
pub fn probe_kvm() -> KvmObservation {
    let observation = initial_observation();
    #[cfg(target_os = "linux")]
    {
        let mut observation = observation;
        probe_linux(&mut observation);
        observation
    }
    #[cfg(not(target_os = "linux"))]
    {
        observation
    }
}

fn initial_observation() -> KvmObservation {
    KvmObservation {
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        state: KvmState::UnsupportedHost,
        api_version: None,
        error_errno: None,
        observed_at: Utc::now(),
        runtime_capabilities_verified: false,
    }
}

#[cfg(target_os = "linux")]
fn probe_linux(observation: &mut KvmObservation) {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};

    let device = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/kvm")
    {
        Ok(device) => device,
        Err(error) => {
            observation.error_errno = error.raw_os_error();
            observation.state = match error.kind() {
                std::io::ErrorKind::NotFound => KvmState::MissingDevice,
                std::io::ErrorKind::PermissionDenied => KvmState::AccessDenied,
                _ => KvmState::InvalidDevice,
            };
            return;
        }
    };
    if !device
        .metadata()
        .is_ok_and(|metadata| metadata.file_type().is_char_device())
    {
        observation.state = KvmState::InvalidDevice;
        return;
    }
    probe_device(observation, &device);
}

#[cfg(target_os = "linux")]
fn probe_device(observation: &mut KvmObservation, device: &std::fs::File) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: GET_API_VERSION takes a zero value, not a pointer. Supply that
    // third C-varargs argument explicitly: the kernel rejects a nonzero arg.
    let version = unsafe { libc::ioctl(device.as_raw_fd(), 0xae00, 0 as libc::c_ulong) };
    observation.api_version = (version >= 0).then_some(version);
    if version < 0 {
        observation.error_errno = std::io::Error::last_os_error().raw_os_error();
        observation.state = KvmState::DeviceQueryFailed;
        return;
    }
    if version != 12 {
        observation.state = KvmState::UnsupportedApi;
        return;
    }
    // SAFETY: CREATE_VM takes the architecture's default machine type (0), not
    // a pointer. On success it returns a new independently owned descriptor.
    let vm = unsafe { libc::ioctl(device.as_raw_fd(), 0xae01, 0 as libc::c_ulong) };
    if vm < 0 {
        observation.error_errno = std::io::Error::last_os_error().raw_os_error();
        observation.state = KvmState::VmCreationRefused;
        return;
    }
    // SAFETY: a successful CREATE_VM returns a fresh fd that has no other owner.
    drop(unsafe { OwnedFd::from_raw_fd(vm) });
    observation.state = KvmState::Ready;
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn actual_non_kvm_descriptor_records_query_errno_without_claiming_an_api_version() {
        let device = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        let mut observation = initial_observation();
        probe_device(&mut observation, &device);
        assert_eq!(observation.state, KvmState::DeviceQueryFailed);
        assert_eq!(observation.api_version, None);
        assert_eq!(observation.error_errno, Some(libc::ENOTTY));
        assert!(!observation.runtime_capabilities_verified);
    }
}
