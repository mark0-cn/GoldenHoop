//! Guest-only PID1. Host execution is refused before any filesystem change.
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
pub mod linux;

#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GuestConfig {
    pub control_port: u32,
    /// Includes the agent and all userland descendants in its guest cgroup.
    pub pids: u32,
}

impl Default for GuestConfig {
    fn default() -> Self {
        Self {
            control_port: 52,
            pids: 256,
        }
    }
}

impl GuestConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.control_port == 0 || self.control_port >= 1024 || !(16..=65535).contains(&self.pids)
        {
            return Err("invalid guest control port or task budget");
        }
        Ok(())
    }
}

pub fn is_guest_init_context() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: identity queries have no arguments or memory preconditions.
        unsafe { libc::getpid() == 1 && libc::geteuid() == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_budget_and_reserved_control_port_cannot_be_disabled() {
        assert!(GuestConfig::default().validate().is_ok());
        for port in [0, 1024, u32::MAX] {
            assert!(
                GuestConfig {
                    control_port: port,
                    ..GuestConfig::default()
                }
                .validate()
                .is_err()
            );
        }
        for pids in [0, 1, 15, 65536, u32::MAX] {
            assert!(
                GuestConfig {
                    pids,
                    ..GuestConfig::default()
                }
                .validate()
                .is_err()
            );
        }
        assert!(serde_json::from_str::<GuestConfig>(r#"{"unknown":true}"#).is_err());
    }

    #[test]
    fn ordinary_host_process_cannot_enter_guest_boot() {
        assert!(!is_guest_init_context());
    }
}
