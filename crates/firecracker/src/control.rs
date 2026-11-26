//! Private guest-init control. These messages are confined to the reserved
//! host-CID2 endpoint; they are not public workload agent methods.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const GUEST_CONTROL_VERSION: u16 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "guest_control", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestControlRequest {
    Info,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestControlInfo {
    pub protocol: u16,
    pub generation: Option<Uuid>,
    pub pids: u32,
    pub agent_pid: u32,
    pub host_cid: u32,
    pub no_new_privileges: bool,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestBootIdentity {
    pub pids: u32,
    pub generation: Option<Uuid>,
}

impl GuestBootIdentity {
    pub fn from_cmdline(cmdline: &str, default_pids: u32) -> Result<Self, &'static str> {
        if cmdline.len() > 4096 {
            return Err("guest command line exceeds limit");
        }
        let mut pids = None;
        let mut generation = None;
        for word in cmdline
            .split_whitespace()
            .filter(|word| word.starts_with("goldenhoop."))
        {
            if let Some(value) = word.strip_prefix("goldenhoop.pids=") {
                let parsed = value
                    .parse::<u32>()
                    .map_err(|_| "invalid guest task argument")?;
                if pids.is_some() || parsed.to_string() != value {
                    return Err("ambiguous guest task argument");
                }
                pids = Some(parsed);
            } else if let Some(value) = word.strip_prefix("goldenhoop.generation=") {
                let parsed =
                    Uuid::parse_str(value).map_err(|_| "invalid guest generation argument")?;
                if generation.is_some() || parsed.is_nil() || parsed.to_string() != value {
                    return Err("ambiguous guest generation argument");
                }
                generation = Some(parsed);
            } else {
                return Err("unknown guest boot argument");
            }
        }
        let pids = pids.unwrap_or(default_pids);
        if !(16..=65535).contains(&pids) {
            return Err("guest task argument outside supported limits");
        }
        Ok(Self { pids, generation })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_identity_is_bounded_unambiguous_and_not_an_ambient_environment_override() {
        let id = Uuid::new_v4();
        let good = GuestBootIdentity::from_cmdline(
            &format!("root=/dev/vda goldenhoop.pids=32 goldenhoop.generation={id}"),
            256,
        )
        .unwrap();
        assert_eq!(good.pids, 32);
        assert_eq!(good.generation, Some(id));
        assert_eq!(
            GuestBootIdentity::from_cmdline("root=/dev/vda", 256)
                .unwrap()
                .generation,
            None
        );
        for text in [
            "goldenhoop.pids=0",
            "goldenhoop.pids=65536",
            "goldenhoop.pids=032",
            "goldenhoop.pids=+32",
            "goldenhoop.pids=32 goldenhoop.pids=32",
            "goldenhoop.generation=00000000-0000-0000-0000-000000000000",
            "goldenhoop.secret=ignored",
        ] {
            assert!(
                GuestBootIdentity::from_cmdline(text, 256).is_err(),
                "{text}"
            );
        }
    }
}
