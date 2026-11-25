use crate::error;
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Trusted planned resource identity before any provider or kernel allocation.
/// Its digest identifies data; it is neither a credential nor enforcement proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkIdentity {
    pub installation_id: Uuid,
    pub sandbox_id: Uuid,
    pub generation: Uuid,
    pub profile: String,
}
impl NetworkIdentity {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.installation_id.is_nil()
            || self.sandbox_id.is_nil()
            || self.generation.is_nil()
            || self.profile.is_empty()
            || self.profile.len() > 128
            || !self
                .profile
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(error(
                ErrorCode::InvalidRequest,
                "invalid planned network identity",
            ));
        }
        Ok(())
    }
    pub fn network_name(&self) -> String {
        format!("goldenhoop-net-{}", self.generation.simple())
    }
    pub fn bridge_name(&self) -> String {
        format!("ghn{}", &self.generation.simple().to_string()[..12])
    }
    pub fn digest(&self) -> String {
        format!("{:x}", Sha256::digest(self.bytes()))
    }
    pub fn ipv6_subnet(&self) -> String {
        let hash = Sha256::digest(self.bytes());
        let network = std::net::Ipv6Addr::new(
            0xfd00 | u16::from(hash[0]),
            u16::from_be_bytes([hash[1], hash[2]]),
            u16::from_be_bytes([hash[3], hash[4]]),
            1,
            0,
            0,
            0,
            0,
        );
        format!("{network}/64")
    }
    fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(1_u8, self)).expect("network identity")
    }
}
