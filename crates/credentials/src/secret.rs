use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Deliberately lacks Debug. Serialization is limited to private control and
/// encrypted vault input; public metadata uses CredentialBinding instead.
pub struct Secret(pub Zeroizing<String>);
impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Zeroizing::new(String::deserialize(deserializer)?);
        if value.is_empty() || value.len() > 32 * 1024 {
            return Err(serde::de::Error::custom("invalid credential value size"));
        }
        Ok(Self(value))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretSource {
    Literal { value: Secret },
    Exchange { resolver: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteCredential {
    pub expected_revision: u64,
    pub binding: crate::BindingSpec,
    pub secret: SecretSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialState {
    Pending,
    Active,
    Revoking,
    Revoked,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialBinding {
    pub id: Uuid,
    pub sandbox_id: Uuid,
    pub revision: u64,
    pub applied_revision: Option<u64>,
    pub state: CredentialState,
    pub binding: crate::BindingSpec,
}
