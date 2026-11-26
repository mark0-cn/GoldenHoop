//! Trusted credential handling. No data-plane support is advertised merely by
//! constructing a vault, parsing a binding or compiling this crate.
mod binding;
mod vault;
pub use binding::*;
pub use vault::*;
mod secret;
pub use secret::*;
mod broker;
pub use broker::*;
mod tls;
pub use tls::*;
mod authority;
pub mod frontend;
pub use authority::*;
mod exchange;
mod rewrite;
pub use exchange::*;

use goldenhoop_protocol::{ApiError, ErrorCode};

fn error(code: ErrorCode, message: &'static str) -> ApiError {
    ApiError::new(code, message)
}

pub type UpstreamCertificate = reqwest::Certificate;
/// Operator-owned additional trust only. Public bindings cannot provide roots.
pub fn upstream_certificates(values: Vec<String>) -> Result<Vec<UpstreamCertificate>, ApiError> {
    if values.len() > 4
        || values
            .iter()
            .any(|v| v.len() > 16384 || v.contains("PRIVATE KEY"))
    {
        return Err(error(
            ErrorCode::QuotaExceeded,
            "trusted upstream CA budget exceeded",
        ));
    }
    values
        .into_iter()
        .map(|v| {
            reqwest::Certificate::from_pem(v.as_bytes())
                .map_err(|_| error(ErrorCode::InvalidRequest, "invalid trusted upstream CA"))
        })
        .collect()
}
