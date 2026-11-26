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
