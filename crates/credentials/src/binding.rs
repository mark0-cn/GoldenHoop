use crate::error;
use goldenhoop_policy::Domain;
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    Http,
    Https,
}
impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Injection {
    Bearer,
    Basic { username: String },
    Header { name: String },
    Placeholders,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubstituteAt {
    Path,
    Query { name: String },
    Header { name: String },
    Body,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Substitution {
    pub placeholder: String,
    pub at: SubstituteAt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingSpec {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub methods: BTreeSet<String>,
    pub path_prefix: String,
    pub injection: Injection,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub substitutions: Vec<Substitution>,
}

pub fn canonical_host(value: &str) -> Result<String, ApiError> {
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(ip.to_canonical().to_string());
    }
    Ok(Domain::parse(value)?.as_str().to_owned())
}

/// The broker refuses path forms whose interpretation can change between HTTP
/// stacks. All bounded percent-decoding forms must stay within the same binding;
/// dot segments, controls, backslashes and excessive nesting are refused.
pub fn canonical_path(value: &str) -> Result<(), ApiError> {
    path_forms(value).map(|_| ())
}

fn path_forms(value: &str) -> Result<Vec<String>, ApiError> {
    let mut path = value.split('?').next().unwrap_or("").to_owned();
    let mut forms = Vec::new();
    for _ in 0..=8 {
        if !path.starts_with('/')
            || path.len() > 8192
            || path.contains(['\\', '#', '?'])
            || path.bytes().any(|v| v <= 32 || v >= 127)
            || path.split('/').any(|s| s == "." || s == "..")
        {
            return Err(error(
                ErrorCode::Forbidden,
                "ambiguous credential request path",
            ));
        }
        forms.push(path.clone());
        if !path.contains('%') {
            return Ok(forms);
        }
        let bytes = path.as_bytes();
        let mut decoded = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                let hex = bytes.get(index + 1..index + 3).ok_or_else(|| {
                    error(ErrorCode::Forbidden, "ambiguous credential request path")
                })?;
                let text = std::str::from_utf8(hex).map_err(|_| {
                    error(ErrorCode::Forbidden, "ambiguous credential request path")
                })?;
                decoded.push(u8::from_str_radix(text, 16).map_err(|_| {
                    error(ErrorCode::Forbidden, "ambiguous credential request path")
                })?);
                index += 3;
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
        path = String::from_utf8(decoded)
            .map_err(|_| error(ErrorCode::Forbidden, "ambiguous credential request path"))?;
    }
    Err(error(
        ErrorCode::Forbidden,
        "credential path encoding exceeds limit",
    ))
}

impl BindingSpec {
    pub fn canonicalize(&self) -> Result<Self, ApiError> {
        canonical_path(&self.path_prefix)?;
        if self.port == 0
            || self.path_prefix.contains('?')
            || self.methods.is_empty()
            || self.methods.len() > 32
            || self.methods.iter().any(|m| {
                m.is_empty()
                    || m.len() > 32
                    || !m.bytes().all(|b| b.is_ascii_uppercase() || b == b'-')
                    || m == "CONNECT"
                    || m == "TRACE"
            })
        {
            return Err(error(
                ErrorCode::InvalidRequest,
                "invalid credential binding",
            ));
        }
        match &self.injection {
            Injection::Basic { username } => {
                if username.len() > 1024
                    || username.contains(':')
                    || username.bytes().any(|v| v < 32 || v == 127)
                {
                    return Err(error(
                        ErrorCode::InvalidRequest,
                        "invalid basic credential user",
                    ));
                }
            }
            Injection::Header { name } => {
                let parsed = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| error(ErrorCode::InvalidRequest, "invalid credential header"))?;
                if [
                    "host",
                    "content-length",
                    "transfer-encoding",
                    "connection",
                    "upgrade",
                    "proxy-authorization",
                    "proxy-authenticate",
                    "te",
                    "trailer",
                ]
                .contains(&parsed.as_str())
                    || parsed.as_str().starts_with(':')
                {
                    return Err(error(
                        ErrorCode::InvalidRequest,
                        "reserved credential header",
                    ));
                }
            }
            Injection::Bearer => {}
            Injection::Placeholders => {
                if self.substitutions.is_empty() {
                    return Err(error(
                        ErrorCode::InvalidRequest,
                        "placeholder injection requires substitutions",
                    ));
                }
            }
        }
        if self.substitutions.len() > 32 {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "credential substitution limit exceeded",
            ));
        }
        for replacement in &self.substitutions {
            if replacement.placeholder.is_empty()
                || replacement.placeholder.len() > 256
                || replacement
                    .placeholder
                    .bytes()
                    .any(|v| !(33..=126).contains(&v))
            {
                return Err(error(
                    ErrorCode::InvalidRequest,
                    "invalid credential placeholder",
                ));
            }
            match &replacement.at {
                SubstituteAt::Header { name } => {
                    let header =
                        reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                            error(ErrorCode::InvalidRequest, "invalid placeholder header")
                        })?;
                    if [
                        "host",
                        "connection",
                        "content-length",
                        "transfer-encoding",
                        "upgrade",
                        "proxy-authorization",
                        "proxy-authenticate",
                        "te",
                        "trailer",
                    ]
                    .contains(&header.as_str())
                    {
                        return Err(error(
                            ErrorCode::InvalidRequest,
                            "reserved placeholder header",
                        ));
                    }
                }
                SubstituteAt::Query { name } => {
                    if name.is_empty() || name.len() > 128 || name.chars().any(|v| v.is_control()) {
                        return Err(error(
                            ErrorCode::InvalidRequest,
                            "invalid placeholder query field",
                        ));
                    }
                }
                SubstituteAt::Path | SubstituteAt::Body => {}
            }
        }
        let mut result = self.clone();
        result.host = canonical_host(&self.host)?;
        if let Injection::Header { name } = &mut result.injection {
            *name = name.to_ascii_lowercase();
        }
        Ok(result)
    }

    pub fn matches(
        &self,
        scheme: Scheme,
        host: &str,
        port: u16,
        method: &str,
        path: &str,
    ) -> Result<bool, ApiError> {
        let forms = path_forms(path)?;
        let prefix = &self.path_prefix;
        let path_matches = forms.iter().all(|path| {
            path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|tail| prefix.ends_with('/') || tail.starts_with('/'))
        });
        Ok(self.scheme == scheme
            && self.host == canonical_host(host)?
            && self.port == port
            && self.methods.contains(method)
            && path_matches)
    }
}
