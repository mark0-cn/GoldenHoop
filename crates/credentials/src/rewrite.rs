use crate::{BindingSpec, BoundRequest, Secret, SubstituteAt, error};
use bytes::Bytes;
use futures_util::StreamExt;
use goldenhoop_protocol::{ApiError, ErrorCode};
use zeroize::Zeroizing;

struct PrivateBytes(Zeroizing<Vec<u8>>);
impl AsRef<[u8]> for PrivateBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub(crate) fn uri_encoded(value: &str) -> Zeroizing<String> {
    let mut result = Zeroizing::new(String::new());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            result.push(char::from(byte));
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}

pub(crate) fn lower_escapes(value: &str) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new(value.as_bytes().to_vec());
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'%' {
            bytes[i + 1].make_ascii_lowercase();
            bytes[i + 2].make_ascii_lowercase();
            i += 3;
        } else {
            i += 1;
        }
    }
    Zeroizing::new(String::from_utf8(bytes.to_vec()).expect("ASCII URI encoding"))
}

pub(crate) fn form_encoded(value: &str) -> Zeroizing<String> {
    let mut url = reqwest::Url::parse("http://placeholder.invalid/").expect("fixed URL");
    url.query_pairs_mut().append_pair("v", value);
    Zeroizing::new(
        url.query()
            .expect("inserted pair")
            .strip_prefix("v=")
            .expect("known field")
            .to_owned(),
    )
}

fn replace(
    input: &[u8],
    needle: &[u8],
    value: &[u8],
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    if needle.is_empty() {
        return Err(error(
            ErrorCode::InvalidRequest,
            "empty credential placeholder",
        ));
    }
    let mut output = Zeroizing::new(Vec::new());
    let mut offset = 0;
    while offset < input.len() {
        let matching = input[offset..].starts_with(needle);
        let next = if matching {
            value
        } else {
            &input[offset..offset + 1]
        };
        if output.len().saturating_add(next.len()) > maximum {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "credential substitution exceeds size limit",
            ));
        }
        output.extend_from_slice(next);
        offset += if matching { needle.len() } else { 1 };
    }
    Ok(output)
}

fn replace_text(
    input: &str,
    needle: &str,
    value: &str,
    maximum: usize,
) -> Result<Zeroizing<String>, ApiError> {
    let bytes = replace(
        input.as_bytes(),
        needle.as_bytes(),
        value.as_bytes(),
        maximum,
    )?;
    Ok(Zeroizing::new(
        std::str::from_utf8(&bytes)
            .map_err(|_| error(ErrorCode::InvalidRequest, "invalid credential substitution"))?
            .to_owned(),
    ))
}

pub(crate) async fn rewrite(
    request: &mut BoundRequest,
    spec: &BindingSpec,
    secret: &Secret,
) -> Result<(), ApiError> {
    for item in &spec.substitutions {
        match &item.at {
            SubstituteAt::Path => {
                let (path, query) = request.identity.path_and_query.split_once('?').map_or(
                    (request.identity.path_and_query.as_str(), None),
                    |(p, q)| (p, Some(q)),
                );
                let value = uri_encoded(&secret.0);
                let path = replace_text(path, &item.placeholder, &value, 8192)?;
                let updated = if let Some(query) = query {
                    format!("{}?{query}", path.as_str())
                } else {
                    path.to_string()
                };
                request.identity.path_and_query = updated;
            }
            SubstituteAt::Query { name } => {
                if let Some((path, query)) = request.identity.path_and_query.split_once('?') {
                    let mut url =
                        reqwest::Url::parse(&format!("http://placeholder.invalid/?{query}"))
                            .map_err(|_| {
                                error(ErrorCode::InvalidRequest, "invalid placeholder query")
                            })?;
                    let mut fields = Vec::new();
                    for (key, value) in url.query_pairs() {
                        let value = if key == name.as_str() {
                            replace_text(&value, &item.placeholder, &secret.0, 8192)?
                        } else {
                            Zeroizing::new(value.into_owned())
                        };
                        fields.push((key.into_owned(), value));
                    }
                    url.set_query(None);
                    {
                        let mut pairs = url.query_pairs_mut();
                        for (key, value) in &fields {
                            pairs.append_pair(key, value);
                        }
                    }
                    request.identity.path_and_query =
                        format!("{path}?{}", url.query().unwrap_or(""));
                }
            }
            SubstituteAt::Header { name } => {
                let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| error(ErrorCode::InvalidRequest, "invalid placeholder header"))?;
                let mut updated = Vec::new();
                for value in request.headers.get_all(&name) {
                    let value = value.to_str().map_err(|_| {
                        error(
                            ErrorCode::InvalidRequest,
                            "invalid placeholder header value",
                        )
                    })?;
                    let value = replace_text(value, &item.placeholder, &secret.0, 16 * 1024)?;
                    let mut value =
                        reqwest::header::HeaderValue::from_str(&value).map_err(|_| {
                            error(
                                ErrorCode::InvalidRequest,
                                "invalid placeholder header value",
                            )
                        })?;
                    value.set_sensitive(true);
                    updated.push(value);
                }
                request.headers.remove(&name);
                for value in updated {
                    request.headers.append(name.clone(), value);
                }
            }
            SubstituteAt::Body => {}
        }
    }
    if request.identity.path_and_query.len() > 8192
        || !spec.matches(
            request.identity.scheme,
            &request.identity.host,
            request.identity.port,
            request.identity.method.as_str(),
            &request.identity.path_and_query,
        )?
    {
        return Err(error(
            ErrorCode::Forbidden,
            "credential substitution leaves its binding",
        ));
    }
    let body_rewrites: Vec<_> = spec
        .substitutions
        .iter()
        .filter(|v| matches!(v.at, SubstituteAt::Body))
        .collect();
    if !body_rewrites.is_empty() {
        let mut source =
            std::mem::replace(&mut request.body, Box::pin(futures_util::stream::empty()));
        let mut buffer = Zeroizing::new(Vec::new());
        let mut oversized = None;
        while let Some(chunk) = source.next().await {
            let chunk = chunk?;
            if buffer.len().saturating_add(chunk.len()) > 1024 * 1024 {
                oversized = Some(chunk);
                break;
            }
            buffer.extend_from_slice(&chunk);
        }
        if let Some(chunk) = oversized {
            // Above the buffering threshold, preserve the exact stream and skip
            // body substitutions; header/path/query injection still applies.
            let prefix = Bytes::from_owner(PrivateBytes(buffer));
            let stream = futures_util::stream::iter([Ok(prefix), Ok(chunk)]).chain(source);
            request.body = Box::pin(stream);
        } else {
            for item in body_rewrites {
                buffer = replace(
                    &buffer,
                    item.placeholder.as_bytes(),
                    secret.0.as_bytes(),
                    1024 * 1024,
                )?;
            }
            request.body = Box::pin(futures_util::stream::once(async move {
                Ok(Bytes::from_owner(PrivateBytes(buffer)))
            }));
        }
    }
    Ok(())
}
