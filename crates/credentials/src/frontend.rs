//! HTTP/1.1 and HTTP/2 over a trusted socket identity. The Linux allocation
//! adapter must verify source ownership and SO_ORIGINAL_DST before calling it.
use crate::{
    BoundRequest, Broker, CertificateAuthority, RequestIdentity, Scheme, canonical_host, error,
};
use bytes::Bytes;
use futures_util::StreamExt;
use goldenhoop_protocol::{ApiError, ErrorCode};
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response, StatusCode, Version,
    body::{Frame, Incoming},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{LazyConfigAcceptor, rustls};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct ConnectionIdentity {
    pub sandbox_id: Uuid,
    pub original: SocketAddr,
    pub tls: bool,
}

type HttpBody = UnsyncBoxBody<Bytes, ApiError>;

fn failure(error: ApiError) -> Response<HttpBody> {
    let status = match error.code {
        ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
        ErrorCode::UnsupportedCapability => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::BackendUnavailable | ErrorCode::DeadlineExceeded => StatusCode::BAD_GATEWAY,
        _ => StatusCode::FORBIDDEN,
    };
    let body = Full::new(Bytes::from(
        serde_json::to_vec(&error).expect("typed error"),
    ))
    .map_err(|never: Infallible| match never {})
    .boxed_unsync();
    Response::builder()
        .status(status)
        .header("cache-control", "no-store")
        .header("content-type", "application/json")
        .body(body)
        .expect("fixed response")
}

async fn request(
    broker: Broker,
    connection: ConnectionIdentity,
    sni: Option<String>,
    request: Request<Incoming>,
) -> Result<Response<HttpBody>, ApiError> {
    if !matches!(request.version(), Version::HTTP_11 | Version::HTTP_2) {
        return Err(error(
            ErrorCode::UnsupportedCapability,
            "credential transport requires HTTP/1.1 or HTTP/2",
        ));
    }
    if request.headers().contains_key("trailer")
        || request.headers().contains_key("te")
        || request.headers().contains_key("upgrade")
    {
        return Err(error(
            ErrorCode::UnsupportedCapability,
            "credential trailers and protocol upgrades are unsupported",
        ));
    }
    let scheme = if connection.tls {
        Scheme::Https
    } else {
        Scheme::Http
    };
    if request
        .uri()
        .scheme_str()
        .is_some_and(|v| v != scheme.as_str())
    {
        return Err(error(
            ErrorCode::Forbidden,
            "HTTP and socket scheme disagree",
        ));
    }
    let authority = request
        .uri()
        .authority()
        .map(|v| v.as_str())
        .or_else(|| request.headers().get("host").and_then(|v| v.to_str().ok()))
        .ok_or_else(|| error(ErrorCode::Forbidden, "HTTP authority is required"))?;
    let url = reqwest::Url::parse(&format!("{}://{authority}/", scheme.as_str()))
        .map_err(|_| error(ErrorCode::Forbidden, "invalid HTTP authority"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(connection.original.port())
    {
        return Err(error(
            ErrorCode::Forbidden,
            "HTTP authority and original port disagree",
        ));
    }
    let host = canonical_host(
        url.host_str()
            .ok_or_else(|| error(ErrorCode::Forbidden, "missing HTTP host"))?
            .trim_matches(['[', ']']),
    )?;
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |v| v.as_str())
        .to_owned();
    if path.len() > 8192 {
        return Err(error(
            ErrorCode::QuotaExceeded,
            "credential request target exceeds limit",
        ));
    }
    let (mut parts, mut incoming) = request.into_parts();
    // H2's :authority is independently compared with any Host header by Broker.
    if !parts.headers.contains_key("host") {
        parts
            .headers
            .insert("host", authority_header(&host, connection.original.port())?);
    }
    let body = async_stream::stream! {
        let mut count=0usize;
        while let Some(frame)=incoming.frame().await {
            match frame {
                Ok(frame)=>match frame.into_data() {
                    Ok(bytes)=>{
                        count=count.saturating_add(bytes.len());
                        if count>64*1024*1024 {yield Err(error(ErrorCode::QuotaExceeded,"credential request body exceeds limit"));break;}
                        yield Ok(bytes);
                    },
                    Err(_)=>{yield Err(error(ErrorCode::UnsupportedCapability,"credential request trailers are unsupported"));break;},
                },
                Err(_)=>{yield Err(error(ErrorCode::InvalidRequest,"credential request body was interrupted"));break;},
            }
        }
    };
    let response = broker
        .forward(BoundRequest {
            identity: RequestIdentity {
                sandbox_id: connection.sandbox_id,
                scheme,
                host,
                port: connection.original.port(),
                destination: connection.original.ip(),
                tls_server_name: sni,
                method: parts.method,
                path_and_query: path,
            },
            headers: parts.headers,
            body: Box::pin(body),
        })
        .await?;
    let mut output = Response::new(
        StreamBody::new(response.body.map(|chunk| chunk.map(Frame::data))).boxed_unsync(),
    );
    *output.status_mut() = response.status;
    *output.headers_mut() = response.headers;
    Ok(output)
}

fn authority_header(host: &str, port: u16) -> Result<hyper::header::HeaderValue, ApiError> {
    let host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    format!("{host}:{port}")
        .parse()
        .map_err(|_| error(ErrorCode::Forbidden, "invalid bound HTTP authority"))
}

async fn http<IO>(
    io: IO,
    broker: Broker,
    identity: ConnectionIdentity,
    sni: Option<String>,
    stop: CancellationToken,
) -> Result<(), ApiError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let active = Arc::new(tokio::sync::Semaphore::new(16));
    let service_active = active.clone();
    let service = service_fn(move |input| {
        let broker = broker.clone();
        let sni = sni.clone();
        let active = service_active.clone();
        async move {
            let Ok(permit) = active.try_acquire_owned() else {
                return Ok::<_, Infallible>(failure(error(
                    ErrorCode::QuotaExceeded,
                    "credential connection request limit reached",
                )));
            };
            let response = match request(broker, identity, sni, input).await {
                Ok(response) => response,
                Err(error) => failure(error),
            };
            let (parts, mut body) = response.into_parts();
            let stream = async_stream::stream! {let _permit=permit;while let Some(frame)=body.frame().await {yield frame;}};
            Ok::<_, Infallible>(Response::from_parts(
                parts,
                StreamBody::new(stream).boxed_unsync(),
            ))
        }
    });
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5))
        .max_buf_size(64 * 1024);
    builder
        .http2()
        .max_concurrent_streams(16)
        .max_header_list_size(64 * 1024)
        .max_send_buf_size(128 * 1024);
    let result = {
        let connection = builder.serve_connection(TokioIo::new(io), service);
        tokio::pin!(connection);
        tokio::select! {
            _=stop.cancelled()=>Ok(()),
            result=&mut connection=>result.map_err(|_|error(ErrorCode::BackendUnavailable,"credential HTTP transport ended")),
        }
    };
    // H2 can spawn request futures. A closed socket alone is not a drain
    // receipt: wait until both pending handlers and response bodies drop.
    let drained = tokio::time::timeout(Duration::from_secs(12), active.acquire_many(16)).await;
    if !matches!(drained, Ok(Ok(_))) {
        return Err(error(
            ErrorCode::BackendUnavailable,
            "credential request collection is unconfirmed",
        ));
    }
    result
}

pub async fn serve_connection<IO>(
    io: IO,
    broker: Broker,
    ca: Arc<CertificateAuthority>,
    identity: ConnectionIdentity,
    stop: CancellationToken,
) -> Result<(), ApiError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if identity.sandbox_id.is_nil() || identity.original.port() == 0 {
        return Err(error(
            ErrorCode::Forbidden,
            "missing verified connection identity",
        ));
    }
    if !identity.tls {
        return http(io, broker, identity, None, stop).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let handshake = async {
        let hello = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io)
            .await
            .map_err(|_| error(ErrorCode::Forbidden, "credential TLS client hello refused"))?;
        let name = hello
            .client_hello()
            .server_name()
            .map(str::to_owned)
            .unwrap_or_else(|| identity.original.ip().to_string());
        let name = canonical_host(&name)?;
        let config = ca.server_config(&name)?;
        let stream = hello
            .into_stream(config)
            .await
            .map_err(|_| error(ErrorCode::Forbidden, "credential TLS handshake refused"))?;
        Ok::<_, ApiError>((stream, name))
    };
    let (io, name) = tokio::select! {
        _=stop.cancelled()=>return Ok(()),
        result=tokio::time::timeout_at(deadline,handshake)=>result.map_err(|_|error(ErrorCode::DeadlineExceeded,"credential TLS handshake exceeded deadline"))??,
    };
    http(io, broker, identity, Some(name), stop).await
}

#[cfg(target_os = "linux")]
pub fn original_destination(stream: &tokio::net::TcpStream) -> Result<SocketAddr, ApiError> {
    use std::{
        mem::{size_of, zeroed},
        os::fd::AsRawFd,
    };
    let local = stream
        .local_addr()
        .map_err(|_| error(ErrorCode::Forbidden, "cannot inspect credential socket"))?;
    let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
    let mut length = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let level = if local.is_ipv4() {
        libc::SOL_IP
    } else {
        libc::SOL_IPV6
    };
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            level,
            80,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    };
    if status != 0 {
        return Err(error(
            ErrorCode::Forbidden,
            "original credential destination is unavailable",
        ));
    }
    let original = match i32::from(storage.ss_family) {
        libc::AF_INET if length as usize == size_of::<libc::sockaddr_in>() => {
            let value =
                unsafe { *(&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            SocketAddr::new(
                std::net::Ipv4Addr::from(value.sin_addr.s_addr.to_ne_bytes()).into(),
                u16::from_be(value.sin_port),
            )
        }
        libc::AF_INET6 if length as usize == size_of::<libc::sockaddr_in6>() => {
            let value = unsafe {
                *(&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            if value.sin6_scope_id != 0 {
                return Err(error(
                    ErrorCode::Forbidden,
                    "scoped original credential destination is unsupported",
                ));
            }
            SocketAddr::new(
                std::net::Ipv6Addr::from(value.sin6_addr.s6_addr).into(),
                u16::from_be(value.sin6_port),
            )
        }
        _ => {
            return Err(error(
                ErrorCode::Forbidden,
                "invalid original credential destination",
            ));
        }
    };
    if original == local
        || original.port() == 0
        || original.ip().is_unspecified()
        || original.ip().is_multicast()
    {
        return Err(error(
            ErrorCode::Forbidden,
            "credential socket has no verified redirection",
        ));
    }
    Ok(original)
}
