use super::*;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

pub struct Upstream {
    endpoint: SocketAddr,
}
impl Upstream {
    pub fn new(endpoint: SocketAddr) -> Result<Self, ApiError> {
        if endpoint.port() == 0 || endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() {
            return Err(error(
                ErrorCode::InvalidRequest,
                "invalid fixed DNS upstream",
            ));
        }
        Ok(Self { endpoint })
    }

    pub async fn exchange(&self, request: &Request) -> Result<PendingAnswer, ApiError> {
        if Instant::now() >= request.upstream_deadline() {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "DNS lookup is too old to forward",
            ));
        }
        tokio::time::timeout_at(
            request.upstream_deadline().into(),
            self.exchange_inner(request),
        )
        .await
        .map_err(|_| error(ErrorCode::DeadlineExceeded, "DNS upstream deadline elapsed"))?
    }

    async fn exchange_inner(&self, request: &Request) -> Result<PendingAnswer, ApiError> {
        let io_error = |_| {
            error(
                ErrorCode::BackendUnavailable,
                "DNS upstream transport failed",
            )
        };
        let bind = if self.endpoint.is_ipv4() {
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
        } else {
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
        };
        let socket = UdpSocket::bind(bind).await.map_err(io_error)?;
        socket.connect(self.endpoint).await.map_err(io_error)?;
        let query = request.upstream_wire()?;
        socket.send(&query).await.map_err(io_error)?;
        let mut buffer = vec![0; MAX_REPLY + 1];
        // Ignore malformed/wrong-ID messages instead of letting the first
        // unrelated datagram terminate a legitimate in-flight DNS request.
        for _ in 0..64 {
            let count = socket.recv(&mut buffer).await.map_err(io_error)?;
            let Ok(message) = request.response(&buffer[..count]) else {
                continue;
            };
            if !message.metadata.truncation {
                return request.prepare(&buffer[..count]);
            }
            let mut stream = TcpStream::connect(self.endpoint).await.map_err(io_error)?;
            stream
                .write_all(&(query.len() as u16).to_be_bytes())
                .await
                .map_err(io_error)?;
            stream.write_all(&query).await.map_err(io_error)?;
            let length = usize::from(stream.read_u16().await.map_err(io_error)?);
            if !(12..=MAX_REPLY).contains(&length) {
                return Err(error(
                    ErrorCode::BackendUnavailable,
                    "invalid DNS upstream TCP frame",
                ));
            }
            stream
                .read_exact(&mut buffer[..length])
                .await
                .map_err(io_error)?;
            return request.prepare(&buffer[..length]);
        }
        Err(error(
            ErrorCode::QuotaExceeded,
            "too many unmatched DNS upstream responses",
        ))
    }
}
