//! Bounded workload DNS transport. Identity is its verified bridge binding and
//! scoped kernel input rules, never a name/header supplied by the workload.
use crate::{DnsBinding, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};

const MAX_QUERY: usize = 4096;
const MAX_PENDING: usize = 16;

pub struct QueryRequest {
    pub wire: Vec<u8>,
    pub tcp: bool,
    pub reply: oneshot::Sender<Vec<u8>>,
}
pub struct BoundSockets {
    pub binding: DnsBinding,
    tcp: TcpListener,
    udp: UdpSocket,
}
pub struct Frontend {
    tasks: Vec<JoinHandle<()>>,
    stop: tokio_util::sync::CancellationToken,
}

impl BoundSockets {
    pub async fn bind(address: Ipv4Addr, port: u16) -> Result<Self, ApiError> {
        if port != 0 && port < 1024 {
            return Err(error(
                ErrorCode::InvalidRequest,
                "DNS requires a high listener port",
            ));
        }
        for _ in 0..16 {
            let tcp = TcpListener::bind((address, port)).await.map_err(|_| {
                error(
                    ErrorCode::BackendUnavailable,
                    "cannot bind owned TCP DNS listener",
                )
            })?;
            let actual = tcp.local_addr().map_err(|_| {
                error(
                    ErrorCode::BackendUnavailable,
                    "cannot inspect owned DNS listener",
                )
            })?;
            match UdpSocket::bind(actual).await {
                Ok(udp) => {
                    return Ok(Self {
                        binding: DnsBinding::new(address, actual.port())?,
                        tcp,
                        udp,
                    });
                }
                Err(e)
                    if port == 0
                        && matches!(
                            e.kind(),
                            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                        ) => {}
                Err(_) => {
                    return Err(error(
                        ErrorCode::BackendUnavailable,
                        "cannot bind owned UDP DNS listener",
                    ));
                }
            }
        }
        Err(error(
            ErrorCode::BackendUnavailable,
            "no paired owned DNS listener port is available",
        ))
    }

    pub fn serve(self, queries: mpsc::Sender<QueryRequest>) -> Frontend {
        let stop = tokio_util::sync::CancellationToken::new();
        let udp_stop = stop.clone();
        let tcp_stop = stop.clone();
        let permits = Arc::new(Semaphore::new(MAX_PENDING));
        let udp = Arc::new(self.udp);
        let tcp = self.tcp;
        let udp_queries = queries.clone();
        let udp_permits = permits.clone();
        let udp_task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            let mut buffer = vec![0; MAX_QUERY + 1];
            loop {
                tokio::select! {
                    _=udp_stop.cancelled()=>break,
                    _=workers.join_next(),if !workers.is_empty()=>{},
                    received=udp.recv_from(&mut buffer)=>{
                        let Ok((count,peer))=received else {break};
                        let wire=buffer[..count].to_vec();
                        let permit=udp_permits.clone().try_acquire_owned();
                        if count>MAX_QUERY || permit.is_err(){
                            if let Some(reply)=crate::dns::failure_wire(&wire,ErrorCode::QuotaExceeded){let _=udp.send_to(&reply,peer).await;}
                            continue;
                        }
                        let permit=permit.expect("checked permit");let socket=udp.clone();let tx=udp_queries.clone();
                        workers.spawn(async move{let _permit=permit;if let Some(reply)=ask(&tx,wire,false).await{let _=socket.send_to(&reply,peer).await;}});
                    }
                }
            }
            workers.shutdown().await;
        });
        let tcp_task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    _=tcp_stop.cancelled()=>break,
                    _=workers.join_next(),if !workers.is_empty()=>{},
                    accepted=tcp.accept()=>{
                        let Ok((stream,_))=accepted else {break};
                        let Ok(permit)=permits.clone().try_acquire_owned() else {drop(stream);continue};
                        let tx=queries.clone();workers.spawn(async move{let _permit=permit;connection(stream,tx).await;});
                    }
                }
            }
            workers.shutdown().await;
        });
        Frontend {
            tasks: vec![udp_task, tcp_task],
            stop,
        }
    }
}

impl Frontend {
    pub async fn shutdown(mut self) {
        self.stop.cancel();
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}
impl Drop for Frontend {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn ask(queries: &mpsc::Sender<QueryRequest>, wire: Vec<u8>, tcp: bool) -> Option<Vec<u8>> {
    let fallback = crate::dns::failure_wire(&wire, ErrorCode::BackendUnavailable);
    let (reply, receiver) = oneshot::channel();
    if queries.try_send(QueryRequest { wire, tcp, reply }).is_err() {
        return fallback;
    }
    match tokio::time::timeout(Duration::from_secs(7), receiver).await {
        Ok(Ok(wire)) => Some(wire),
        _ => fallback,
    }
}

async fn connection(mut stream: TcpStream, queries: mpsc::Sender<QueryRequest>) {
    for _ in 0..16 {
        let Ok(Ok(length)) = tokio::time::timeout(Duration::from_secs(3), stream.read_u16()).await
        else {
            return;
        };
        let length = usize::from(length);
        if !(12..=MAX_QUERY).contains(&length) {
            return;
        }
        let mut wire = vec![0; length];
        if !matches!(
            tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut wire)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        let Some(reply) = ask(&queries, wire, true).await else {
            return;
        };
        if reply.len() > u16::MAX as usize {
            return;
        }
        let write = async {
            stream.write_u16(reply.len() as u16).await?;
            stream.write_all(&reply).await
        };
        if !matches!(
            tokio::time::timeout(Duration::from_secs(3), write).await,
            Ok(Ok(()))
        ) {
            return;
        }
    }
}

/// Read the address of exactly the already-verified bridge. No route, alias or
/// host setting is changed. The kernel selects the sockaddr union member.
pub(crate) fn bridge_address(bridge: &str) -> Result<Ipv4Addr, ApiError> {
    use std::os::fd::AsRawFd;
    if bridge.is_empty()
        || bridge.len() >= libc::IFNAMSIZ
        || !bridge
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(error(
            ErrorCode::InvalidRequest,
            "invalid bridge address query",
        ));
    }
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|_| {
        error(
            ErrorCode::BackendUnavailable,
            "cannot open bridge address query",
        )
    })?;
    // SAFETY: ifreq consists of C integer/byte/pointer fields; zero initializes
    // a terminated name and a valid output buffer for SIOCGIFADDR.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dest, byte) in request.ifr_name.iter_mut().zip(bridge.bytes()) {
        *dest = byte as libc::c_char;
    }
    // SAFETY: the live datagram descriptor and full writable ifreq buffer match
    // the ioctl contract. This operation only reads one interface address.
    // musl declares ioctl's operation as int, while glibc uses unsigned long.
    // This fixed Linux operation (0x8915) fits both ABIs.
    #[cfg(target_env = "musl")]
    let operation = libc::SIOCGIFADDR as libc::c_int;
    #[cfg(not(target_env = "musl"))]
    let operation = libc::SIOCGIFADDR;
    if unsafe { libc::ioctl(socket.as_raw_fd(), operation, &mut request) } != 0 {
        return Err(error(
            ErrorCode::BackendUnavailable,
            "owned bridge has no readable IPv4 address",
        ));
    }
    // SAFETY: the successful SIOCGIFADDR filled ifru_addr. Read a copied AF_INET
    // sockaddr with unaligned access, then check the returned family.
    let address = unsafe {
        std::ptr::read_unaligned(
            (&request.ifr_ifru.ifru_addr as *const libc::sockaddr).cast::<libc::sockaddr_in>(),
        )
    };
    if i32::from(address.sin_family) != libc::AF_INET {
        return Err(error(
            ErrorCode::BackendUnavailable,
            "owned bridge address family differs",
        ));
    }
    Ok(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()))
}

pub fn channel() -> (mpsc::Sender<QueryRequest>, mpsc::Receiver<QueryRequest>) {
    mpsc::channel(MAX_PENDING)
}
pub fn endpoint(binding: &DnsBinding) -> SocketAddr {
    SocketAddr::new(binding.address().into(), binding.port())
}
