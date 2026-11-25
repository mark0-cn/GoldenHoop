//! Bounded workload DNS transport. Identity is its verified bridge binding and
//! scoped kernel input rules, never a name/header supplied by the workload.
use crate::{DnsBinding, DnsBindings, error};
use goldenhoop_protocol::{ApiError, ErrorCode};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
pub struct BridgeAddresses {
    pub v4: Ipv4Addr,
    pub v6: Option<Ipv6Addr>,
}
pub struct BoundListeners {
    pub bindings: DnsBindings,
    sockets: Vec<BoundSockets>,
}
pub struct Frontend {
    tasks: Vec<JoinHandle<()>>,
    stop: tokio_util::sync::CancellationToken,
}

impl BoundSockets {
    pub async fn bind(address: IpAddr, port: u16) -> Result<Self, ApiError> {
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

    fn spawn(
        self,
        queries: mpsc::Sender<QueryRequest>,
        permits: Arc<Semaphore>,
        stop: &tokio_util::sync::CancellationToken,
    ) -> Vec<JoinHandle<()>> {
        let udp_stop = stop.clone();
        let tcp_stop = stop.clone();
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
                            if let Some(reply)=crate::dns::failure_wire(&wire,ErrorCode::QuotaExceeded){send_datagram(&udp,&reply,peer).await;}
                            continue;
                        }
                        let permit=permit.expect("checked permit");let socket=udp.clone();let tx=udp_queries.clone();
                        workers.spawn(async move{let _permit=permit;if let Some(reply)=ask(&tx,wire,false).await{send_datagram(&socket,&reply,peer).await;}});
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
        vec![udp_task, tcp_task]
    }
}

impl BoundListeners {
    pub async fn bind(addresses: &BridgeAddresses) -> Result<Self, ApiError> {
        let first = BoundSockets::bind(addresses.v4.into(), 0).await?;
        let second = if let Some(v6) = addresses.v6 {
            Some(BoundSockets::bind(v6.into(), 0).await?)
        } else {
            None
        };
        let bindings = DnsBindings::new(
            first.binding.clone(),
            second.as_ref().map(|s| s.binding.clone()),
        )?;
        Ok(Self {
            bindings,
            sockets: std::iter::once(first).chain(second).collect(),
        })
    }
    pub async fn rebind(bindings: &DnsBindings) -> Result<Self, ApiError> {
        let mut sockets = Vec::new();
        for binding in bindings.iter() {
            sockets.push(BoundSockets::bind(binding.address(), binding.port()).await?);
        }
        Ok(Self {
            bindings: bindings.clone(),
            sockets,
        })
    }
    pub fn serve(self, queries: mpsc::Sender<QueryRequest>) -> Frontend {
        let stop = tokio_util::sync::CancellationToken::new();
        let permits = Arc::new(Semaphore::new(MAX_PENDING));
        let tasks = self
            .sockets
            .into_iter()
            .flat_map(|socket| socket.spawn(queries.clone(), permits.clone(), &stop))
            .collect();
        Frontend { tasks, stop }
    }
}

async fn send_datagram(socket: &UdpSocket, reply: &[u8], peer: SocketAddr) {
    let _ = tokio::time::timeout(Duration::from_millis(250), socket.send_to(reply, peer)).await;
}

impl Frontend {
    pub fn is_running(&self) -> bool {
        !self.stop.is_cancelled()
            && !self.tasks.is_empty()
            && self.tasks.iter().all(|task| !task.is_finished())
    }
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

/// Enumerate kernel-owned native interface addresses without retaining libc
/// pointers. The visitor runs before the successful allocation is released.
fn visit_addresses(mut visitor: impl FnMut(&[u8], IpAddr)) -> Result<(), ApiError> {
    use std::ffi::CStr;
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            // SAFETY: this exclusively owned successful getifaddrs allocation
            // remains live until every callback and linked-list read ends.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut pointer = std::ptr::null_mut();
    // SAFETY: libc initializes the output and owns its complete linked list.
    if unsafe { libc::getifaddrs(&mut pointer) } != 0 {
        return Err(error(
            ErrorCode::BackendUnavailable,
            "cannot read host interface addresses",
        ));
    }
    let _allocation = Addresses(pointer);
    let mut count = 0;
    while !pointer.is_null() {
        count += 1;
        if count > 16384 {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "interface address inventory exceeds limit",
            ));
        }
        // SAFETY: the pointer is a live node in the libc-owned list.
        let node = unsafe { &*pointer };
        if !node.ifa_name.is_null() && !node.ifa_addr.is_null() {
            // SAFETY: libc supplies a terminated name and a readable family.
            let name = unsafe { CStr::from_ptr(node.ifa_name) }.to_bytes();
            // SAFETY: a nonnull getifaddrs sockaddr has a readable family.
            let family = i32::from(unsafe { (*node.ifa_addr).sa_family });
            let address = match family {
                libc::AF_INET => {
                    // SAFETY: matching AF_INET guarantees a sockaddr_in.
                    let a = unsafe {
                        std::ptr::read_unaligned(node.ifa_addr.cast::<libc::sockaddr_in>())
                    };
                    Some(IpAddr::V4(Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes())))
                }
                libc::AF_INET6 => {
                    // SAFETY: matching AF_INET6 guarantees a sockaddr_in6.
                    let a = unsafe {
                        std::ptr::read_unaligned(node.ifa_addr.cast::<libc::sockaddr_in6>())
                    };
                    Some(IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)))
                }
                _ => None,
            };
            if let Some(address) = address {
                visitor(name, address);
            }
        }
        pointer = node.ifa_next;
    }
    Ok(())
}

pub(crate) fn host_addresses() -> Result<Vec<IpAddr>, ApiError> {
    let mut addresses = std::collections::BTreeSet::new();
    visit_addresses(|_, address| {
        addresses.insert(address);
    })?;
    if addresses.is_empty() || addresses.len() > 128 {
        return Err(error(
            ErrorCode::QuotaExceeded,
            "host address scope is empty or exceeds limit",
        ));
    }
    Ok(addresses.into_iter().collect())
}

/// Read only the already-verified bridge. Multiple application addresses in
/// either family refuse rather than choosing an ambiguous policy endpoint.
pub(crate) fn bridge_addresses(bridge: &str) -> Result<BridgeAddresses, ApiError> {
    use std::collections::BTreeSet;
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
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    visit_addresses(|name, address| {
        if name != bridge.as_bytes() {
            return;
        }
        match address {
            IpAddr::V4(ip) => {
                v4.insert(ip);
            }
            IpAddr::V6(ip) => {
                if !ip.is_unicast_link_local()
                    && !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_multicast()
                    && ip.to_ipv4_mapped().is_none()
                {
                    v6.insert(ip);
                }
            }
        }
    })?;
    if v4.len() != 1 || v6.len() > 1 {
        return Err(error(
            ErrorCode::Conflict,
            "owned bridge addresses are missing or ambiguous",
        ));
    }
    Ok(BridgeAddresses {
        v4: v4.into_iter().next().expect("one IPv4 address"),
        v6: v6.into_iter().next(),
    })
}

pub fn channel() -> (mpsc::Sender<QueryRequest>, mpsc::Receiver<QueryRequest>) {
    mpsc::channel(MAX_PENDING)
}
pub fn endpoint(binding: &DnsBinding) -> SocketAddr {
    SocketAddr::new(binding.address(), binding.port())
}
