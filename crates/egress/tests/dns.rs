use goldenhoop_egress::dns::{
    GrantInstaller, GrantReceipt, GrantRequest, Request, Upstream, failure_wire,
};
use goldenhoop_policy::{Model, Overlays, Policy};
use goldenhoop_protocol::{ApiError, ErrorCode, NetworkAction, NetworkPolicy, NetworkRule};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME},
    },
};
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

fn model() -> Model {
    Model::new(
        vec![
            Policy::compile(&NetworkPolicy {
                default_action: NetworkAction::Deny,
                rules: vec![NetworkRule {
                    destination: "good.example.test".into(),
                    ports: vec![],
                    action: NetworkAction::Allow,
                }],
            })
            .unwrap(),
        ],
        Overlays::default(),
    )
    .unwrap()
}
fn query(name: &str, kind: RecordType) -> Vec<u8> {
    let mut m = Message::query();
    m.metadata.id = 77;
    m.queries
        .push(Query::query(Name::from_ascii(name).unwrap(), kind));
    m.to_vec().unwrap()
}
fn request() -> Request {
    Request::parse(&query("good.example.test.", RecordType::A), &model(), 9).unwrap()
}
fn response(query: &Message) -> Message {
    let mut m = Message::response(query.metadata.id, OpCode::Query);
    m.queries = query.queries.clone();
    m
}
fn answer(request: &Request) -> Message {
    let q = Message::from_vec(&request.upstream_wire().unwrap()).unwrap();
    response(&q)
}
fn a(name: &str, ttl: u32, ip: &str) -> Record {
    Record::from_rdata(
        Name::from_ascii(name).unwrap(),
        ttl,
        RData::A(A(ip.parse().unwrap())),
    )
}
fn cname(name: &str, ttl: u32, next: &str) -> Record {
    Record::from_rdata(
        Name::from_ascii(name).unwrap(),
        ttl,
        RData::CNAME(CNAME(Name::from_ascii(next).unwrap())),
    )
}

#[test]
fn query_bounds_policy_and_protocol_shape_are_checked_before_forwarding() {
    let good = query("good.example.test.", RecordType::A);
    let mut trailing = good.clone();
    trailing.push(0);
    let mut count = vec![0; 12];
    count[4] = 255;
    count[5] = 255;
    let looped = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1];
    for bytes in [vec![], trailing, count, looped, vec![0; 4097]] {
        assert!(Request::parse(&bytes, &model(), 9).is_err());
    }
    assert!(
        matches!(Request::parse(&query("blocked.example.test.",RecordType::A),&model(),9),Err(e) if e.code==ErrorCode::Forbidden)
    );
    assert!(
        matches!(Request::parse(&query("good.example.test.",RecordType::TXT),&model(),9),Err(e) if e.code==ErrorCode::UnsupportedCapability)
    );
    let mut message = Message::from_vec(&good).unwrap();
    message.metadata.message_type = MessageType::Response;
    assert!(Request::parse(&message.to_vec().unwrap(), &model(), 9).is_err());
}

#[test]
fn workload_errors_preserve_only_bounded_questions_and_never_echo_records() {
    let good = query("good.example.test.", RecordType::A);
    let mut supplied = Message::from_vec(&good).unwrap();
    supplied
        .answers
        .push(a("good.example.test.", 60, "192.0.2.20"));
    supplied.authorities = supplied.answers.clone();
    supplied.additionals = supplied.answers.clone();
    let mut malformed = good.clone();
    malformed[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
    let mut oversized = good.clone();
    oversized.resize(4097, 0);
    for (wire, code, expected, questions) in [
        (good, ErrorCode::Forbidden, ResponseCode::Refused, 1),
        (
            supplied.to_vec().unwrap(),
            ErrorCode::BackendUnavailable,
            ResponseCode::ServFail,
            1,
        ),
        (
            malformed,
            ErrorCode::InvalidRequest,
            ResponseCode::FormErr,
            0,
        ),
        (
            oversized,
            ErrorCode::QuotaExceeded,
            ResponseCode::ServFail,
            0,
        ),
    ] {
        let reply = failure_wire(&wire, code).unwrap();
        assert!(reply.len() <= 512);
        let decoded = Message::from_vec(&reply).unwrap();
        assert_eq!(decoded.metadata.id, 77);
        assert_eq!(decoded.metadata.message_type, MessageType::Response);
        assert_eq!(decoded.metadata.response_code, expected);
        assert_eq!(decoded.queries.len(), questions);
        assert!(decoded.answers.is_empty());
        assert!(decoded.authorities.is_empty());
        assert!(decoded.additionals.is_empty());
    }
    assert!(failure_wire(&[0; 11], ErrorCode::InvalidRequest).is_none());
}

#[derive(Clone, Copy)]
enum Mode {
    Success,
    Fail,
    Stale,
    Expired,
    Extended,
    WrongLookup,
    Delayed,
}
struct Installer {
    mode: Mode,
    calls: usize,
}
#[async_trait::async_trait]
impl GrantInstaller for Installer {
    async fn install(&mut self, request: &GrantRequest) -> Result<GrantReceipt, ApiError> {
        self.calls += 1;
        if matches!(self.mode, Mode::Delayed) {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        match self.mode {
            Mode::Fail => Err(ApiError::new(
                ErrorCode::BackendUnavailable,
                "injected install failure",
            )),
            mode => Ok(GrantReceipt {
                lookup_id: if matches!(mode, Mode::WrongLookup) {
                    uuid::Uuid::new_v4()
                } else {
                    request.lookup_id()
                },
                revision: request.revision() + u64::from(matches!(mode, Mode::Stale)),
                expires_at: match mode {
                    Mode::Expired => Instant::now() - Duration::from_secs(1),
                    Mode::Extended => request.expires_at() + Duration::from_secs(1),
                    _ => request.expires_at(),
                },
            }),
        }
    }
}
fn installer(mode: Mode) -> Installer {
    Installer { mode, calls: 0 }
}

#[tokio::test]
async fn connected_cname_source_is_original_question_and_extra_addresses_are_not_credited() {
    let request = request();
    let mut response = answer(&request);
    response.metadata.authentic_data = true;
    response.answers = vec![
        a("cdn.example.test.", 900, "192.0.2.20"),
        cname("good.example.test.", 600, "cdn.example.test."),
    ];
    response
        .additionals
        .push(a("injected.example.test.", 900, "192.0.2.21"));
    let pending = request.prepare(&response.to_vec().unwrap()).unwrap();
    assert_eq!(pending.grant().source().as_str(), "good.example.test");
    assert_eq!(
        pending.grant().addresses(),
        &["192.0.2.20".parse::<IpAddr>().unwrap()]
    );
    assert!(
        pending.grant().expires_at().duration_since(Instant::now()) <= Duration::from_secs(300)
    );
    let mut install = installer(Mode::Success);
    let finished = Message::from_vec(&pending.finish(&mut install, true).await.unwrap()).unwrap();
    assert_eq!(install.calls, 1);
    assert_eq!(finished.metadata.id, 77);
    assert!(!finished.metadata.authentic_data);
    assert!(finished.additionals.is_empty());
    assert!(finished.authorities.is_empty());
    assert_eq!(finished.answers.len(), 2);
    assert!(matches!(finished.answers[0].data, RData::CNAME(_)));
    assert!(finished.answers.iter().all(|r| r.ttl <= 300));
}

#[test]
fn mismatched_poisoned_looped_branched_or_expired_answers_fail_closed() {
    let request = request();
    let mut response = answer(&request);
    response.answers = vec![a("good.example.test.", 60, "192.0.2.20")];
    let mut wrong = response.clone();
    wrong.metadata.id = wrong.metadata.id.wrapping_add(1);
    assert!(request.prepare(&wrong.to_vec().unwrap()).is_err());
    let mut wrong = response.clone();
    wrong.queries[0].query_type = RecordType::AAAA;
    assert!(request.prepare(&wrong.to_vec().unwrap()).is_err());
    for records in [
        vec![
            a("good.example.test.", 60, "192.0.2.20"),
            a("other.example.test.", 60, "192.0.2.21"),
        ],
        vec![
            cname("good.example.test.", 60, "alias.example.test."),
            cname("alias.example.test.", 60, "good.example.test."),
        ],
        vec![
            cname("good.example.test.", 60, "alias.example.test."),
            cname("good.example.test.", 60, "other.example.test."),
        ],
        vec![a("good.example.test.", 0, "192.0.2.20")],
    ] {
        let mut m = response.clone();
        m.answers = records;
        assert!(request.prepare(&m.to_vec().unwrap()).is_err());
    }
    response.metadata.response_code = ResponseCode::NXDomain;
    assert!(request.prepare(&response.to_vec().unwrap()).is_err());
}

#[tokio::test]
async fn failed_stale_expired_or_extended_receipts_publish_no_address_answer() {
    for mode in [
        Mode::Fail,
        Mode::Stale,
        Mode::Expired,
        Mode::Extended,
        Mode::WrongLookup,
    ] {
        let request = request();
        let mut response = answer(&request);
        response
            .answers
            .push(a("good.example.test.", 60, "192.0.2.20"));
        let pending = request.prepare(&response.to_vec().unwrap()).unwrap();
        let mut install = installer(mode);
        assert!(pending.finish(&mut install, true).await.is_err());
        assert_eq!(install.calls, 1);
    }
}

#[tokio::test]
async fn install_acknowledgement_cannot_outlive_the_dns_source() {
    let request = request();
    let mut response = answer(&request);
    response
        .answers
        .push(a("good.example.test.", 1, "192.0.2.20"));
    let pending = request.prepare(&response.to_vec().unwrap()).unwrap();
    let mut install = installer(Mode::Delayed);
    assert!(
        matches!(pending.finish(&mut install,true).await,Err(e) if e.code==ErrorCode::DeadlineExceeded)
    );
    assert_eq!(install.calls, 1);
}

#[tokio::test]
async fn aaaa_mapping_negative_answers_and_udp_truncation_are_bounded() {
    let req = Request::parse(&query("good.example.test.", RecordType::AAAA), &model(), 9).unwrap();
    let mut m = answer(&req);
    m.answers.push(Record::from_rdata(
        Name::from_ascii("good.example.test.").unwrap(),
        60,
        RData::AAAA(AAAA("::ffff:192.0.2.20".parse().unwrap())),
    ));
    let pending = req.prepare(&m.to_vec().unwrap()).unwrap();
    assert_eq!(
        pending.grant().addresses(),
        &["192.0.2.20".parse::<IpAddr>().unwrap()]
    );
    let req = request();
    let mut negative = answer(&req);
    negative.metadata.response_code = ResponseCode::NXDomain;
    let pending = req.prepare(&negative.to_vec().unwrap()).unwrap();
    assert!(pending.grant().addresses().is_empty());
    let negative = Message::from_vec(
        &pending
            .finish(&mut installer(Mode::Success), true)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(negative.metadata.response_code, ResponseCode::NXDomain);
    let mut many = answer(&req);
    many.answers = (1..=32)
        .map(|i| a("good.example.test.", 60, &format!("192.0.2.{i}")))
        .collect();
    let bytes = many.to_vec().unwrap();
    let udp = Message::from_vec(
        &req.prepare(&bytes)
            .unwrap()
            .finish(&mut installer(Mode::Success), false)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(udp.metadata.truncation);
    assert!(udp.answers.is_empty());
    let tcp = Message::from_vec(
        &req.prepare(&bytes)
            .unwrap()
            .finish(&mut installer(Mode::Success), true)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(tcp.answers.len(), 32);
    assert!(!tcp.metadata.truncation);
}

#[tokio::test]
async fn actual_udp_ignores_malformed_and_wrong_id_datagrams() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let q = Message::from_vec(&buffer[..len]).unwrap();
        socket.send_to(b"bad", peer).await.unwrap();
        let mut m = response(&q);
        m.metadata.id = m.metadata.id.wrapping_add(1);
        socket.send_to(&m.to_vec().unwrap(), peer).await.unwrap();
        m.metadata.id = q.metadata.id;
        m.answers.push(a("good.example.test.", 60, "192.0.2.20"));
        socket.send_to(&m.to_vec().unwrap(), peer).await.unwrap();
    });
    let pending = Upstream::new(endpoint)
        .unwrap()
        .exchange(&request())
        .await
        .unwrap();
    assert_eq!(pending.grant().addresses().len(), 1);
    server.await.unwrap();
}

#[tokio::test]
async fn actual_truncated_udp_retries_tcp_and_tcp_eof_is_not_an_answer() {
    for complete in [true, false] {
        let (tcp, udp, endpoint) = paired_listeners().await.unwrap();
        let server = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                let mut buffer = [0; 4096];
                let (len, peer) = udp.recv_from(&mut buffer).await.unwrap();
                let q = Message::from_vec(&buffer[..len]).unwrap();
                let mut m = response(&q);
                m.metadata.truncation = true;
                udp.send_to(&m.to_vec().unwrap(), peer).await.unwrap();
                let (mut stream, _) = tcp.accept().await.unwrap();
                let len = usize::from(stream.read_u16().await.unwrap());
                assert!(len <= buffer.len());
                stream.read_exact(&mut buffer[..len]).await.unwrap();
                let q = Message::from_vec(&buffer[..len]).unwrap();
                let mut m = response(&q);
                m.answers.push(a("good.example.test.", 60, "192.0.2.20"));
                let bytes = m.to_vec().unwrap();
                stream
                    .write_all(&(bytes.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                if complete {
                    stream.write_all(&bytes).await.unwrap();
                }
            })
            .await
            .unwrap();
        });
        let result = Upstream::new(endpoint).unwrap().exchange(&request()).await;
        if complete {
            assert_eq!(result.unwrap().grant().addresses().len(), 1);
        } else {
            assert!(result.is_err());
        }
        server.await.unwrap();
    }
}

async fn paired_listeners() -> std::io::Result<(TcpListener, UdpSocket, std::net::SocketAddr)> {
    // TCP/UDP exclusions can differ and adjacent TCP auto-allocations may all
    // lie in a UDP-only reservation. Sample distinct high loopback ports and
    // require both real binds before running either DNS assertion.
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..128 {
        let random = *uuid::Uuid::new_v4().as_bytes();
        let port = 49_152 + u16::from_ne_bytes([random[0], random[1]]) % 16_384;
        if !seen.insert(port) {
            continue;
        }
        let endpoint = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let tcp = match TcpListener::bind(endpoint).await {
            Ok(tcp) => tcp,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        match UdpSocket::bind(endpoint).await {
            Ok(udp) => return Ok((tcp, udp, endpoint)),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "no shared TCP/UDP fixture port",
    ))
}
