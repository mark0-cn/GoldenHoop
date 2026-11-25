//! Bounded DNS forwarding and the answer-after-install handshake. This module
//! does not bind a workload DNS server or implement a kernel grant installer.
mod upstream;
pub use upstream::Upstream;
mod leases;
pub use leases::{Authority, KernelLease, LeaseBook, LeaseTransaction};
mod sets;
pub(crate) use sets::duration_ms;
pub use sets::{SetConfirmation, SetNames, StagedSets};
#[cfg(target_os = "linux")]
mod probe;
#[cfg(target_os = "linux")]
pub use probe::probe_staged_sets;

use crate::error;
use goldenhoop_policy::{DecisionOrigin, Domain, Model};
use goldenhoop_protocol::{ApiError, ErrorCode, NetworkAction};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RData, Record, RecordType},
    serialize::binary::{BinDecodable, BinDecoder},
};
use std::{
    collections::BTreeSet,
    net::IpAddr,
    time::{Duration, Instant},
};

const MAX_QUERY: usize = 4096;
const MAX_RECORDS: usize = 128;
pub const MAX_REPLY: usize = 65535;
const MAX_ADDRESSES: usize = 32;
const MAX_CNAME: usize = 16;
const MAX_TTL: u32 = 300;

pub struct Request {
    client_id: u16,
    upstream_id: u16,
    lookup_id: uuid::Uuid,
    started_at: Instant,
    query: Query,
    source: Domain,
    revision: u64,
    origin: DecisionOrigin,
    recursion_desired: bool,
    edns_payload: Option<u16>,
}

impl Request {
    /// A denied name never becomes an upstream request. IP/port-only policies
    /// cannot create DNS authority via the model's name decision.
    pub fn parse(bytes: &[u8], model: &Model, revision: u64) -> Result<Self, ApiError> {
        let started_at = Instant::now();
        let msg = decode(bytes, MAX_QUERY)?;
        if msg.metadata.message_type != MessageType::Query
            || msg.metadata.op_code != OpCode::Query
            || msg.metadata.truncation
            || msg.metadata.response_code != ResponseCode::NoError
            || !msg.answers.is_empty()
            || !msg.authorities.is_empty()
            || !msg.additionals.is_empty()
            || msg.signature.is_some()
            || msg.edns.as_ref().is_some_and(|e| e.version() != 0)
        {
            return Err(error(
                ErrorCode::InvalidRequest,
                "unsupported DNS query shape",
            ));
        }
        let query = &msg.queries[0];
        if query.query_class != DNSClass::IN
            || !matches!(query.query_type, RecordType::A | RecordType::AAAA)
        {
            return Err(error(
                ErrorCode::UnsupportedCapability,
                "DNS adapter currently accepts IN A and AAAA only",
            ));
        }
        let source = Domain::parse(&query.name.to_ascii())?;
        let decision = model.dns_candidate(&source);
        if decision.action != NetworkAction::Allow {
            return Err(error(ErrorCode::Forbidden, "DNS query is denied by policy"));
        }
        let name = Name::from_ascii(format!("{}.", source.as_str()))
            .map_err(|_| error(ErrorCode::InvalidRequest, "invalid canonical DNS name"))?;
        let random = uuid::Uuid::new_v4();
        Ok(Self {
            client_id: msg.metadata.id,
            upstream_id: u16::from_be_bytes([random.as_bytes()[0], random.as_bytes()[1]]),
            lookup_id: random,
            started_at,
            query: Query::query(name, query.query_type),
            source,
            revision,
            origin: decision.origin,
            recursion_desired: msg.metadata.recursion_desired,
            edns_payload: msg.edns.map(|e| e.max_payload().clamp(512, 1232)),
        })
    }

    pub fn upstream_wire(&self) -> Result<Vec<u8>, ApiError> {
        let mut message = Message::query();
        message.metadata.id = self.upstream_id;
        message.metadata.recursion_desired = true;
        message.queries.push(self.query.clone());
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        message.edns = Some(edns);
        encode(&message)
    }

    fn response(&self, bytes: &[u8]) -> Result<Message, ApiError> {
        let message = decode(bytes, MAX_REPLY)?;
        if message.metadata.message_type != MessageType::Response
            || message.metadata.op_code != OpCode::Query
            || message.metadata.id != self.upstream_id
            || message.queries[0] != self.query
            || message.signature.is_some()
            || message.edns.as_ref().is_some_and(|e| e.version() != 0)
        {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "DNS upstream response does not match request",
            ));
        }
        Ok(message)
    }

    pub fn prepare(&self, bytes: &[u8]) -> Result<PendingAnswer, ApiError> {
        if Instant::now() >= self.upstream_deadline() {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "DNS lookup freshness window elapsed",
            ));
        }
        let response = self.response(bytes)?;
        if response.metadata.truncation
            || !matches!(
                response.metadata.response_code,
                ResponseCode::NoError | ResponseCode::NXDomain
            )
        {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "DNS upstream response is incomplete or failed",
            ));
        }
        let (records, addresses, ttl) =
            chain(&self.source, self.query.query_type, &response.answers)?;
        if response.metadata.response_code == ResponseCode::NXDomain && !addresses.is_empty() {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "negative DNS response contains addresses",
            ));
        }
        let now = Instant::now();
        let grant = GrantRequest {
            lookup_id: self.lookup_id,
            lookup_deadline: self.started_at + Duration::from_secs(6),
            revision: self.revision,
            source: self.source.clone(),
            query_type: self.query.query_type,
            origin: self.origin,
            addresses,
            expires_at: now + Duration::from_secs(u64::from(ttl)),
        };
        if !grant.addresses.is_empty() && ttl == 0 {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "DNS address source has already expired",
            ));
        }
        let mut message = Message::response(self.client_id, OpCode::Query);
        message.metadata.response_code = response.metadata.response_code;
        message.metadata.recursion_desired = self.recursion_desired;
        message.metadata.recursion_available = true;
        // Never copy AD/CD, arbitrary EDNS options, authorities, unrelated
        // additional addresses or the upstream transaction ID to the workload.
        message.queries.push(self.query.clone());
        message.answers = records;
        if let Some(payload) = self.edns_payload {
            let mut edns = Edns::new();
            edns.set_max_payload(payload);
            message.edns = Some(edns);
        }
        Ok(PendingAnswer {
            grant,
            message,
            udp_limit: usize::from(self.edns_payload.unwrap_or(512)),
        })
    }

    fn upstream_deadline(&self) -> Instant {
        self.started_at + Duration::from_secs(3)
    }
}

#[derive(Debug)]
pub struct GrantRequest {
    lookup_id: uuid::Uuid,
    lookup_deadline: Instant,
    revision: u64,
    source: Domain,
    query_type: RecordType,
    origin: DecisionOrigin,
    addresses: Vec<IpAddr>,
    expires_at: Instant,
}
impl GrantRequest {
    pub fn lookup_id(&self) -> uuid::Uuid {
        self.lookup_id
    }
    pub fn lookup_deadline(&self) -> Instant {
        self.lookup_deadline
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn source(&self) -> &Domain {
        &self.source
    }
    pub fn query_type(&self) -> RecordType {
        self.query_type
    }
    pub fn origin(&self) -> DecisionOrigin {
        self.origin
    }
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }
}

/// A trusted installer must recheck policy revision, install bounded source
/// credits and confirm the kernel before returning this receipt. It is not a
/// claim supplied by a DNS peer. No production installer exists yet.
pub struct GrantReceipt {
    pub lookup_id: uuid::Uuid,
    pub revision: u64,
    pub expires_at: Instant,
}

#[async_trait::async_trait]
pub trait GrantInstaller: Send {
    async fn install(&mut self, request: &GrantRequest) -> Result<GrantReceipt, ApiError>;
}

pub struct PendingAnswer {
    grant: GrantRequest,
    message: Message,
    udp_limit: usize,
}
impl PendingAnswer {
    pub fn grant(&self) -> &GrantRequest {
        &self.grant
    }

    /// Failure returns no encoded answer. The caller must send SERVFAIL with
    /// no addresses. Mock installers are unit evidence only, not a kernel gate.
    pub async fn finish(
        mut self,
        installer: &mut impl GrantInstaller,
        tcp: bool,
    ) -> Result<Vec<u8>, ApiError> {
        let deadline = if self.grant.addresses.is_empty() {
            Instant::now() + Duration::from_secs(3)
        } else {
            self.grant
                .expires_at
                .min(Instant::now() + Duration::from_secs(3))
        };
        let deadline = deadline.min(self.grant.lookup_deadline);
        if Instant::now() >= deadline {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "DNS lookup is too old to install",
            ));
        }
        let receipt = tokio::time::timeout_at(deadline.into(), installer.install(&self.grant))
            .await
            .map_err(|_| {
                error(
                    ErrorCode::DeadlineExceeded,
                    "DNS install acknowledgement deadline elapsed",
                )
            })??;
        if receipt.lookup_id != self.grant.lookup_id
            || receipt.revision != self.grant.revision
            || receipt.expires_at > self.grant.expires_at
        {
            return Err(error(
                ErrorCode::Conflict,
                "DNS grant receipt differs from lookup, source revision or expiry",
            ));
        }
        let remaining = receipt.expires_at.saturating_duration_since(Instant::now());
        if !self.grant.addresses.is_empty() && remaining.is_zero() {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "DNS grant expired before answer publication",
            ));
        }
        let ttl = remaining.as_secs().min(u64::from(MAX_TTL)) as u32;
        for record in &mut self.message.answers {
            record.ttl = record.ttl.min(ttl);
        }
        let encoded = encode(&self.message)?;
        if !tcp && encoded.len() > self.udp_limit {
            self.message.answers.clear();
            self.message.metadata.truncation = true;
            return encode(&self.message);
        }
        if !self.grant.addresses.is_empty() && Instant::now() >= receipt.expires_at {
            return Err(error(
                ErrorCode::BackendUnavailable,
                "DNS grant expired while encoding the answer",
            ));
        }
        Ok(encoded)
    }
}

fn decode(bytes: &[u8], limit: usize) -> Result<Message, ApiError> {
    if !(12..=limit).contains(&bytes.len()) {
        return Err(error(ErrorCode::InvalidRequest, "invalid DNS wire length"));
    }
    let count = |at| usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
    // Bound counts before a parser can allocate from an untrusted header.
    if count(4) != 1 || count(6) + count(8) + count(10) > MAX_RECORDS {
        return Err(error(
            ErrorCode::InvalidRequest,
            "DNS section counts exceed limits",
        ));
    }
    let mut decoder = BinDecoder::new(bytes);
    let message = Message::read(&mut decoder)
        .map_err(|_| error(ErrorCode::InvalidRequest, "invalid DNS wire data"))?;
    if !decoder.is_empty() || message.queries.len() != 1 {
        return Err(error(
            ErrorCode::InvalidRequest,
            "DNS trailing bytes or query count differs",
        ));
    }
    Ok(message)
}

fn encode(message: &Message) -> Result<Vec<u8>, ApiError> {
    let bytes = message
        .to_vec()
        .map_err(|_| error(ErrorCode::Internal, "cannot encode DNS response"))?;
    if bytes.len() > MAX_REPLY {
        return Err(error(
            ErrorCode::QuotaExceeded,
            "DNS response exceeds wire limit",
        ));
    }
    Ok(bytes)
}

/// Bounded address-free errors for the workload transport. Never serialize
/// private error messages or upstream/additional records to an untrusted peer.
pub fn failure_wire(bytes: &[u8], code: ErrorCode) -> Option<Vec<u8>> {
    if bytes.len() < 12 {
        return None;
    }
    let response_code = match code {
        ErrorCode::Forbidden | ErrorCode::UnsupportedCapability => ResponseCode::Refused,
        ErrorCode::InvalidRequest => ResponseCode::FormErr,
        _ => ResponseCode::ServFail,
    };
    let mut message = Message::response(u16::from_be_bytes([bytes[0], bytes[1]]), OpCode::Query);
    message.metadata.response_code = response_code;
    message.metadata.recursion_available = true;
    if let Ok(query) = decode(bytes, MAX_QUERY)
        && query.metadata.message_type == MessageType::Query
        && query.metadata.op_code == OpCode::Query
    {
        message.metadata.recursion_desired = query.metadata.recursion_desired;
        message.queries = query.queries;
    }
    encode(&message).ok()
}

fn chain(
    source: &Domain,
    kind: RecordType,
    answers: &[Record],
) -> Result<(Vec<Record>, Vec<IpAddr>, u32), ApiError> {
    let bad = || {
        error(
            ErrorCode::BackendUnavailable,
            "DNS answers are not one bounded connected address chain",
        )
    };
    let names = answers
        .iter()
        .map(|r| Domain::parse(&r.name.to_ascii()).map_err(|_| bad()))
        .collect::<Result<Vec<_>, _>>()?;
    if answers.iter().any(|r| r.dns_class != DNSClass::IN) {
        return Err(bad());
    }
    let mut current = source.clone();
    let mut seen = BTreeSet::new();
    let mut used = BTreeSet::new();
    let mut records = Vec::new();
    let mut addresses = BTreeSet::new();
    let mut ttl = MAX_TTL;
    loop {
        if !seen.insert(current.clone()) || seen.len() > MAX_CNAME + 1 {
            return Err(bad());
        }
        let owned = names
            .iter()
            .enumerate()
            .filter_map(|(i, n)| (n == &current).then_some(i))
            .collect::<Vec<_>>();
        let cnames = owned
            .iter()
            .copied()
            .filter(|&i| matches!(answers[i].data, RData::CNAME(_)))
            .collect::<Vec<_>>();
        if !cnames.is_empty() {
            if cnames.len() != 1 || owned.len() != 1 {
                return Err(bad());
            }
            let i = cnames[0];
            let RData::CNAME(next) = &answers[i].data else {
                unreachable!()
            };
            current = Domain::parse(&next.0.to_ascii()).map_err(|_| bad())?;
            ttl = ttl.min(answers[i].ttl);
            used.insert(i);
            records.push(answers[i].clone());
            continue;
        }
        for i in owned {
            let address = match &answers[i].data {
                RData::A(ip) if kind == RecordType::A => IpAddr::V4(ip.0),
                RData::AAAA(ip) if kind == RecordType::AAAA => IpAddr::V6(ip.0),
                _ => return Err(bad()),
            }
            .to_canonical();
            addresses.insert(address);
            ttl = ttl.min(answers[i].ttl);
            used.insert(i);
            records.push(answers[i].clone());
        }
        break;
    }
    if used.len() != answers.len() || addresses.len() > MAX_ADDRESSES {
        return Err(bad());
    }
    Ok((records, addresses.into_iter().collect(), ttl))
}

#[cfg(test)]
mod freshness_tests {
    use super::*;
    struct MustNotInstall;
    #[async_trait::async_trait]
    impl GrantInstaller for MustNotInstall {
        async fn install(&mut self, _: &GrantRequest) -> Result<GrantReceipt, ApiError> {
            panic!("expired lookup reached the installer");
        }
    }

    #[tokio::test]
    async fn held_requests_cannot_forward_reprepare_or_install_after_lookup_expiry() {
        let model = Model::new(
            vec![
                goldenhoop_policy::Policy::compile(&goldenhoop_protocol::NetworkPolicy {
                    default_action: NetworkAction::Allow,
                    rules: vec![],
                })
                .unwrap(),
            ],
            goldenhoop_policy::Overlays::default(),
        )
        .unwrap();
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("valid.test.").unwrap(),
            RecordType::A,
        ));
        let mut request = Request::parse(&query.to_vec().unwrap(), &model, 9).unwrap();
        let mut response = Message::response(request.upstream_id, OpCode::Query);
        response.queries.push(request.query.clone());
        response.answers.push(Record::from_rdata(
            request.query.name.clone(),
            60,
            RData::A(hickory_proto::rr::rdata::A("192.0.2.1".parse().unwrap())),
        ));
        let bytes = response.to_vec().unwrap();
        let mut pending = request.prepare(&bytes).unwrap();
        pending.grant.lookup_deadline = Instant::now() - Duration::from_secs(1);
        assert!(
            matches!(pending.finish(&mut MustNotInstall,true).await,Err(e) if e.code==ErrorCode::DeadlineExceeded)
        );
        request.started_at = Instant::now() - Duration::from_secs(4);
        assert!(matches!(request.prepare(&bytes),Err(e) if e.code==ErrorCode::DeadlineExceeded));
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(
            matches!(Upstream::new(upstream.local_addr().unwrap()).unwrap().exchange(&request).await,Err(e) if e.code==ErrorCode::DeadlineExceeded)
        );
        assert_eq!(
            upstream.try_recv_from(&mut [0; 512]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}
