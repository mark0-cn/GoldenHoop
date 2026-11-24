//! Logical DNS-source credits, not evidence of installed kernel permission.
use super::*;
use std::collections::BTreeMap;
use uuid::Uuid;

const MAX_SOURCES: usize = 256;
const MAX_MEMBERSHIPS: usize = 2048;
const MAX_LOOKUPS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Authority {
    User,
    OperatorAllow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelLease {
    pub authority: Authority,
    pub address: IpAddr,
    pub expires_at: Instant,
}

#[derive(Clone)]
struct Source {
    authority: Authority,
    addresses: Vec<IpAddr>,
    expires_at: Instant,
}
#[derive(Default, Clone)]
struct State {
    sources: BTreeMap<(Domain, RecordType), Source>,
    lookups: BTreeMap<Uuid, Instant>,
}

/// Construct an empty book only after the trusted manager has confirmed kernel
/// quarantine at this effective revision. Public values alone attest no I/O.
pub struct LeaseBook {
    revision: u64,
    sandbox_deadline: Instant,
    pending: Option<Uuid>,
    state: State,
}

#[must_use = "a dropped transaction leaves the book unknown; quarantine before further grants"]
pub struct LeaseTransaction {
    id: Uuid,
    revision: u64,
    lookup_id: Uuid,
    lookup_deadline: Instant,
    source_expiry: Instant,
    has_addresses: bool,
    next: State,
}

impl LeaseTransaction {
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Render remaining time at actual installation, never reset these absolute
    /// deadlines from the duration that happened to be left during preparation.
    pub fn memberships(&self, now: Instant) -> Vec<KernelLease> {
        memberships(&self.next, now)
    }
}

impl LeaseBook {
    pub fn new(revision: u64, sandbox_deadline: Instant) -> Self {
        Self {
            revision,
            sandbox_deadline,
            pending: None,
            state: State::default(),
        }
    }
    pub fn is_unknown(&self) -> bool {
        self.pending.is_some()
    }
    fn known(&self) -> Result<(), ApiError> {
        if self.is_unknown() {
            return Err(error(
                ErrorCode::InvalidState,
                "DNS grant installation is unknown; quarantine is required",
            ));
        }
        Ok(())
    }

    pub fn source_expiry(
        &self,
        name: &Domain,
        query_type: RecordType,
        now: Instant,
    ) -> Result<Option<Instant>, ApiError> {
        self.known()?;
        Ok(self
            .state
            .sources
            .get(&(name.clone(), query_type))
            .filter(|s| s.expires_at > now)
            .map(|s| s.expires_at))
    }

    pub fn memberships(&self, now: Instant) -> Result<Vec<KernelLease>, ApiError> {
        self.known()?;
        Ok(memberships(&self.state, now))
    }

    /// The Unknown transition happens before the caller starts a kernel batch,
    /// so cancellation cannot accidentally leave a renewable known state.
    pub fn begin(
        &mut self,
        request: &GrantRequest,
        now: Instant,
    ) -> Result<LeaseTransaction, ApiError> {
        self.known()?;
        if request.revision != self.revision {
            return Err(error(
                ErrorCode::Conflict,
                "DNS grant effective revision differs",
            ));
        }
        if now >= request.lookup_deadline
            || now >= self.sandbox_deadline
            || (!request.addresses.is_empty() && now >= request.expires_at)
        {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "DNS lookup, source or sandbox expired",
            ));
        }
        if request.addresses.len() > MAX_ADDRESSES {
            return Err(error(ErrorCode::QuotaExceeded, "too many source addresses"));
        }
        if !matches!(request.query_type, RecordType::A | RecordType::AAAA) {
            return Err(error(
                ErrorCode::InvalidRequest,
                "unsupported DNS source question type",
            ));
        }
        let authority = match request.origin {
            DecisionOrigin::AllowAlways(_) => Authority::OperatorAllow,
            DecisionOrigin::UserAgreement => Authority::User,
            _ => {
                return Err(error(
                    ErrorCode::Forbidden,
                    "DNS candidate has no grant authority",
                ));
            }
        };
        let mut next = self.state.clone();
        next.sources.retain(|_, s| s.expires_at > now);
        next.lookups.retain(|_, expiry| *expiry > now);
        if next.lookups.contains_key(&request.lookup_id) {
            return Err(error(ErrorCode::Conflict, "DNS lookup was already applied"));
        }
        if next.lookups.len() >= MAX_LOOKUPS {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "too many recent DNS lookups",
            ));
        }
        next.lookups
            .insert(request.lookup_id, request.lookup_deadline);
        let source_expiry = request.expires_at.min(self.sandbox_deadline);
        if request.addresses.is_empty() {
            next.sources
                .remove(&(request.source.clone(), request.query_type));
        } else {
            let addresses = request
                .addresses
                .iter()
                .map(|ip| ip.to_canonical())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            next.sources.insert(
                (request.source.clone(), request.query_type),
                Source {
                    authority,
                    addresses,
                    expires_at: source_expiry,
                },
            );
        }
        if next.sources.len() > MAX_SOURCES || memberships(&next, now).len() > MAX_MEMBERSHIPS {
            return Err(error(
                ErrorCode::QuotaExceeded,
                "DNS source or membership budget exhausted",
            ));
        }
        let id = Uuid::new_v4();
        self.pending = Some(id);
        Ok(LeaseTransaction {
            id,
            revision: self.revision,
            lookup_id: request.lookup_id,
            lookup_deadline: request.lookup_deadline,
            source_expiry,
            has_addresses: !request.addresses.is_empty(),
            next,
        })
    }

    /// The concrete manager must obtain these identifiers from its owned nft
    /// table after atomic mutation, never from a peer or proposed transaction.
    /// Any failed acknowledgement keeps Unknown and requires quarantine.
    pub fn commit(
        &mut self,
        transaction: LeaseTransaction,
        observed_revision: u64,
        observed_transaction: Uuid,
        now: Instant,
    ) -> Result<GrantReceipt, ApiError> {
        if self.pending != Some(transaction.id)
            || transaction.revision != self.revision
            || observed_revision != transaction.revision
            || observed_transaction != transaction.id
        {
            return Err(error(
                ErrorCode::Conflict,
                "DNS kernel transaction acknowledgement differs",
            ));
        }
        if now >= transaction.lookup_deadline
            || now >= self.sandbox_deadline
            || (transaction.has_addresses && now >= transaction.source_expiry)
        {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "DNS transaction expired before acknowledgement",
            ));
        }
        self.state = transaction.next;
        self.pending = None;
        Ok(GrantReceipt {
            lookup_id: transaction.lookup_id,
            revision: self.revision,
            expires_at: transaction.source_expiry,
        })
    }
}

fn memberships(state: &State, now: Instant) -> Vec<KernelLease> {
    let mut merged = BTreeMap::<(Authority, IpAddr), Instant>::new();
    for source in state.sources.values().filter(|s| s.expires_at > now) {
        for address in &source.addresses {
            merged
                .entry((source.authority, *address))
                .and_modify(|expiry| *expiry = (*expiry).max(source.expires_at))
                .or_insert(source.expires_at);
        }
    }
    merged
        .into_iter()
        .map(|((authority, address), expires_at)| KernelLease {
            authority,
            address,
            expires_at,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn grant(name: &str, ip: &str, ttl: u64, now: Instant) -> GrantRequest {
        GrantRequest {
            lookup_id: Uuid::new_v4(),
            lookup_deadline: now + Duration::from_secs(6),
            revision: 9,
            source: Domain::parse(name).unwrap(),
            query_type: RecordType::A,
            origin: DecisionOrigin::UserAgreement,
            addresses: vec![ip.parse().unwrap()],
            expires_at: now + Duration::from_secs(ttl),
        }
    }
    fn accept(book: &mut LeaseBook, grant: &GrantRequest, now: Instant) -> GrantReceipt {
        let transaction = book.begin(grant, now).unwrap();
        let id = transaction.id();
        book.commit(transaction, 9, id, now).unwrap()
    }
    fn book(now: Instant) -> LeaseBook {
        LeaseBook::new(9, now + Duration::from_secs(3600))
    }

    #[test]
    fn live_alias_protects_shared_ip_without_reviving_an_expired_original_source() {
        let now = Instant::now();
        let mut book = book(now);
        let original = grant("original.test", "192.0.2.1", 1, now);
        let alias = grant("alias.test", "192.0.2.1", 10, now);
        accept(&mut book, &original, now);
        accept(&mut book, &alias, now);
        let later = now + Duration::from_secs(2);
        assert_eq!(
            book.source_expiry(&original.source, RecordType::A, later)
                .unwrap(),
            None
        );
        assert_eq!(
            book.source_expiry(&alias.source, RecordType::A, later)
                .unwrap(),
            Some(alias.expires_at)
        );
        let leases = book.memberships(later).unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].expires_at, alias.expires_at);
        assert!(book.begin(&original, later).is_err());
        assert!(!book.is_unknown());
        assert!(
            book.memberships(now + Duration::from_secs(11))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn replacement_and_negative_answers_revoke_only_their_own_source() {
        let now = Instant::now();
        let mut book = book(now);
        let a = grant("a.test", "192.0.2.1", 30, now);
        let b = grant("b.test", "192.0.2.1", 60, now);
        accept(&mut book, &a, now);
        accept(&mut book, &b, now);
        let changed = grant("a.test", "192.0.2.2", 20, now);
        accept(&mut book, &changed, now);
        assert_eq!(book.memberships(now).unwrap().len(), 2);
        let mut negative = grant("a.test", "192.0.2.2", 20, now);
        negative.addresses.clear();
        accept(&mut book, &negative, now);
        assert_eq!(
            book.source_expiry(&a.source, RecordType::A, now).unwrap(),
            None
        );
        let leases = book.memberships(now).unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].address, b.addresses[0]);
    }

    #[test]
    fn cancellation_wrong_acknowledgement_and_late_acknowledgement_hold_unknown() {
        let now = Instant::now();
        let grant = grant("a.test", "192.0.2.1", 60, now);
        for failure in 0..4 {
            let mut book = book(now);
            let transaction = book.begin(&grant, now).unwrap();
            let id = transaction.id();
            match failure {
                0 => drop(transaction),
                1 => {
                    assert!(book.commit(transaction, 9, Uuid::new_v4(), now).is_err());
                }
                2 => {
                    assert!(
                        book.commit(transaction, 9, id, now + Duration::from_secs(7))
                            .is_err()
                    );
                }
                _ => {
                    assert!(book.commit(transaction, 10, id, now).is_err());
                }
            }
            assert!(book.is_unknown());
            assert!(book.begin(&grant, now).is_err());
            assert!(book.memberships(now).is_err());
            assert!(
                book.source_expiry(&grant.source, RecordType::A, now)
                    .is_err()
            );
        }
    }

    #[test]
    fn replay_revision_authority_and_sandbox_expiry_cannot_widen_grants() {
        let now = Instant::now();
        let mut book = LeaseBook::new(9, now + Duration::from_secs(5));
        let source = grant("a.test", "::ffff:192.0.2.1", 60, now);
        let receipt = accept(&mut book, &source, now);
        assert_eq!(receipt.expires_at, now + Duration::from_secs(5));
        assert!(book.begin(&source, now).is_err());
        assert!(book.begin(&source, now + Duration::from_secs(7)).is_err());
        let mut wrong = grant("b.test", "192.0.2.2", 60, now);
        wrong.revision = 8;
        assert!(book.begin(&wrong, now).is_err());
        wrong.revision = 9;
        wrong.origin = DecisionOrigin::DenyAlways(0);
        assert!(book.begin(&wrong, now).is_err());
        assert!(!book.is_unknown());
        let mut late = LeaseBook::new(9, now + Duration::from_secs(3600));
        assert!(
            matches!(late.begin(&source,now+Duration::from_secs(7)),Err(e) if e.code==ErrorCode::DeadlineExceeded)
        );
        let leases = book.memberships(now).unwrap();
        assert_eq!(leases[0].address, "192.0.2.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn operator_and_user_memberships_stay_separate() {
        let now = Instant::now();
        let mut book = book(now);
        let a = grant("a.test", "192.0.2.1", 60, now);
        let mut b = grant("b.test", "192.0.2.1", 30, now);
        b.origin = DecisionOrigin::AllowAlways(2);
        accept(&mut book, &a, now);
        accept(&mut book, &b, now);
        let leases = book.memberships(now).unwrap();
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].authority, Authority::User);
        assert_eq!(leases[1].authority, Authority::OperatorAllow);
        assert_eq!(leases[0].expires_at, a.expires_at);
        assert_eq!(leases[1].expires_at, b.expires_at);
    }

    #[test]
    fn a_and_aaaa_of_one_name_do_not_overwrite_or_negatively_clear_each_other() {
        let now = Instant::now();
        let mut book = book(now);
        let v4 = grant("both.test", "192.0.2.1", 60, now);
        let mut v6 = grant("both.test", "2001:db8::1", 30, now);
        v6.query_type = RecordType::AAAA;
        accept(&mut book, &v4, now);
        accept(&mut book, &v6, now);
        assert_eq!(book.memberships(now).unwrap().len(), 2);
        assert_eq!(
            book.source_expiry(&v4.source, RecordType::A, now).unwrap(),
            Some(v4.expires_at)
        );
        assert_eq!(
            book.source_expiry(&v6.source, RecordType::AAAA, now)
                .unwrap(),
            Some(v6.expires_at)
        );
        let mut negative = grant("both.test", "192.0.2.1", 30, now);
        negative.query_type = RecordType::AAAA;
        negative.addresses.clear();
        accept(&mut book, &negative, now);
        assert_eq!(
            book.source_expiry(&v4.source, RecordType::A, now).unwrap(),
            Some(v4.expires_at)
        );
        assert_eq!(
            book.source_expiry(&v4.source, RecordType::AAAA, now)
                .unwrap(),
            None
        );
        assert_eq!(book.memberships(now).unwrap().len(), 1);
    }

    #[test]
    fn source_membership_and_replay_budgets_refuse_before_unknown_transition() {
        let now = Instant::now();
        let mut sources = book(now);
        for i in 0..MAX_SOURCES {
            accept(
                &mut sources,
                &grant(&format!("s{i}.test"), "192.0.2.1", 60, now),
                now,
            );
        }
        assert!(
            matches!(sources.begin(&grant("overflow.test","192.0.2.1",60,now),now),Err(e) if e.code==ErrorCode::QuotaExceeded)
        );
        assert!(!sources.is_unknown());
        let after_expiry = now + Duration::from_secs(61);
        accept(
            &mut sources,
            &grant("after-expiry.test", "192.0.2.2", 60, after_expiry),
            after_expiry,
        );
        assert_eq!(sources.memberships(after_expiry).unwrap().len(), 1);
        let mut lookups = book(now);
        for _ in 0..MAX_LOOKUPS {
            accept(&mut lookups, &grant("same.test", "192.0.2.1", 60, now), now);
        }
        assert!(
            matches!(lookups.begin(&grant("same.test","192.0.2.1",60,now),now),Err(e) if e.code==ErrorCode::QuotaExceeded)
        );
        assert!(!lookups.is_unknown());
        let later = now + Duration::from_secs(7);
        accept(
            &mut lookups,
            &grant("same.test", "192.0.2.1", 60, later),
            later,
        );
        let mut addresses = book(now);
        for i in 0..MAX_MEMBERSHIPS / MAX_ADDRESSES {
            let mut source = grant(&format!("a{i}.test"), "192.0.2.1", 60, now);
            source.addresses = (0..MAX_ADDRESSES)
                .map(|j| IpAddr::V4((0xc0000000u32 + (i * MAX_ADDRESSES + j) as u32).into()))
                .collect();
            accept(&mut addresses, &source, now);
        }
        assert!(
            matches!(addresses.begin(&grant("new.test","203.0.113.1",60,now),now),Err(e) if e.code==ErrorCode::QuotaExceeded)
        );
        assert!(!addresses.is_unknown());
    }
}
