use super::*;
use crate::dns::{
    Authority, GrantInstaller, GrantReceipt, GrantRequest, LeaseBook, Request, SetConfirmation,
    SetNames, StagedSets, Upstream,
};
use goldenhoop_policy::{DecisionOrigin, Model, Packet, Transport};
use goldenhoop_protocol::NetworkAction;
use std::net::SocketAddr as IpEndpoint;
use uuid::Uuid;

#[derive(Serialize)]
pub struct Resolution {
    pub revision: u64,
    pub uncertain: bool,
    pub wire: Vec<u8>,
}

pub(super) struct DnsState {
    upstream: Upstream,
    pub(super) deadline: Instant,
    pub(super) model: Option<Model>,
    pub(super) config: Option<Config>,
    pub(super) book: Option<LeaseBook>,
    pub(super) active: SetNames,
}
impl DnsState {
    pub(super) fn invalidate(&mut self, revision: u64) {
        self.model = None;
        self.config = None;
        self.book = Some(LeaseBook::new(revision, self.deadline));
        self.active = SetNames::bootstrap();
    }
}

impl Manager {
    pub(super) fn check_lifetime(&self) -> Result<(), ApiError> {
        if self
            .dns
            .as_ref()
            .is_some_and(|s| Instant::now() >= s.deadline)
        {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "configured sandbox DNS lifetime elapsed",
            ));
        }
        Ok(())
    }

    /// Trusted allocation control only. Configure once, while actual quarantine
    /// is known. This endpoint is not a workload resolver or a public API.
    pub async fn enable_dns(
        &mut self,
        expected: u64,
        upstream: IpEndpoint,
        remaining_seconds: u16,
    ) -> Result<Observation, ApiError> {
        if self.uncertain || self.can_renew || self.revision != Some(expected) || self.dns.is_some()
        {
            return Err(error(
                ErrorCode::InvalidState,
                "configure DNS once after confirmed quarantine",
            ));
        }
        if !(1..=1800).contains(&remaining_seconds) {
            return Err(error(
                ErrorCode::InvalidRequest,
                "invalid remaining sandbox DNS lifetime",
            ));
        }
        let upstream = Upstream::new(upstream)?;
        self.expected(expected).await?;
        self.dns = Some(DnsState {
            upstream,
            deadline: Instant::now() + Duration::from_secs(u64::from(remaining_seconds)),
            model: None,
            config: None,
            book: None,
            active: SetNames::bootstrap(),
        });
        self.inspect().await
    }

    fn live_dns(&self) -> Result<(), ApiError> {
        self.check_lifetime()?;
        if self.uncertain
            || !self.can_renew
            || self.lease_until.is_none_or(|until| until <= Instant::now())
        {
            return Err(error(
                ErrorCode::InvalidState,
                "DNS requires a known live controller lease",
            ));
        }
        Ok(())
    }

    pub async fn resolve(&mut self, wire: &[u8], tcp: bool) -> Result<Resolution, ApiError> {
        self.live_dns()?;
        let revision = self
            .revision
            .ok_or_else(|| error(ErrorCode::InvalidState, "DNS policy is unavailable"))?;
        let pending = {
            let state = self.dns.as_ref().ok_or_else(|| {
                error(
                    ErrorCode::UnsupportedCapability,
                    "trusted DNS is not configured",
                )
            })?;
            let model = state
                .model
                .as_ref()
                .ok_or_else(|| error(ErrorCode::InvalidState, "DNS policy is unavailable"))?;
            let request = Request::parse(wire, model, revision)?;
            state.upstream.exchange(&request).await?
        };
        let wire = pending.finish(self, tcp).await?;
        self.live_dns()?;
        Ok(Resolution {
            revision,
            uncertain: false,
            wire,
        })
    }

    pub async fn dns_source(&self, name: &str, kind: bool) -> Result<serde_json::Value, ApiError> {
        self.live_dns()?;
        let state = self
            .dns
            .as_ref()
            .ok_or_else(|| error(ErrorCode::InvalidState, "DNS is not configured"))?;
        let book = state
            .book
            .as_ref()
            .ok_or_else(|| error(ErrorCode::InvalidState, "DNS source book is unavailable"))?;
        let name = goldenhoop_policy::Domain::parse(name)?;
        let now = Instant::now();
        let expiry = book.source_expiry(
            &name,
            if kind {
                hickory_proto::rr::RecordType::AAAA
            } else {
                hickory_proto::rr::RecordType::A
            },
            now,
        )?;
        Ok(
            serde_json::json!({"revision":self.revision,"uncertain":false,"source_live":expiry.is_some(),"remaining_milliseconds":expiry.map(|until|until.saturating_duration_since(now).as_millis())}),
        )
    }

    async fn confirm_sets(
        &self,
        staged: &StagedSets,
        revision: u64,
        marker: Option<Uuid>,
    ) -> Result<SetConfirmation, ApiError> {
        self.check_bridge()?;
        let (actual, value) = self
            .table()
            .await?
            .ok_or_else(|| error(ErrorCode::Conflict, "DNS filter disappeared"))?;
        if actual != revision || dns_marker(&value)? != marker {
            return Err(error(
                ErrorCode::Conflict,
                "DNS kernel activation identity differs",
            ));
        }
        let started = Instant::now();
        let native = nft(&["list", "table", "inet", &self.allocation.table()], None).await?;
        let ended = Instant::now();
        staged.confirm_native(
            std::str::from_utf8(&native).map_err(|_| {
                error(
                    ErrorCode::BackendUnavailable,
                    "invalid native DNS set observation",
                )
            })?,
            started,
            ended,
        )
    }
}

#[async_trait::async_trait]
impl GrantInstaller for Manager {
    async fn install(&mut self, request: &GrantRequest) -> Result<GrantReceipt, ApiError> {
        self.live_dns()?;
        let revision = self
            .revision
            .ok_or_else(|| error(ErrorCode::InvalidState, "DNS policy is unavailable"))?;
        if request.revision() != revision {
            return Err(error(ErrorCode::Conflict, "DNS effective revision changed"));
        }
        let authority = match request.origin() {
            DecisionOrigin::UserAgreement => Authority::User,
            DecisionOrigin::AllowAlways(_) => Authority::OperatorAllow,
            _ => {
                return Err(error(
                    ErrorCode::Forbidden,
                    "DNS source authority is invalid",
                ));
            }
        };
        let (config, old) = {
            let state = self
                .dns
                .as_ref()
                .ok_or_else(|| error(ErrorCode::InvalidState, "DNS is unavailable"))?;
            let model = state
                .model
                .as_ref()
                .ok_or_else(|| error(ErrorCode::InvalidState, "DNS policy is unavailable"))?;
            let candidate = model.dns_candidate(request.source());
            if candidate.action != NetworkAction::Allow || candidate.origin != request.origin() {
                return Err(error(
                    ErrorCode::Forbidden,
                    "DNS source no longer matches effective policy",
                ));
            }
            for address in request.addresses() {
                let packet = Packet::new(*address, Transport::Other, None)?;
                if model
                    .leased_address_candidate(&packet, request.origin())?
                    .action
                    != NetworkAction::Allow
                {
                    return Err(error(
                        ErrorCode::Forbidden,
                        "resolved DNS address is denied by policy",
                    ));
                }
            }
            (
                state
                    .config
                    .clone()
                    .ok_or_else(|| error(ErrorCode::InvalidState, "DNS config is unavailable"))?,
                state.active.clone(),
            )
        };
        self.expected(revision).await?;
        let now = Instant::now();
        let transaction = self
            .dns
            .as_mut()
            .and_then(|s| s.book.as_mut())
            .ok_or_else(|| error(ErrorCode::InvalidState, "DNS book is unavailable"))?
            .begin(request, now)?;
        self.uncertain = true;
        self.can_renew = false;
        let staged = StagedSets::new(&self.allocation, &transaction, now)?;
        nft(&["--file", "-"], Some(staged.script().as_bytes())).await?;
        self.confirm_sets(&staged, revision, old.token()).await?;
        let activation = Plan::activate_dns(
            self.allocation.clone(),
            revision,
            &config,
            &old,
            staged.names(),
        )?;
        nft(&["--file", "-"], Some(activation.script().as_bytes())).await?;
        let confirmation = self
            .confirm_sets(&staged, revision, Some(transaction.id()))
            .await?;
        let until = if request.addresses().is_empty() {
            request.expires_at()
        } else {
            confirmation.confirmed_until(authority, request.addresses())?
        };
        let global = self
            .lease_until
            .filter(|until| *until > Instant::now())
            .ok_or_else(|| {
                error(
                    ErrorCode::DeadlineExceeded,
                    "controller lease expired during DNS installation",
                )
            })?;
        let (actual, value) = self
            .table()
            .await?
            .ok_or_else(|| error(ErrorCode::Conflict, "activated DNS table disappeared"))?;
        let marker = dns_marker(&value)?
            .ok_or_else(|| error(ErrorCode::Conflict, "DNS activation marker disappeared"))?;
        let state = self.dns.as_mut().expect("configured DNS state");
        let mut receipt = state.book.as_mut().expect("configured DNS book").commit(
            transaction,
            actual,
            marker,
            Instant::now(),
        )?;
        receipt.expires_at = receipt.expires_at.min(until).min(global);
        if !request.addresses().is_empty() && receipt.expires_at <= Instant::now() {
            return Err(error(
                ErrorCode::DeadlineExceeded,
                "DNS address expired before acknowledgement",
            ));
        }
        state.active = staged.names().clone();
        self.uncertain = false;
        self.can_renew = true;
        Ok(receipt)
    }
}

fn dns_marker(value: &Value) -> Result<Option<Uuid>, ApiError> {
    let rows = value["nftables"].as_array().ok_or_else(|| {
        error(
            ErrorCode::BackendUnavailable,
            "invalid DNS marker observation",
        )
    })?;
    let names = rows
        .iter()
        .filter_map(|entry| entry["chain"]["name"].as_str())
        .filter_map(|n| n.strip_prefix("dns_txn_"))
        .collect::<Vec<_>>();
    if names.is_empty() {
        return Ok(None);
    }
    if names.len() != 1 {
        return Err(error(
            ErrorCode::Conflict,
            "multiple DNS activation markers",
        ));
    }
    let id = Uuid::parse_str(names[0])
        .map_err(|_| error(ErrorCode::Conflict, "invalid DNS activation marker"))?;
    if id.is_nil() || id.simple().to_string() != names[0] {
        return Err(error(
            ErrorCode::Conflict,
            "noncanonical DNS activation marker",
        ));
    }
    Ok(Some(id))
}
