//! Explicit host diagnostic for an already-owned table with no packet hooks.
use super::*;
use crate::{Allocation, Manager, manager::nft};
use serde_json::{Value, json};

pub async fn probe_staged_sets(allocation: Allocation) -> Result<Value, ApiError> {
    let manager = Manager::new(allocation.clone()).await?;
    let observed = manager.inspect().await?;
    if !observed.installed || observed.revision != Some(0) {
        return Err(error(
            ErrorCode::Conflict,
            "probe requires an owned revision-zero table",
        ));
    }
    let table = allocation.table();
    let before: Value =
        serde_json::from_slice(&nft(&["--json", "list", "table", "inet", &table], None).await?)
            .map_err(|_| {
                error(
                    ErrorCode::BackendUnavailable,
                    "invalid probe table observation",
                )
            })?;
    if before["nftables"]
        .as_array()
        .ok_or_else(|| {
            error(
                ErrorCode::BackendUnavailable,
                "missing probe table observation",
            )
        })?
        .iter()
        .any(|entry| {
            entry
                .get("chain")
                .is_some_and(|chain| chain.get("hook").is_some())
        })
    {
        return Err(error(
            ErrorCode::Forbidden,
            "probe refuses a table with a packet hook",
        ));
    }
    let model = Model::new(
        vec![goldenhoop_policy::Policy::compile(
            &goldenhoop_protocol::NetworkPolicy {
                default_action: NetworkAction::Allow,
                rules: vec![],
            },
        )?],
        goldenhoop_policy::Overlays::default(),
    )?;
    let mut query = Message::query();
    query.queries.push(Query::query(
        Name::from_ascii("probe.test.").expect("constant name"),
        RecordType::A,
    ));
    let request = Request::parse(
        &query
            .to_vec()
            .map_err(|_| error(ErrorCode::Internal, "cannot encode probe question"))?,
        &model,
        0,
    )?;
    let mut reply = Message::response(request.upstream_id, OpCode::Query);
    reply.queries.push(request.query.clone());
    reply.answers.push(Record::from_rdata(
        request.query.name.clone(),
        10,
        RData::A(hickory_proto::rr::rdata::A(
            "192.0.2.1".parse().expect("constant IP"),
        )),
    ));
    let pending = request.prepare(
        &reply
            .to_vec()
            .map_err(|_| error(ErrorCode::Internal, "cannot encode probe answer"))?,
    )?;
    let now = Instant::now();
    let mut book = LeaseBook::new(0, now + Duration::from_secs(60));
    let transaction = book.begin(pending.grant(), now)?;
    let staged = StagedSets::new(&allocation, &transaction, now)?;
    let result=async {
        nft(&["--file","-"],Some(staged.script().as_bytes())).await?;
        manager.inspect().await?; // JSON ownership and revision before native data.
        let started=Instant::now();
        let bytes=nft(&["list","table","inet",&table],None).await?;
        let finished=Instant::now();
        let native=std::str::from_utf8(&bytes).map_err(|_|error(ErrorCode::BackendUnavailable,"invalid native nft observation"))?;
        let confirmation=staged.confirm_native(native,started,finished).inspect_err(|_|{
            // Only this explicit no-hook diagnostic dumps its owned table.
            eprintln!("{}",json!({"probe_native":native,"probe_script":staged.script(),"read_milliseconds":finished.duration_since(started).as_millis()}));
        })?;
        let expiry=confirmation.confirmed_until(Authority::User,pending.grant().addresses())?;
        if expiry<=Instant::now() || expiry>pending.grant().expires_at(){return Err(error(ErrorCode::BackendUnavailable,"probe expiry confirmation is invalid"));}
        Ok::<_,ApiError>(json!({"result":"passed","scope":"unreferenced timed sets only; no packet grant or DNS frontend","staging_token":transaction.id(),
            "confirmed_remaining_milliseconds":expiry.saturating_duration_since(Instant::now()).as_millis(),"ledger_committed":false,"packet_hooks_installed":false}))
    }.await;
    // Exact owner still required after failure; only our generated set names
    // may be removed. The outer fixture separately collects the whole table.
    manager.inspect().await?;
    let value: Value =
        serde_json::from_slice(&nft(&["--json", "list", "table", "inet", &table], None).await?)
            .map_err(|_| {
                error(
                    ErrorCode::BackendUnavailable,
                    "cannot verify staged set collection",
                )
            })?;
    let rows = value["nftables"].as_array().ok_or_else(|| {
        error(
            ErrorCode::BackendUnavailable,
            "missing staged set collection observation",
        )
    })?;
    let mut batch = String::new();
    for (name, _, _) in staged.names().entries() {
        if rows.iter().any(|entry| {
            entry["set"]["name"] == name
                && entry["set"]["table"] == table
                && entry["set"]["family"] == "inet"
        }) {
            batch.push_str(&format!("delete set inet {table} {name}\n"));
        }
    }
    if !batch.is_empty() {
        nft(&["--file", "-"], Some(batch.as_bytes())).await?;
    }
    let after: Value =
        serde_json::from_slice(&nft(&["--json", "list", "table", "inet", &table], None).await?)
            .map_err(|_| {
                error(
                    ErrorCode::BackendUnavailable,
                    "invalid staged set absence observation",
                )
            })?;
    let rows = after["nftables"].as_array().ok_or_else(|| {
        error(
            ErrorCode::BackendUnavailable,
            "missing staged set absence observation",
        )
    })?;
    if staged
        .names()
        .entries()
        .any(|(name, _, _)| rows.iter().any(|e| e["set"]["name"] == name))
    {
        return Err(error(
            ErrorCode::BackendUnavailable,
            "staged set collection is unconfirmed",
        ));
    }
    result.map(|mut value| {
        value["staged_sets_confirmed_absent"] = json!(true);
        value
    })
}
