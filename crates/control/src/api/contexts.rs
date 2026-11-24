use super::*;

pub(super) async fn create(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
    ApiJson(spec): ApiJson<CodeContextSpec>,
) -> Result<(StatusCode, Json<CodeContext>), HttpError> {
    let key = idempotency_key(&headers)?;
    goldenhoop_core::validate_code_context(&spec)?;
    if let Some(existing) = app
        .store
        .idempotent_resource(&format!("contexts:{id}:create"), key, &fingerprint(&spec)?)
        .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(app.store.code_context(existing).await?.context),
        ));
    }
    let sandbox = app.store.sandbox(id).await?.sandbox;
    let observed = profile(&app, &sandbox.profile, Some(Capability::CodeContexts)).await?;
    goldenhoop_core::require_code_language(&observed, spec.language)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(app.store.create_code_context(id, &spec, key).await?),
    ))
}

pub(super) async fn inspect(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<CodeContext>, HttpError> {
    Ok(Json(app.store.code_context(id).await?.context))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContextQuery {
    sandbox_id: Option<Uuid>,
    after: Option<Uuid>,
    limit: Option<u32>,
}
pub(super) async fn list(
    State(app): State<AppState>,
    ApiQuery(query): ApiQuery<ContextQuery>,
) -> Result<Json<CodeContextPage>, HttpError> {
    Ok(Json(
        app.store
            .list_code_contexts(query.sandbox_id, query.after, query.limit.unwrap_or(100))
            .await?,
    ))
}

pub(super) async fn close(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<CodeContext>), HttpError> {
    // Closing is durable intent; worker liveness is not a prerequisite.
    Ok((
        StatusCode::ACCEPTED,
        Json(
            app.store
                .close_code_context(id, idempotency_key(&headers)?)
                .await?,
        ),
    ))
}

pub(super) async fn start(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
    ApiJson(spec): ApiJson<CodeRunSpec>,
) -> Result<(StatusCode, Json<CodeRun>), HttpError> {
    let key = idempotency_key(&headers)?;
    goldenhoop_core::validate_code_run(&spec)?;
    if let Some(existing) = app
        .store
        .idempotent_resource(&format!("contexts:{id}:run"), key, &fingerprint(&spec)?)
        .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(app.store.code_run(existing).await?.run),
        ));
    }
    let context = app.store.code_context(id).await?.context;
    let sandbox = app.store.sandbox(context.sandbox_id).await?.sandbox;
    let observed = profile(&app, &sandbox.profile, Some(Capability::CodeContexts)).await?;
    goldenhoop_core::require_code_language(&observed, context.spec.language)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(app.store.create_code_run(id, &spec, key).await?),
    ))
}
pub(super) async fn runs(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    ApiQuery(query): ApiQuery<PageQuery>,
) -> Result<Json<CodeRunPage>, HttpError> {
    Ok(Json(
        app.store
            .list_code_runs(id, query.after, query.limit.unwrap_or(100))
            .await?,
    ))
}
pub(super) async fn run(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<CodeRun>, HttpError> {
    Ok(Json(app.store.code_run(id).await?.run))
}
pub(super) async fn cancel(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<(StatusCode, Json<CodeRun>), HttpError> {
    Ok((
        StatusCode::ACCEPTED,
        Json(app.store.cancel_code_run(id).await?),
    ))
}

pub(super) async fn events(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<EventsQuery>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, HttpError> {
    let header_cursor = headers
        .get("last-event-id")
        .map(|value| {
            let (context, sequence) = value
                .to_str()
                .ok()
                .and_then(|value| value.rsplit_once(':'))
                .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "invalid Last-Event-ID"))?;
            if Uuid::parse_str(context).ok() != Some(id) {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    "Last-Event-ID belongs to another context",
                ));
            }
            sequence.parse::<u64>().map_err(|_| {
                ApiError::new(ErrorCode::InvalidRequest, "invalid Last-Event-ID sequence")
            })
        })
        .transpose()?;
    if query.after.zip(header_cursor).is_some_and(|(a, b)| a != b) {
        return Err(ApiError::new(ErrorCode::InvalidRequest, "event cursors disagree").into());
    }
    let mut cursor = header_cursor.or(query.after).unwrap_or(0);
    if cursor > app.store.code_context(id).await?.events_cursor {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "event cursor is ahead of persisted history",
        )
        .into());
    }
    // Hold the permit inside the response body: header-level concurrency limits
    // release before a streaming response finishes.
    let permit = app
        .context_streams
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::new(
                ErrorCode::QuotaExceeded,
                "code-context event connection limit reached",
            )
        })?;
    let stream = async_stream::stream! {
        let _permit=permit;
        loop {
            // Observe state first, then query its atomic completion history.
            let snapshot=app.store.code_context(id).await;
            let batch=app.store.code_context_events(id,cursor).await;
            match (snapshot,batch) {
                (Ok(snapshot),Ok(batch)) => {
                    if batch.is_empty() && snapshot.context.cleanup==CleanupState::Complete
                        && matches!(snapshot.context.state,CodeContextState::Closed|CodeContextState::Failed) {break;}
                    for event in batch {
                        cursor=event.sequence;
                        match Event::default().id(format!("{id}:{cursor}")).event("code_context").json_data(&event) {
                            Ok(event)=>yield Ok::<Event,Infallible>(event),
                            Err(_)=>return,
                        }
                    }
                },
                (Err(error),_)|(_,Err(error)) => {
                    if let Ok(event)=Event::default().event("error").json_data(error) {yield Ok(event);}
                    break;
                },
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(10))
            .text("heartbeat"),
    ))
}
