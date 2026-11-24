use super::*;

pub(super) async fn create(
    State(app): State<AppState>,
    ApiPath(parent): ApiPath<Uuid>,
    headers: HeaderMap,
    ApiJson(spec): ApiJson<CreateIsolatedSession>,
) -> Result<(StatusCode, Json<IsolatedSessionCreated>), HttpError> {
    let key = idempotency_key(&headers)?;
    if let Some(id) = app
        .store
        .idempotent_resource(
            &format!("sandboxes:{parent}:isolated:create"),
            key,
            &fingerprint(&spec)?,
        )
        .await?
    {
        let created = app.store.created(id).await?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(IsolatedSessionCreated {
                sandbox: created.sandbox,
                scope: app.store.sandbox_scope(id).await?,
                operation: created.operation,
            }),
        ));
    }
    let source = app.store.sandbox(parent).await?.sandbox;
    let profile = profile(&app, &source.profile, Some(Capability::IsolatedSessions)).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(
            app.store
                .create_isolated_session(&profile, parent, &spec, key)
                .await?,
        ),
    ))
}

pub(super) async fn list(
    State(app): State<AppState>,
    ApiPath(parent): ApiPath<Uuid>,
    ApiQuery(query): ApiQuery<PageQuery>,
) -> Result<Json<SandboxPage>, HttpError> {
    Ok(Json(
        app.store
            .isolated_sessions(parent, query.after, query.limit.unwrap_or(100))
            .await?,
    ))
}

pub(super) async fn scope(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<SandboxScope>, HttpError> {
    Ok(Json(app.store.sandbox_scope(id).await?))
}
