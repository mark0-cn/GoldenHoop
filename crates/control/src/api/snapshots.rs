//! Public resources retain source authorization; private backend data stays host-side.
use super::*;

pub(super) async fn restore(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RestoreSnapshot>,
) -> Result<(StatusCode, Json<SnapshotRestored>), HttpError> {
    let key = idempotency_key(&headers)?;
    if let Some(previous) = app.store.prior_restoration(id, &request, key).await? {
        return Ok((StatusCode::ACCEPTED, Json(previous)));
    }
    let profile = profile(
        &app,
        &request.target.profile,
        Some(Capability::MemorySnapshot),
    )
    .await?;
    if profile.availability != Availability::Available {
        return Err(ApiError::new(
            ErrorCode::BackendUnavailable,
            "restoration profile is unavailable",
        )
        .into());
    }
    let reply: SnapshotRestored = worker_call(
        &app,
        "internal/restorations",
        &crate::InternalRestoreCall {
            snapshot_id: id,
            request: request.clone(),
            idempotency_key: key.into(),
        },
    )
    .await?;
    let stored = app
        .store
        .prior_restoration(id, &request, key)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "private restoration admission has no durable binding",
            )
        })?;
    if reply.snapshot_id != id
        || reply.sandbox.id != stored.sandbox.id
        || reply.operation.id != stored.operation.id
        || reply.operation.resource_id != stored.sandbox.id
    {
        return Err(ApiError::new(
            ErrorCode::BackendUnavailable,
            "private restoration reply differs from its durable target",
        )
        .into());
    }
    Ok((StatusCode::ACCEPTED, Json(stored)))
}
pub(super) async fn restoration(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<SnapshotRestored>, HttpError> {
    Ok(Json(app.store.restored(id).await?))
}

pub(super) async fn create(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<CreateSnapshot>,
) -> Result<(StatusCode, Json<SnapshotCreated>), HttpError> {
    let key = idempotency_key(&headers)?;
    if let Some(previous) = app.store.prior_snapshot_request(id, &request, key).await? {
        return Ok((StatusCode::ACCEPTED, Json(previous)));
    }
    if request.kind != SnapshotKind::MemoryAndDisk {
        return Err(ApiError::new(
            ErrorCode::UnsupportedCapability,
            "this snapshot capture path requires memory_and_disk kind",
        )
        .into());
    }
    let source = app.store.sandbox(id).await?.sandbox;
    let observed = profile(&app, &source.profile, Some(Capability::MemorySnapshot)).await?;
    if observed.availability != Availability::Available {
        return Err(ApiError::new(
            ErrorCode::BackendUnavailable,
            "snapshot source profile is unavailable",
        )
        .into());
    }
    let created: SnapshotCreated = worker_call(
        &app,
        "internal/snapshots",
        &crate::InternalSnapshotCall {
            sandbox_id: id,
            request: request.clone(),
            idempotency_key: key.into(),
        },
    )
    .await?;
    if created.snapshot.id.is_nil()
        || created.snapshot.source_sandbox_id != id
        || created.snapshot.kind != request.kind
        || created.operation.id.is_nil()
        || created.operation.resource_id != created.snapshot.id
    {
        return Err(ApiError::new(
            ErrorCode::BackendUnavailable,
            "private snapshot reply differs from its requested identity",
        )
        .into());
    }
    // The common store, not a mutable or stale worker reply, is the public truth.
    let stored = app
        .store
        .prior_snapshot_request(id, &request, key)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "private snapshot admission has no durable request binding",
            )
        })?;
    if stored.snapshot.id != created.snapshot.id || stored.operation.id != created.operation.id {
        return Err(ApiError::new(
            ErrorCode::BackendUnavailable,
            "private snapshot reply differs from durable admission",
        )
        .into());
    }
    Ok((StatusCode::ACCEPTED, Json(stored)))
}
pub(super) async fn inspect(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<Snapshot>, HttpError> {
    Ok(Json(app.store.snapshot(id).await?.snapshot))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SnapshotQuery {
    sandbox_id: Option<Uuid>,
    after: Option<Uuid>,
    limit: Option<u32>,
}
pub(super) async fn list(
    State(app): State<AppState>,
    ApiQuery(query): ApiQuery<SnapshotQuery>,
) -> Result<Json<SnapshotPage>, HttpError> {
    Ok(Json(
        app.store
            .list_snapshots(query.sandbox_id, query.after, query.limit.unwrap_or(100))
            .await?,
    ))
}
pub(super) async fn delete(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Operation>), HttpError> {
    Ok((
        StatusCode::ACCEPTED,
        Json(
            app.store
                .delete_snapshot(id, idempotency_key(&headers)?)
                .await?,
        ),
    ))
}
