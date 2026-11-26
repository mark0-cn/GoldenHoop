use super::*;
use crate::security::Principal;
use axum::Extension;

pub(super) async fn issue(
    State(app): State<AppState>,
    Extension(principal): Extension<Principal>,
    ApiJson(spec): ApiJson<CreateApiKey>,
) -> Result<(StatusCode, Json<ApiKeyIssued>), HttpError> {
    Ok((
        StatusCode::CREATED,
        Json(app.store.issue_api_key(&spec, principal.request_id).await?),
    ))
}

pub(super) async fn inspect(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<ApiKey>, HttpError> {
    Ok(Json(app.store.api_key(id).await?))
}

pub(super) async fn revoke(
    State(app): State<AppState>,
    Extension(principal): Extension<Principal>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<ApiKey>, HttpError> {
    Ok(Json(
        app.store.revoke_api_key(id, principal.request_id).await?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuditQuery {
    after: Option<u64>,
    limit: Option<u32>,
    through: Option<u64>,
}

pub(super) async fn audit(
    State(app): State<AppState>,
    ApiQuery(query): ApiQuery<AuditQuery>,
) -> Result<Json<AuditPage>, HttpError> {
    Ok(Json(
        app.store
            .audit_page_through(
                query.after.unwrap_or(0),
                query.limit.unwrap_or(100),
                query.through,
            )
            .await?,
    ))
}
