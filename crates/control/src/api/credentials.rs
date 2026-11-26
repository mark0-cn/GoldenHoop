use super::*;
use crate::security::Principal;
use axum::Extension;
use goldenhoop_credentials::{CredentialBinding, WriteCredential};

pub(super) async fn list(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<Vec<CredentialBinding>>, HttpError> {
    app.store.sandbox(id).await?;
    Ok(Json(app.store.credentials(id).await?))
}
pub(super) async fn inspect(
    State(app): State<AppState>,
    ApiPath((id, binding)): ApiPath<(Uuid, Uuid)>,
) -> Result<Json<CredentialBinding>, HttpError> {
    Ok(Json(app.store.credential(id, binding).await?))
}
pub(super) async fn put(
    State(app): State<AppState>,
    Extension(principal): Extension<Principal>,
    ApiPath((id, binding)): ApiPath<(Uuid, Uuid)>,
    ApiJson(input): ApiJson<WriteCredential>,
) -> Result<(StatusCode, Json<CredentialBinding>), HttpError> {
    let key = app.vault.as_ref().ok_or_else(|| {
        ApiError::new(
            ErrorCode::BackendUnavailable,
            "private credential vault is not configured",
        )
    })?;
    Ok((
        StatusCode::ACCEPTED,
        Json(
            app.store
                .put_credential(key, principal.request_id, id, binding, input)
                .await?,
        ),
    ))
}
pub(super) async fn revoke(
    State(app): State<AppState>,
    Extension(principal): Extension<Principal>,
    ApiPath((id, binding)): ApiPath<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<CredentialBinding>), HttpError> {
    Ok((
        StatusCode::ACCEPTED,
        Json(
            app.store
                .revoke_credential(principal.request_id, id, binding)
                .await?,
        ),
    ))
}
