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
    // Provisioning is explicit credential-management intent. An established CA
    // that is missing/damaged is never silently replaced during recovery.
    input.binding.canonicalize()?;
    app.store.ensure_credential_ca(key, id).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(
            app.store
                .put_credential(key, principal.request_id, id, binding, input)
                .await?,
        ),
    ))
}

pub(super) async fn public_ca(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<serde_json::Value>, HttpError> {
    app.store.sandbox(id).await?;
    let pem = app.store.credential_ca_public(id).await?;
    Ok(Json(
        serde_json::json!({"sandbox_id":id,"certificate_pem":pem}),
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
