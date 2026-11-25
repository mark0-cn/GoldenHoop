use super::*;

pub(super) async fn get_policy(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<NetworkPolicyState>, HttpError> {
    Ok(Json(app.store.public_network_policy(id).await?))
}

pub(super) async fn set_policy(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<SetNetworkPolicy>,
) -> Result<(StatusCode, Json<NetworkPolicyChanged>), HttpError> {
    let key = idempotency_key(&headers)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(
            app.store
                .set_public_network_policy(id, &request, key)
                .await?,
        ),
    ))
}
