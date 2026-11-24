use axum::{
    Json,
    extract::{FromRequest, FromRequestParts, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub struct HttpError(pub ApiError, pub Option<StatusCode>);
impl From<ApiError> for HttpError {
    fn from(error: ApiError) -> Self {
        Self(error, None)
    }
}
impl IntoResponse for HttpError {
    fn into_response(mut self) -> Response {
        let status = self.1.unwrap_or(match self.0.code {
            ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::Conflict | ErrorCode::InvalidState => StatusCode::CONFLICT,
            ErrorCode::UnsupportedCapability => StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::BackendUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        });
        let id = *self.0.request_id.get_or_insert_with(Uuid::new_v4);
        let mut response = (status, Json(self.0)).into_response();
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_str(&id.to_string()).expect("UUID is a header value"),
        );
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

#[derive(Clone)]
pub struct BearerAuth([u8; 32]);
impl BearerAuth {
    pub fn new(token: &str) -> Result<Self, ApiError> {
        if !(32..=512).contains(&token.len())
            || !token.bytes().all(|byte| (33..=126).contains(&byte))
        {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "API token must contain 32..512 visible ASCII bytes",
            ));
        }
        Ok(Self(Sha256::digest(token.as_bytes()).into()))
    }
    pub fn accepts(&self, headers: &HeaderMap) -> bool {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map_or("", |(_, token)| token);
        let supplied: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        self.0.ct_eq(&supplied).into()
    }
}

pub async fn authenticate(
    State(auth): State<BearerAuth>,
    request: Request,
    next: Next,
) -> Response {
    if !auth.accepts(request.headers()) {
        return HttpError::from(ApiError::new(
            ErrorCode::Unauthorized,
            "valid bearer authentication is required",
        ))
        .into_response();
    }
    next.run(request).await
}

pub struct ApiJson<T>(pub T);
impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = HttpError;
    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|error| {
                let oversized = error.status() == StatusCode::PAYLOAD_TOO_LARGE;
                HttpError(
                    ApiError::new(
                        if oversized {
                            ErrorCode::QuotaExceeded
                        } else {
                            ErrorCode::InvalidRequest
                        },
                        "invalid or oversized JSON request",
                    ),
                    oversized.then_some(StatusCode::PAYLOAD_TOO_LARGE),
                )
            })
    }
}
pub struct ApiPath<T>(pub T);
impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = HttpError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "invalid resource path").into())
    }
}
pub struct ApiQuery<T>(pub T);
impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = HttpError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|_| {
                ApiError::new(ErrorCode::InvalidRequest, "invalid query parameters").into()
            })
    }
}

pub fn idempotency_key(headers: &HeaderMap) -> Result<&str, ApiError> {
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "Idempotency-Key is required"))?;
    goldenhoop_core::validate_idempotency_key(key)?;
    Ok(key)
}

pub async fn not_found() -> HttpError {
    ApiError::new(ErrorCode::NotFound, "endpoint not found").into()
}
