//! Authorization at every public request and throughout retained transports.
use std::time::Duration;

use axum::{
    body::Body,
    extract::{MatchedPath, Request, State},
    http::{HeaderMap, HeaderValue, Method, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use goldenhoop_protocol::*;
use goldenhoop_store::Store;
use uuid::Uuid;

use crate::http::{BearerAuth, HttpError};

#[derive(Clone)]
pub struct Authorizer {
    pub bootstrap: BearerAuth,
    pub store: Store,
}

#[derive(Clone)]
pub struct Principal {
    pub key: Option<ApiKey>,
    pub request_id: Uuid,
}

impl Principal {
    pub fn require(&self, permission: KeyPermission) -> Result<(), ApiError> {
        if self
            .key
            .as_ref()
            .is_some_and(|key| !key.permissions.contains(&permission))
        {
            return Err(denied());
        }
        Ok(())
    }
    pub async fn check(&self, store: &Store) -> Result<(), ApiError> {
        if let Some(key) = &self.key {
            let current = tokio::time::timeout(Duration::from_millis(500), store.api_key(key.id))
                .await
                .map_err(|_| denied())??;
            if current.revoked_at.is_some()
                || current.expires_at <= chrono::Utc::now()
                || current.permissions != key.permissions
                || current.resources != key.resources
            {
                return Err(denied());
            }
        }
        Ok(())
    }
    pub fn event(
        &self,
        action: AuditAction,
        phase: AuditPhase,
        target: Option<Uuid>,
        sandbox: Option<Uuid>,
    ) -> AuditEvent {
        AuditEvent {
            actor: if self.key.is_some() {
                AuditActor::ApiKey
            } else {
                AuditActor::Bootstrap
            },
            key_id: self.key.as_ref().map(|k| k.id),
            request_id: Some(self.request_id),
            target_id: target,
            sandbox_id: sandbox,
            action,
            phase,
            http_status: None,
        }
    }
}

fn denied() -> ApiError {
    ApiError::new(
        ErrorCode::Forbidden,
        "request is outside the current key grant",
    )
}

fn failure(mut error: ApiError, request_id: Uuid) -> Response {
    error.request_id = Some(request_id);
    HttpError::from(error).into_response()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = first.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && token.len() <= 512).then_some(token)
}

fn permission(pattern: &str, method: &Method) -> Option<KeyPermission> {
    if pattern == "/healthz" || pattern == "/v1/profiles" {
        return Some(KeyPermission::Read);
    }
    if !pattern.starts_with("/v1/") || pattern.starts_with("/v1/api-keys") || pattern == "/v1/audit"
    {
        return None;
    }
    if pattern.ends_with("/socket") {
        return Some(KeyPermission::Execute);
    }
    if pattern.contains("/credentials") && method != Method::GET && method != Method::HEAD {
        return None;
    }
    if method == Method::GET || method == Method::HEAD {
        return Some(KeyPermission::Read);
    }
    if pattern.ends_with("/network-policy") {
        return Some(KeyPermission::Network);
    }
    if pattern.contains("/commands")
        || pattern.contains("/executions/")
        || pattern.contains("/sessions")
        || pattern.contains("/code-contexts")
        || pattern.contains("/code-runs/")
    {
        return Some(KeyPermission::Execute);
    }
    Some(KeyPermission::Write)
}

fn action(pattern: &str, method: &Method) -> AuditAction {
    if pattern == "/v1/audit" {
        return AuditAction::AuditRead;
    }
    if pattern.starts_with("/v1/api-keys") {
        return if method == Method::POST {
            AuditAction::KeyCreate
        } else if method == Method::DELETE {
            AuditAction::KeyRevoke
        } else {
            AuditAction::Read
        };
    }
    match permission(pattern, method) {
        Some(KeyPermission::Read) => AuditAction::Read,
        Some(KeyPermission::Write) => AuditAction::Write,
        Some(KeyPermission::Execute) => AuditAction::Execute,
        Some(KeyPermission::Network) => AuditAction::Network,
        None => AuditAction::Unknown,
    }
}

async fn resource(store: &Store, namespace: &str, id: Uuid) -> Result<Uuid, ApiError> {
    Ok(match namespace {
        "sandboxes" => id,
        "executions" | "sessions" => store.execution(id).await?.execution.sandbox_id,
        "code-contexts" => store.code_context(id).await?.context.sandbox_id,
        "code-runs" => {
            store
                .code_context(store.code_run(id).await?.run.context_id)
                .await?
                .context
                .sandbox_id
        }
        "artifacts" => store.artifact(id).await?.artifact.sandbox_id,
        "snapshots" => store.snapshot(id).await?.snapshot.source_sandbox_id,
        "operations" => {
            let target = store.operation(id).await?.resource_id;
            if let Some(source) = store.snapshot_operation_source(id).await? {
                source
            } else if store.sandbox(target).await.is_ok() {
                target
            } else {
                store.artifact(target).await?.artifact.sandbox_id
            }
        }
        _ => return Err(denied()),
    })
}

async fn authorize(
    store: &Store,
    key: &ApiKey,
    pattern: &str,
    method: &Method,
    uri: &axum::http::Uri,
) -> Result<(Option<Uuid>, Option<Uuid>), ApiError> {
    let required = permission(pattern, method).ok_or_else(denied)?;
    if !key.permissions.contains(&required) {
        return Err(denied());
    }
    if (pattern.ends_with("/isolated-sessions") || pattern == "/v1/snapshots/{id}/restore")
        && !matches!(key.resources, KeyResources::All)
    {
        return Err(denied());
    }
    if pattern == "/healthz" || pattern == "/v1/profiles" {
        return Ok((None, None));
    }
    let parts: Vec<_> = uri.path().split('/').filter(|v| !v.is_empty()).collect();
    if let Some(raw) = parts.get(2) {
        let id = Uuid::parse_str(raw).map_err(|_| denied())?;
        let sandbox = resource(store, parts[1], id).await?;
        if !key.resources.permits(sandbox) {
            return Err(denied());
        }
        return Ok((Some(id), Some(sandbox)));
    }
    // Global collections expose other resources unless the grant is global.
    // Filtered collections must use exactly one validated sandbox selector.
    if matches!(key.resources, KeyResources::All) {
        return Ok((None, None));
    }
    if method != Method::GET || pattern == "/v1/sandboxes" {
        return Err(denied());
    }
    let url = reqwest::Url::parse(&format!("http://localhost/?{}", uri.query().unwrap_or("")))
        .map_err(|_| denied())?;
    let ids: Vec<_> = url
        .query_pairs()
        .filter(|(k, _)| k == "sandbox_id")
        .map(|(_, v)| v.into_owned())
        .collect();
    if ids.len() != 1 {
        return Err(denied());
    }
    let sandbox = Uuid::parse_str(&ids[0]).map_err(|_| denied())?;
    if !key.resources.permits(sandbox) {
        return Err(denied());
    }
    Ok((None, Some(sandbox)))
}

pub async fn authenticate(
    State(auth): State<Authorizer>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = Uuid::new_v4();
    let pattern = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("", MatchedPath::as_str)
        .to_owned();
    let action = action(&pattern, request.method());
    let principal =
        if bearer(request.headers()).is_some() && auth.bootstrap.accepts(request.headers()) {
            Ok(Principal {
                key: None,
                request_id,
            })
        } else if let Some(token) = bearer(request.headers()) {
            auth.store
                .authenticate_api_key(token)
                .await
                .map(|key| Principal {
                    key: Some(key),
                    request_id,
                })
        } else {
            Err(ApiError::new(
                ErrorCode::Unauthorized,
                "valid bearer authentication is required",
            ))
        };
    let (principal, target, sandbox, error) = match principal {
        Ok(principal) => {
            if let Some(key) = &principal.key {
                match authorize(&auth.store, key, &pattern, request.method(), request.uri()).await {
                    Ok((target, sandbox)) => (principal, target, sandbox, None),
                    Err(error) => (principal, None, None, Some(error)),
                }
            } else {
                let target = request
                    .uri()
                    .path()
                    .split('/')
                    .nth(3)
                    .and_then(|v| Uuid::parse_str(v).ok());
                (principal, target, None, None)
            }
        }
        Err(error) => {
            let event = AuditEvent {
                actor: AuditActor::Anonymous,
                key_id: None,
                request_id: Some(request_id),
                target_id: None,
                sandbox_id: None,
                action,
                phase: AuditPhase::AuthorizationDenied,
                http_status: Some(401),
            };
            if let Err(error) = auth.store.append_audit(&event).await {
                return failure(error, request_id);
            }
            return failure(error, request_id);
        }
    };
    let mut event = principal.event(
        action,
        if error.is_some() {
            AuditPhase::AuthorizationDenied
        } else {
            AuditPhase::RequestStarted
        },
        target,
        sandbox,
    );
    if let Err(error) = auth.store.append_audit(&event).await {
        return failure(error, request_id);
    }
    if let Some(error) = error {
        return failure(error, request_id);
    }
    request.extensions_mut().insert(principal.clone());
    let mut response = next.run(request).await;
    event.phase = AuditPhase::HttpReturned;
    event.http_status = Some(response.status().as_u16());
    if let Err(error) = auth.store.append_audit(&event).await {
        return failure(error, request_id);
    }
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).expect("UUID header"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if principal.key.is_some() && response.status().is_success() {
        let (parts, body) = response.into_parts();
        let store = auth.store;
        let stream = async_stream::stream! {
            let mut source=body.into_data_stream();
            loop {
                // An idle SSE body may be suspended inside a database read.
                // Keep polling it while authorization waits for the same
                // single-connection pool; hold at most one frame until the
                // authorization result is known and never emit it on denial.
                let (allowed,buffered)={
                    let checking=principal.check(&store);
                    tokio::pin!(checking);
                    let mut buffered=None;
                    let allowed=loop {
                        tokio::select! {
                            result=&mut checking=>break result.is_ok(),
                            item=source.next(),if buffered.is_none()=>buffered=Some(item),
                        }
                    };
                    (allowed,buffered)
                };
                if !allowed {
                    // Release an unfinished source read before requesting the
                    // bounded audit write, which uses that pool as well.
                    drop(source);
                    let event=principal.event(action,AuditPhase::StreamRevoked,target,sandbox);
                    // A blocked audit writer must not retain a revoked
                    // observer indefinitely. The transport is fail-closed
                    // even when this separate observation cannot be stored.
                    let _=tokio::time::timeout(Duration::from_millis(500),store.append_audit(&event)).await;
                    break;
                }
                if let Some(item)=buffered {
                    match item {Some(item)=>yield item,None=>break}
                    continue;
                }
                tokio::select! {
                    item=source.next()=>match item {Some(item)=>yield item,None=>break},
                    _=tokio::time::sleep(Duration::from_millis(200))=>{},
                }
            }
        };
        response = Response::from_parts(parts, Body::from_stream(stream));
    }
    response
}
