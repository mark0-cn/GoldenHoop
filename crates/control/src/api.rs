use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::Response,
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, post, put},
};
use goldenhoop_core::{request_fingerprint, require_capability};
use goldenhoop_protocol::*;
use goldenhoop_store::{Store, fingerprint};
use serde::Deserialize;
use tower::limit::ConcurrencyLimitLayer;
use uuid::Uuid;

use crate::{InternalArtifactCall, InternalFileCall, InternalSandboxCall, http::*};
use base64::{Engine, engine::general_purpose::STANDARD};

mod contexts;
mod credentials;
mod isolated;
mod network_policy;
mod security;
mod sessions;

struct App {
    store: Store,
    vault: Option<goldenhoop_credentials::VaultKey>,
    worker_client: reqwest::Client,
    session_sockets: Arc<tokio::sync::Semaphore>,
    context_streams: Arc<tokio::sync::Semaphore>,
}
type AppState = Arc<App>;

pub fn router(store: Store, token: &str) -> Result<Router, ApiError> {
    router_with_vault(store, token, None)
}

pub fn router_with_vault(
    store: Store,
    token: &str,
    vault: Option<goldenhoop_credentials::VaultKey>,
) -> Result<Router, ApiError> {
    let auth = crate::security::Authorizer {
        bootstrap: BearerAuth::new(token)?,
        store: store.clone(),
    };
    let worker_client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| {
            ApiError::new(
                ErrorCode::Internal,
                "could not initialize private worker transport",
            )
        })?;
    let app = Arc::new(App {
        store,
        vault,
        worker_client,
        session_sockets: Arc::new(tokio::sync::Semaphore::new(64)),
        context_streams: Arc::new(tokio::sync::Semaphore::new(16)),
    });
    Ok(Router::new()
        .route("/healthz", get(health))
        .route("/v1/api-keys", post(security::issue))
        .route(
            "/v1/api-keys/{id}",
            get(security::inspect).delete(security::revoke),
        )
        .route("/v1/audit", get(security::audit))
        .route("/v1/sandboxes/{id}/credentials", get(credentials::list))
        .route(
            "/v1/sandboxes/{id}/credential-ca",
            get(credentials::public_ca),
        )
        .route(
            "/v1/sandboxes/{id}/credentials/{binding}",
            get(credentials::inspect)
                .put(credentials::put)
                .delete(credentials::revoke)
                .layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route("/v1/profiles", get(profiles))
        .route("/v1/sandboxes", get(list).post(create))
        .route("/v1/sandboxes/{id}", get(inspect).delete(terminate))
        .route(
            "/v1/sandboxes/{id}/isolated-sessions",
            get(isolated::list).post(isolated::create),
        )
        .route("/v1/sandboxes/{id}/scope", get(isolated::scope))
        .route("/v1/sandboxes/{id}/pause", post(pause))
        .route("/v1/sandboxes/{id}/resume", post(resume))
        .route("/v1/sandboxes/{id}/diagnostics", get(diagnostics))
        .route(
            "/v1/sandboxes/{id}/network-policy",
            get(network_policy::get_policy)
                .put(network_policy::set_policy)
                .layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route("/v1/sandboxes/{id}/commands", post(command))
        .route("/v1/executions/{id}", get(execution))
        .route("/v1/executions/{id}/cancel", post(cancel))
        .route("/v1/executions/{id}/events", get(events))
        .route("/v1/operations/{id}", get(operation))
        .route(
            "/v1/sandboxes/{id}/files",
            put(write_file).get(read_file).delete(remove_file),
        )
        .route("/v1/sandboxes/{id}/directories", get(list_files))
        .route("/v1/sandboxes/{id}/artifacts", post(create_artifact))
        .route("/v1/artifacts", get(list_artifacts))
        .route("/v1/artifacts/{id}", get(artifact).delete(delete_artifact))
        .route("/v1/artifacts/{id}/content", get(artifact_content))
        .route("/v1/sandboxes/{id}/sessions", post(sessions::create))
        .route("/v1/sessions", get(sessions::list))
        .route("/v1/sessions/{id}", get(sessions::get_session))
        .route("/v1/sessions/{id}/cancel", post(sessions::cancel_session))
        .route("/v1/sessions/{id}/events", get(sessions::session_events))
        .route("/v1/sessions/{id}/controls", post(sessions::control))
        .route(
            "/v1/sessions/{id}/controls/{sequence}",
            get(sessions::control_status),
        )
        .route("/v1/sessions/{id}/socket", get(sessions::socket))
        .route("/v1/sandboxes/{id}/code-contexts", post(contexts::create))
        .route("/v1/code-contexts", get(contexts::list))
        .route(
            "/v1/code-contexts/{id}",
            get(contexts::inspect).delete(contexts::close),
        )
        .route(
            "/v1/code-contexts/{id}/runs",
            get(contexts::runs).post(contexts::start),
        )
        .route("/v1/code-contexts/{id}/events", get(contexts::events))
        .route("/v1/code-runs/{id}", get(contexts::run))
        .route("/v1/code-runs/{id}/cancel", post(contexts::cancel))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(24 * 1024 * 1024))
        .layer(ConcurrencyLimitLayer::new(64))
        .layer(middleware::from_fn_with_state(
            auth,
            crate::security::authenticate,
        ))
        .with_state(app))
}

async fn health(State(app): State<AppState>) -> Json<serde_json::Value> {
    Json(
        serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"installation_id":app.store.installation_id(),"worker_ready":app.store.worker().await.is_ok()}),
    )
}
async fn profiles(State(app): State<AppState>) -> Result<Json<Vec<RuntimeProfile>>, HttpError> {
    Ok(Json(app.store.worker().await?.profiles))
}
async fn profile(
    app: &App,
    id: &str,
    capability: Option<Capability>,
) -> Result<RuntimeProfile, ApiError> {
    let profile = app
        .store
        .worker()
        .await?
        .profiles
        .into_iter()
        .find(|profile| profile.id == id)
        .ok_or_else(|| {
            ApiError::new(
                ErrorCode::UnsupportedCapability,
                "requested runtime profile is not registered",
            )
        })?;
    if let Some(capability) = capability {
        require_capability(&profile, capability)?;
    }
    Ok(profile)
}

async fn create(
    State(app): State<AppState>,
    axum::Extension(principal): axum::Extension<crate::security::Principal>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<CreateSandbox>,
) -> Result<(StatusCode, Json<SandboxCreated>), HttpError> {
    if request.network != NetworkPolicy::default() {
        principal.require(KeyPermission::Network)?;
    }
    let key = idempotency_key(&headers)?;
    if let Some(id) = app
        .store
        .idempotent_resource("sandboxes:create", key, &request_fingerprint(&request)?)
        .await?
    {
        return Ok((StatusCode::ACCEPTED, Json(app.store.created(id).await?)));
    }
    let profile = profile(&app, &request.profile, None).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(app.store.create_sandbox(&profile, &request, key).await?),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    after: Option<Uuid>,
    limit: Option<u32>,
}
async fn list(
    State(app): State<AppState>,
    ApiQuery(query): ApiQuery<PageQuery>,
) -> Result<Json<SandboxPage>, HttpError> {
    Ok(Json(
        app.store
            .list_sandboxes(query.after, query.limit.unwrap_or(100))
            .await?,
    ))
}
async fn inspect(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<Sandbox>, HttpError> {
    Ok(Json(app.store.sandbox(id).await?.sandbox))
}
async fn terminate(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Operation>), HttpError> {
    Ok((
        StatusCode::ACCEPTED,
        Json(
            app.store
                .set_desired(id, DesiredState::Terminated, idempotency_key(&headers)?)
                .await?,
        ),
    ))
}
async fn change_state(
    app: &App,
    id: Uuid,
    desired: DesiredState,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Operation>), HttpError> {
    let key = idempotency_key(&headers)?;
    let kind = if desired == DesiredState::Paused {
        "pause"
    } else {
        "resume"
    };
    if let Some(operation) = app
        .store
        .idempotent_resource(
            &format!("sandboxes:{id}:{kind}"),
            key,
            &fingerprint(&desired)?,
        )
        .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(app.store.operation(operation).await?),
        ));
    }
    let stored = app.store.sandbox(id).await?;
    profile(app, &stored.sandbox.profile, Some(Capability::Pause)).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(app.store.set_desired(id, desired, key).await?),
    ))
}
async fn pause(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Operation>), HttpError> {
    change_state(&app, id, DesiredState::Paused, headers).await
}
async fn resume(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Operation>), HttpError> {
    change_state(&app, id, DesiredState::Running, headers).await
}
async fn operation(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<Operation>, HttpError> {
    Ok(Json(app.store.operation(id).await?))
}

async fn command(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
    ApiJson(spec): ApiJson<CommandSpec>,
) -> Result<(StatusCode, Json<Execution>), HttpError> {
    let key = idempotency_key(&headers)?;
    if let Some(execution) = app
        .store
        .idempotent_resource(&format!("commands:{id}"), key, &fingerprint(&spec)?)
        .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(app.store.execution(execution).await?.execution),
        ));
    }
    let sandbox = app.store.sandbox(id).await?.sandbox;
    profile(&app, &sandbox.profile, Some(Capability::Commands)).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(app.store.create_execution(id, &spec, key).await?),
    ))
}
async fn execution(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<Execution>, HttpError> {
    Ok(Json(app.store.execution(id).await?.execution))
}
async fn cancel(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<(StatusCode, Json<Execution>), HttpError> {
    Ok((
        StatusCode::ACCEPTED,
        Json(app.store.cancel_execution(id).await?),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventsQuery {
    after: Option<u64>,
}
async fn events(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<EventsQuery>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, HttpError> {
    let header_cursor = headers
        .get("last-event-id")
        .map(|value| {
            let (execution, sequence) = value
                .to_str()
                .ok()
                .and_then(|value| value.rsplit_once(':'))
                .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "invalid Last-Event-ID"))?;
            if Uuid::parse_str(execution).ok() != Some(id) {
                return Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    "Last-Event-ID belongs to another execution",
                ));
            }
            sequence.parse::<u64>().map_err(|_| {
                ApiError::new(ErrorCode::InvalidRequest, "invalid Last-Event-ID sequence")
            })
        })
        .transpose()?;
    if query
        .after
        .zip(header_cursor)
        .is_some_and(|(left, right)| left != right)
    {
        return Err(ApiError::new(ErrorCode::InvalidRequest, "event cursors disagree").into());
    }
    let mut cursor = header_cursor.or(query.after).unwrap_or(0);
    if cursor > app.store.execution(id).await?.cursor {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "event cursor is ahead of persisted history",
        )
        .into());
    }
    let stream = async_stream::stream! {
        loop {
            // Read the result first: observing a terminal snapshot then querying its
            // atomic event history cannot miss a completion committed between reads.
            let snapshot=app.store.execution(id).await;
            let batch=app.store.events(id,cursor).await;
            match (snapshot,batch) {
                (Ok(snapshot),Ok(batch)) => {
                    if batch.is_empty() && snapshot.execution.state.is_terminal() {break;}
                    for event in batch {
                        cursor=event.sequence;
                        match Event::default().id(format!("{id}:{cursor}")).event("execution").json_data(&event) {
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

async fn file_call(
    app: &App,
    sandbox_id: Uuid,
    request: AgentRequest,
) -> Result<AgentResponse, ApiError> {
    worker_call(
        app,
        "internal/files",
        &InternalFileCall {
            sandbox_id,
            request,
        },
    )
    .await
}

async fn diagnostics(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<SandboxDiagnostics>, HttpError> {
    app.store.sandbox(id).await?;
    let sample: SandboxDiagnostics = worker_call(
        &app,
        "internal/diagnostics",
        &InternalSandboxCall { sandbox_id: id },
    )
    .await?;
    if sample.sandbox.id != id
        || sample
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.sandbox_id != id)
    {
        return Err(ApiError::new(
            ErrorCode::BackendUnavailable,
            "runtime diagnostics identity mismatch",
        )
        .into());
    }
    Ok(Json(sample))
}

async fn worker_call<T: serde::de::DeserializeOwned>(
    app: &App,
    route: &str,
    request: &(impl serde::Serialize + Sync),
) -> Result<T, ApiError> {
    let worker = app.store.worker().await?;
    let endpoint = reqwest::Url::parse(&worker.endpoint).map_err(|_| {
        ApiError::new(
            ErrorCode::BackendUnavailable,
            "invalid private worker endpoint",
        )
    })?;
    if endpoint.scheme() != "http"
        || endpoint.host_str() != Some("127.0.0.1")
        || endpoint.port().is_none()
        || endpoint.path() != "/"
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(ApiError::new(
            ErrorCode::BackendUnavailable,
            "private worker endpoint must be an explicit loopback address",
        ));
    }
    let response = app
        .worker_client
        .post(
            endpoint
                .join(route)
                .map_err(|_| ApiError::new(ErrorCode::Internal, "invalid internal route"))?,
        )
        .bearer_auth(&worker.token)
        .json(request)
        .send()
        .await
        .map_err(|_| {
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "private worker transport failed",
            )
        })?;
    if !response.status().is_success() {
        let error = response.json::<ApiError>().await.map_err(|_| {
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "invalid private worker error",
            )
        })?;
        return Err(if error.code == ErrorCode::Unauthorized {
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "private worker authentication failed",
            )
        } else {
            error
        });
    }
    response.json().await.map_err(|_| {
        ApiError::new(
            ErrorCode::BackendUnavailable,
            "invalid private worker reply",
        )
    })
}

async fn create_artifact(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<CreateArtifact>,
) -> Result<(StatusCode, Json<ArtifactCreated>), HttpError> {
    let key = idempotency_key(&headers)?;
    goldenhoop_core::validate_artifact(&request)?;
    if let Some(existing) = app
        .store
        .idempotent_resource(
            &format!("sandboxes:{id}:artifacts:create"),
            key,
            &fingerprint(&request)?,
        )
        .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(app.store.artifact_created(existing).await?),
        ));
    }
    let sandbox = app.store.sandbox(id).await?.sandbox;
    profile(&app, &sandbox.profile, Some(Capability::Artifacts)).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(app.store.create_artifact(id, &request, key).await?),
    ))
}
async fn artifact(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<Artifact>, HttpError> {
    Ok(Json(app.store.artifact(id).await?.artifact))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactQuery {
    sandbox_id: Option<Uuid>,
    after: Option<Uuid>,
    limit: Option<u32>,
}
async fn list_artifacts(
    State(app): State<AppState>,
    ApiQuery(query): ApiQuery<ArtifactQuery>,
) -> Result<Json<ArtifactPage>, HttpError> {
    Ok(Json(
        app.store
            .list_artifacts(query.sandbox_id, query.after, query.limit.unwrap_or(100))
            .await?,
    ))
}
async fn delete_artifact(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Operation>), HttpError> {
    Ok((
        StatusCode::ACCEPTED,
        Json(
            app.store
                .delete_artifact(id, idempotency_key(&headers)?)
                .await?,
        ),
    ))
}
async fn artifact_content(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Response, HttpError> {
    let artifact = app.store.artifact(id).await?.artifact;
    if artifact.state != ArtifactState::Available
        || artifact.desired_state != ArtifactDesiredState::Available
    {
        return Err(
            ApiError::new(ErrorCode::InvalidState, "artifact content is not available").into(),
        );
    }
    let content: FileData = worker_call(
        &app,
        "internal/artifact-content",
        &InternalArtifactCall { artifact_id: id },
    )
    .await?;
    let bytes = STANDARD.decode(content.data_base64).map_err(|_| {
        ApiError::new(
            ErrorCode::BackendUnavailable,
            "invalid artifact content encoding",
        )
    })?;
    if bytes.len() > goldenhoop_artifacts::MAX_BLOB_BYTES
        || artifact.size_bytes != Some(bytes.len() as u64)
        || artifact.sha256.as_deref() != Some(&fingerprint_bytes(&bytes))
    {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "artifact content integrity check failed",
        )
        .into());
    }
    let mut response = Response::new(axum::body::Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let name = artifact
        .name
        .as_bytes()
        .iter()
        .map(|byte| format!("%{byte:02X}"))
        .collect::<String>();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{name}"))
            .map_err(|_| ApiError::new(ErrorCode::Internal, "invalid artifact display name"))?,
    );
    Ok(response)
}
fn fingerprint_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
async fn write_file(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(file): ApiJson<WriteFile>,
) -> Result<StatusCode, HttpError> {
    match file_call(
        &app,
        id,
        AgentRequest::WriteFile {
            path: file.path,
            data_base64: file.data_base64,
        },
    )
    .await?
    {
        AgentResponse::Ok => Ok(StatusCode::NO_CONTENT),
        _ => Err(ApiError::new(ErrorCode::Internal, "unexpected file response").into()),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileQuery {
    path: String,
    max_bytes: Option<u64>,
}
async fn read_file(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    ApiQuery(query): ApiQuery<FileQuery>,
) -> Result<Json<FileData>, HttpError> {
    match file_call(
        &app,
        id,
        AgentRequest::ReadFile {
            path: query.path,
            max_bytes: query.max_bytes.unwrap_or(16 * 1024 * 1024),
        },
    )
    .await?
    {
        AgentResponse::File { data_base64 } => Ok(Json(FileData { data_base64 })),
        _ => Err(ApiError::new(ErrorCode::Internal, "unexpected file response").into()),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathQuery {
    path: String,
}
async fn remove_file(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    ApiQuery(query): ApiQuery<PathQuery>,
) -> Result<StatusCode, HttpError> {
    match file_call(&app, id, AgentRequest::RemoveFile { path: query.path }).await? {
        AgentResponse::Ok => Ok(StatusCode::NO_CONTENT),
        _ => Err(ApiError::new(ErrorCode::Internal, "unexpected file response").into()),
    }
}
async fn list_files(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    ApiQuery(query): ApiQuery<PathQuery>,
) -> Result<Json<Vec<FileInfo>>, HttpError> {
    match file_call(&app, id, AgentRequest::ListFiles { path: query.path }).await? {
        AgentResponse::Files(files) => Ok(Json(files)),
        _ => Err(ApiError::new(ErrorCode::Internal, "unexpected file response").into()),
    }
}
