use super::*;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
};
use std::collections::BTreeSet;

pub(super) async fn create(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
    ApiJson(spec): ApiJson<SessionSpec>,
) -> Result<(StatusCode, Json<Session>), HttpError> {
    let key = idempotency_key(&headers)?;
    goldenhoop_core::validate_session(&spec)?;
    if let Some(existing) = app
        .store
        .idempotent_resource(&format!("sessions:{id}"), key, &fingerprint(&spec)?)
        .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(app.store.session(existing).await?),
        ));
    }
    let sandbox = app.store.sandbox(id).await?.sandbox;
    profile(&app, &sandbox.profile, Some(Capability::ShellSessions)).await?;
    if spec.terminal.is_some() {
        profile(&app, &sandbox.profile, Some(Capability::Pty)).await?;
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(app.store.create_session(id, &spec, key).await?),
    ))
}

pub(super) async fn get_session(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<Session>, HttpError> {
    Ok(Json(app.store.session(id).await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionQuery {
    sandbox_id: Option<Uuid>,
    after: Option<Uuid>,
    limit: Option<u32>,
}
pub(super) async fn list(
    State(app): State<AppState>,
    ApiQuery(query): ApiQuery<SessionQuery>,
) -> Result<Json<SessionPage>, HttpError> {
    Ok(Json(
        app.store
            .list_sessions(query.sandbox_id, query.after, query.limit.unwrap_or(100))
            .await?,
    ))
}
pub(super) async fn cancel_session(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<(StatusCode, Json<Execution>), HttpError> {
    app.store.session(id).await?;
    super::cancel(State(app), ApiPath(id)).await
}
pub(super) async fn session_events(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<EventsQuery>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, HttpError> {
    app.store.session(id).await?;
    super::events(State(app), ApiPath(id), headers, ApiQuery(query)).await
}
async fn enqueue(
    app: &App,
    id: Uuid,
    control: &SessionControl,
) -> Result<SessionControlReceipt, ApiError> {
    if let Some(receipt) = app.store.replay_session_control(id, control).await? {
        return Ok(receipt);
    }
    let session = app.store.session(id).await?;
    let sandbox = app
        .store
        .sandbox(session.execution.sandbox_id)
        .await?
        .sandbox;
    profile(app, &sandbox.profile, Some(Capability::ShellSessions)).await?;
    if session.spec.terminal.is_some() {
        profile(app, &sandbox.profile, Some(Capability::Pty)).await?;
    }
    app.store.enqueue_session_control(id, control).await
}
pub(super) async fn control(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(control): ApiJson<SessionControl>,
) -> Result<(StatusCode, Json<SessionControlReceipt>), HttpError> {
    Ok((
        StatusCode::ACCEPTED,
        Json(enqueue(&app, id, &control).await?),
    ))
}
pub(super) async fn control_status(
    State(app): State<AppState>,
    ApiPath((id, sequence)): ApiPath<(Uuid, u64)>,
) -> Result<Json<SessionControlReceipt>, HttpError> {
    Ok(Json(app.store.session_control(id, sequence).await?.receipt))
}

pub(super) async fn socket(
    State(app): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    ApiQuery(query): ApiQuery<EventsQuery>,
    upgrade: Result<WebSocketUpgrade, axum::extract::ws::rejection::WebSocketUpgradeRejection>,
) -> Result<Response, HttpError> {
    app.store.session(id).await?;
    let after = query.after.unwrap_or(0);
    if after > app.store.execution(id).await?.cursor {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "event cursor is ahead of persisted history",
        )
        .into());
    }
    let upgrade = upgrade.map_err(|_| {
        ApiError::new(
            ErrorCode::InvalidRequest,
            "a valid WebSocket upgrade is required",
        )
    })?;
    let permit = app
        .session_sockets
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError::new(
                ErrorCode::QuotaExceeded,
                "interactive connection limit reached",
            )
        })?;
    Ok(upgrade
        .max_frame_size(128 * 1024)
        .max_message_size(128 * 1024)
        .max_write_buffer_size(2 * 1024 * 1024)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            let _ = drive_socket(app, id, after, socket).await;
        })
        .into_response())
}

async fn send(socket: &mut WebSocket, message: SessionSocketServerMessage) -> Result<(), ()> {
    let text = serde_json::to_string(&message).map_err(|_| ())?;
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.send(Message::Text(text.into())),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}
async fn drive_socket(
    app: AppState,
    id: Uuid,
    mut cursor: u64,
    mut socket: WebSocket,
) -> Result<(), ()> {
    let initial = app.store.session(id).await.map_err(|_| ())?;
    send(&mut socket, SessionSocketServerMessage::Session(initial)).await?;
    let mut pending = BTreeSet::new();
    let mut heartbeat = std::time::Instant::now();
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            message=socket.recv()=>{
                match message {
                    None|Some(Ok(Message::Close(_)))|Some(Err(_))=>return Ok(()),
                    Some(Ok(Message::Text(text)))=>{
                        let result=match serde_json::from_str::<SessionSocketClientMessage>(&text) {
                            Ok(SessionSocketClientMessage::Control(control))=>enqueue(&app,id,&control).await,
                            Err(_)=>Err(ApiError::new(ErrorCode::InvalidRequest,"invalid session socket message")),
                        };
                        match result {
                            Ok(receipt)=>{
                                if receipt.state==SessionControlState::Pending {pending.insert(receipt.sequence);}
                                send(&mut socket,SessionSocketServerMessage::Control(receipt)).await?;
                            }
                            Err(error)=>send(&mut socket,SessionSocketServerMessage::Error(error)).await?,
                        }
                    }
                    Some(Ok(Message::Ping(bytes)))=>{tokio::time::timeout(Duration::from_secs(5),socket.send(Message::Pong(bytes))).await.map_err(|_|())?.map_err(|_|())?;}
                    Some(Ok(Message::Pong(_)))=>{}
                    Some(Ok(Message::Binary(_)))=>send(&mut socket,SessionSocketServerMessage::Error(ApiError::new(ErrorCode::InvalidRequest,"use JSON controls with base64 input"))).await?,
                }
            }
            _=interval.tick()=>{
                if heartbeat.elapsed()>=Duration::from_secs(10) {
                    tokio::time::timeout(Duration::from_secs(5),socket.send(Message::Ping(Vec::new().into()))).await.map_err(|_|())?.map_err(|_|())?;
                    heartbeat=std::time::Instant::now();
                }
                let result=async {
                    // The snapshot precedes history, preserving atomic completion visibility.
                    let snapshot=app.store.session(id).await?;
                    let batch=app.store.events(id,cursor).await?;
                    Ok::<_,ApiError>((snapshot,batch))
                }.await;
                let (snapshot,batch)=match result {Ok(value)=>value,Err(error)=>{send(&mut socket,SessionSocketServerMessage::Error(error)).await?;return Err(());}};
                for sequence in pending.clone() {
                    if let Ok(control)=app.store.session_control(id,sequence).await && control.receipt.state!=SessionControlState::Pending {
                        send(&mut socket,SessionSocketServerMessage::Control(control.receipt)).await?;
                        pending.remove(&sequence);
                    }
                }
                if batch.is_empty() && snapshot.execution.state.is_terminal() {
                    send(&mut socket,SessionSocketServerMessage::Session(snapshot)).await?;
                    let _=tokio::time::timeout(Duration::from_secs(5),socket.send(Message::Close(None))).await;
                    return Ok(());
                }
                for event in batch {cursor=event.sequence;send(&mut socket,SessionSocketServerMessage::Event(event)).await?;}
            }
        }
    }
}
