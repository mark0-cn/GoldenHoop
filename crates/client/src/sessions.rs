use super::*;
use futures_util::SinkExt;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Message, client::IntoClientRequest, protocol::WebSocketConfig},
};

impl Client {
    pub async fn create_session(
        &self,
        sandbox: Uuid,
        spec: &SessionSpec,
        key: &str,
    ) -> Result<Session> {
        let session: Session = Self::json(
            self.send(
                Method::POST,
                &format!("v1/sandboxes/{sandbox}/sessions"),
                Some(
                    serde_json::to_value(spec)
                        .map_err(|_| Error::Protocol("invalid session request"))?,
                ),
                Some(key),
            )
            .await?,
        )
        .await?;
        if session.execution.id.is_nil()
            || session.execution.sandbox_id != sandbox
            || serde_json::to_value(&session.spec).ok() != serde_json::to_value(spec).ok()
        {
            return Err(Error::Protocol("session response identity mismatch"));
        }
        Ok(session)
    }
    pub async fn session(&self, id: Uuid) -> Result<Session> {
        let session: Session = self.get(&format!("v1/sessions/{id}")).await?;
        if session.execution.id != id {
            return Err(Error::Protocol("session identity mismatch"));
        }
        Ok(session)
    }
    pub async fn list_sessions(
        &self,
        sandbox: Option<Uuid>,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<SessionPage> {
        let mut path = format!("v1/sessions?limit={limit}");
        if let Some(id) = sandbox {
            path.push_str(&format!("&sandbox_id={id}"));
        }
        if let Some(id) = after {
            path.push_str(&format!("&after={id}"));
        }
        self.get(&path).await
    }
    pub async fn session_control(
        &self,
        id: Uuid,
        control: &SessionControl,
    ) -> Result<SessionControlReceipt> {
        let result = async {
            let receipt: SessionControlReceipt = Self::json(
                self.send(
                    Method::POST,
                    &format!("v1/sessions/{id}/controls"),
                    Some(
                        serde_json::to_value(control)
                            .map_err(|_| Error::Protocol("invalid session control"))?,
                    ),
                    None,
                )
                .await?,
            )
            .await?;
            validate_receipt(id, control.sequence, &receipt)?;
            Ok(receipt)
        }
        .await;
        result.map_err(|error| Error::SessionControl(id, control.sequence, Box::new(error)))
    }
    pub async fn session_control_status(
        &self,
        id: Uuid,
        sequence: u64,
    ) -> Result<SessionControlReceipt> {
        let receipt: SessionControlReceipt = self
            .get(&format!("v1/sessions/{id}/controls/{sequence}"))
            .await?;
        validate_receipt(id, sequence, &receipt)?;
        Ok(receipt)
    }
    /// Final receipts can be Applied, Rejected or Unknown. Inspect the state.
    pub async fn wait_session_control(
        &self,
        id: Uuid,
        sequence: u64,
        deadline: Duration,
    ) -> Result<SessionControlReceipt> {
        let waiting = async {
            loop {
                let receipt = self.session_control_status(id, sequence).await?;
                if receipt.state != SessionControlState::Pending {
                    return Ok(receipt);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        tokio::time::timeout(deadline, waiting)
            .await
            .map_err(|_| Error::SessionControl(id, sequence, Box::new(Error::Timeout(id))))?
    }
    /// Opens an observer/control channel. Dropping it does not cancel the session.
    pub async fn session_socket(&self, id: Uuid, after: u64) -> Result<SessionSocket> {
        let mut url = self.url(&format!("v1/sessions/{id}/socket?after={after}"))?;
        let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(scheme)
            .map_err(|_| Error::Protocol("invalid session socket URL"))?;
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|_| Error::Protocol("invalid session socket request"))?;
        request
            .headers_mut()
            .insert(AUTHORIZATION, self.0.authorization.clone());
        let config = WebSocketConfig::default()
            .max_message_size(Some(2 * 1024 * 1024))
            .max_frame_size(Some(2 * 1024 * 1024))
            .max_write_buffer_size(2 * 1024 * 1024);
        let (stream, _) = tokio::time::timeout(
            Duration::from_secs(10),
            tokio_tungstenite::connect_async_with_config(request, Some(config), false),
        )
        .await
        .map_err(|_| Error::Transport)?
        .map_err(|_| Error::Transport)?;
        Ok(SessionSocket {
            stream,
            id,
            cursor: after,
            completed: false,
            closed: false,
            sandbox: None,
        })
    }
}

fn validate_receipt(id: Uuid, sequence: u64, receipt: &SessionControlReceipt) -> Result<()> {
    if receipt.execution_id != id
        || receipt.sequence != sequence
        || sequence == 0
        || sequence > 1024
        || (matches!(
            receipt.state,
            SessionControlState::Applied | SessionControlState::Pending
        ) != receipt.error.is_none())
    {
        return Err(Error::Protocol("invalid session control receipt"));
    }
    Ok(())
}

pub struct SessionSocket {
    stream: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    id: Uuid,
    cursor: u64,
    completed: bool,
    closed: bool,
    sandbox: Option<Uuid>,
}
impl SessionSocket {
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
    pub async fn control(&mut self, control: &SessionControl) -> Result<()> {
        if self.closed {
            return Err(Error::Protocol("session socket is closed"));
        }
        let text = serde_json::to_string(&SessionSocketClientMessage::Control(control.clone()))
            .map_err(|_| Error::Protocol("invalid socket control"))?;
        if text.len() > 128 * 1024 {
            return Err(Error::Protocol("socket control exceeds message limit"));
        }
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            self.stream.send(Message::Text(text.into())),
        )
        .await;
        match result {
            Ok(Ok(())) => Ok(()),
            _ => Err(Error::SessionControl(
                self.id,
                control.sequence,
                Box::new(Error::Transport),
            )),
        }
    }
    pub async fn recv(&mut self) -> Result<Option<SessionSocketServerMessage>> {
        if self.closed {
            return if self.completed {
                Ok(None)
            } else {
                Err(Error::Protocol("socket ended without a completion event"))
            };
        }
        loop {
            let message = tokio::time::timeout(Duration::from_secs(30), self.stream.next())
                .await
                .map_err(|_| Error::Transport)?;
            match message {
                None | Some(Ok(Message::Close(_))) => {
                    self.closed = true;
                    return if self.completed {
                        Ok(None)
                    } else {
                        Err(Error::Protocol("socket ended without a completion event"))
                    };
                }
                Some(Err(_)) => return Err(Error::Transport),
                Some(Ok(Message::Text(text))) => {
                    let message: SessionSocketServerMessage = serde_json::from_str(&text)
                        .map_err(|_| Error::Protocol("invalid session socket message"))?;
                    match &message {
                        SessionSocketServerMessage::Event(event) => {
                            if event.execution_id != self.id
                                || self.sandbox.is_none()
                                || Some(event.sequence) != self.cursor.checked_add(1)
                                || self.completed
                            {
                                return Err(Error::Protocol(
                                    "socket event identity or sequence mismatch",
                                ));
                            }
                            if event.kind == EventKind::Completed {
                                let execution: Execution =
                                    serde_json::from_value(event.data.clone()).map_err(|_| {
                                        Error::Protocol("invalid socket completion")
                                    })?;
                                if execution.id != self.id
                                    || Some(execution.sandbox_id) != self.sandbox
                                    || !execution.state.is_terminal()
                                    || execution.cleanup != CleanupState::Complete
                                    || execution.finished_at.is_none()
                                    || (execution.state == ExecutionState::Succeeded
                                        && execution.exit_code != Some(0))
                                {
                                    return Err(Error::Protocol("invalid socket terminal result"));
                                }
                                self.completed = true;
                            }
                            self.cursor = event.sequence;
                        }
                        SessionSocketServerMessage::Control(receipt) => {
                            validate_receipt(self.id, receipt.sequence, receipt)?
                        }
                        SessionSocketServerMessage::Session(session) => {
                            if session.execution.id != self.id
                                || session.execution.sandbox_id.is_nil()
                                || self
                                    .sandbox
                                    .is_some_and(|id| id != session.execution.sandbox_id)
                            {
                                return Err(Error::Protocol("socket session identity mismatch"));
                            }
                            self.sandbox = Some(session.execution.sandbox_id);
                        }
                        SessionSocketServerMessage::Error(error) => {
                            return Err(Error::Api(error.clone()));
                        }
                    }
                    return Ok(Some(message));
                }
                Some(Ok(Message::Ping(_))) => {
                    tokio::time::timeout(Duration::from_secs(5), self.stream.flush())
                        .await
                        .map_err(|_| Error::Transport)?
                        .map_err(|_| Error::Transport)?;
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(_)) => return Err(Error::Protocol("unexpected binary socket message")),
            }
        }
    }
    pub async fn close(&mut self) -> Result<()> {
        self.closed = true;
        tokio::time::timeout(Duration::from_secs(5), self.stream.close(None))
            .await
            .map_err(|_| Error::Transport)?
            .map_err(|_| Error::Transport)
    }
}
