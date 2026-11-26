//! The host's private guest-agent transport. No request is sent before the VMM
//! process/instance and virtio-vsock acknowledgement are independently checked.
use std::{path::PathBuf, time::Duration};

use goldenhoop_protocol::{AgentReply, AgentRequest, ErrorCode};
use tokio::io::{AsyncWriteExt, BufReader};

use crate::{
    CallError, DispatchState,
    api::{ApiClient, authenticated_socket},
    models::InstanceState,
    vsock::{MAX_AGENT_FRAME, parse_connect_ack, read_frame},
};

#[derive(Clone)]
pub struct AgentClient {
    api: ApiClient,
    socket: PathBuf,
    port: u32,
    timeout: Duration,
}

impl AgentClient {
    pub fn new(
        api: ApiClient,
        socket: PathBuf,
        port: u32,
        timeout: Duration,
    ) -> Result<Self, CallError> {
        if !socket.is_absolute()
            || std::os::unix::net::SocketAddr::from_pathname(&socket).is_err()
            || port == 0
            || port >= 1024
            || timeout.is_zero()
            || timeout > Duration::from_secs(120)
        {
            return Err(CallError::new(
                DispatchState::NotSent,
                ErrorCode::InvalidRequest,
                "invalid private guest agent endpoint",
            ));
        }
        Ok(Self {
            api,
            socket,
            port,
            timeout,
        })
    }

    pub async fn rpc_reply(&self, request: &AgentRequest) -> Result<AgentReply, CallError> {
        let mut bytes = serde_json::to_vec(request).map_err(|_| {
            CallError::new(
                DispatchState::NotSent,
                ErrorCode::InvalidRequest,
                "cannot encode guest request",
            )
        })?;
        bytes.push(b'\n');
        if bytes.len() > MAX_AGENT_FRAME {
            return Err(CallError::new(
                DispatchState::NotSent,
                ErrorCode::QuotaExceeded,
                "guest request exceeds limit",
            ));
        }
        let mut dispatched = false;
        let result = tokio::time::timeout(self.timeout, async {
            let info = self.api.instance_info().await.map_err(|error| {
                CallError::new(
                    DispatchState::NotSent,
                    error.error.code,
                    "cannot authenticate VMM for guest request",
                )
            })?;
            if info.state != InstanceState::Running {
                return Err(CallError::new(
                    DispatchState::NotSent,
                    ErrorCode::InvalidState,
                    "guest is not running",
                ));
            }
            let stream = authenticated_socket(&self.socket, self.api.peer_identity()).await?;
            let mut stream = BufReader::new(stream);
            stream
                .get_mut()
                .write_all(format!("CONNECT {}\n", self.port).as_bytes())
                .await
                .map_err(|_| {
                    CallError::new(
                        DispatchState::NotSent,
                        ErrorCode::BackendUnavailable,
                        "guest connect request failed",
                    )
                })?;
            let acknowledgement = read_frame(&mut stream, 32).await.map_err(|_| {
                CallError::new(
                    DispatchState::NotSent,
                    ErrorCode::BackendUnavailable,
                    "guest connect acknowledgement is incomplete",
                )
            })?;
            parse_connect_ack(&acknowledgement).map_err(|_| {
                CallError::new(
                    DispatchState::NotSent,
                    ErrorCode::BackendUnavailable,
                    "guest connect acknowledgement is invalid",
                )
            })?;
            dispatched = true;
            stream.get_mut().write_all(&bytes).await.map_err(|_| {
                CallError::new(
                    DispatchState::Uncertain,
                    ErrorCode::BackendUnavailable,
                    "guest request dispatch is uncertain",
                )
            })?;
            let reply = read_frame(&mut stream, MAX_AGENT_FRAME)
                .await
                .map_err(|_| {
                    CallError::new(
                        DispatchState::Uncertain,
                        ErrorCode::BackendUnavailable,
                        "guest response is incomplete or oversized",
                    )
                })?;
            serde_json::from_slice(&reply).map_err(|_| {
                CallError::new(
                    DispatchState::Uncertain,
                    ErrorCode::BackendUnavailable,
                    "invalid guest response",
                )
            })
        })
        .await;
        result.unwrap_or_else(|_| {
            Err(CallError::new(
                if dispatched {
                    DispatchState::Uncertain
                } else {
                    DispatchState::NotSent
                },
                ErrorCode::DeadlineExceeded,
                "guest transport deadline exceeded",
            ))
        })
    }
}
