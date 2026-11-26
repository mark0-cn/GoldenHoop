//! Private HTTP/1 over a Unix socket owned by the tracked VMM process. Each
//! operation first reads that same connection's instance identity. There is no
//! retry, redirect, TCP fallback, capability publication or success inferred from EOF.
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use bytes::Bytes;
use goldenhoop_protocol::ErrorCode;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode, client::conn::http1::SendRequest, header};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::{net::UnixStream, task::JoinHandle};
use uuid::Uuid;

use crate::{CallError, DispatchState, models::*};

pub const MAX_API_BYTES: usize = 64 * 1024;
pub const SUPPORTED_VMM_VERSION: &str = "1.18.0";

/// Trusted driver input, derived from the owned process generation. PID/start
/// time and executable ownership must also be retained by that lifecycle journal.
#[derive(Debug, Clone, Copy)]
pub struct PeerIdentity {
    pub pid: u32,
    pub uid: u32,
    pub instance: Uuid,
}

#[derive(Debug, Clone)]
pub struct ApiClient {
    socket: PathBuf,
    peer: PeerIdentity,
    timeout: Duration,
}

struct ConnectionTask(JoinHandle<()>);

impl Drop for ConnectionTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn failure(dispatch: DispatchState, message: &'static str) -> CallError {
    CallError::new(dispatch, ErrorCode::BackendUnavailable, message)
}

pub(crate) async fn authenticated_socket(
    socket: &Path,
    peer: PeerIdentity,
) -> Result<UnixStream, CallError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = tokio::fs::symlink_metadata(socket)
        .await
        .map_err(|_| failure(DispatchState::NotSent, "private VMM socket is absent"))?;
    if !metadata.file_type().is_socket() || metadata.uid() != peer.uid {
        return Err(failure(
            DispatchState::NotSent,
            "private VMM socket ownership mismatch",
        ));
    }
    let stream = UnixStream::connect(socket).await.map_err(|_| {
        failure(
            DispatchState::NotSent,
            "cannot connect to private VMM socket",
        )
    })?;
    let credentials = stream
        .peer_cred()
        .map_err(|_| failure(DispatchState::NotSent, "cannot observe private VMM peer"))?;
    if credentials.uid() != peer.uid || credentials.pid() != Some(peer.pid as i32) {
        return Err(failure(
            DispatchState::NotSent,
            "private VMM peer identity mismatch",
        ));
    }
    Ok(stream)
}

impl ApiClient {
    pub(crate) fn peer_identity(&self) -> PeerIdentity {
        self.peer
    }
    /// Bounds the whole connection, identity read, request and response exchange.
    pub fn new(socket: PathBuf, peer: PeerIdentity, timeout: Duration) -> Result<Self, CallError> {
        if !socket.is_absolute()
            || std::os::unix::net::SocketAddr::from_pathname(&socket).is_err()
            || peer.pid == 0
            || peer.pid > i32::MAX as u32
            || peer.instance.is_nil()
            || timeout.is_zero()
            || timeout > Duration::from_secs(120)
        {
            return Err(CallError::new(
                DispatchState::NotSent,
                ErrorCode::InvalidRequest,
                "invalid private Firecracker API endpoint",
            ));
        }
        Ok(Self {
            socket,
            peer,
            timeout,
        })
    }

    pub async fn instance_info(&self) -> Result<InstanceInfo, CallError> {
        self.exchange(None).await
    }

    pub async fn configure_machine(&self, value: &MachineConfiguration) -> Result<(), CallError> {
        self.mutate(Method::PUT, "/machine-config", value).await
    }

    pub async fn configure_boot(&self, value: &BootSource) -> Result<(), CallError> {
        self.mutate(Method::PUT, "/boot-source", value).await
    }

    pub async fn configure_root(&self, value: &RootDrive) -> Result<(), CallError> {
        self.mutate(Method::PUT, "/drives/rootfs", value).await
    }

    pub async fn configure_vsock(&self, value: &Vsock) -> Result<(), CallError> {
        self.mutate(Method::PUT, "/vsock", value).await
    }

    pub async fn start(&self) -> Result<(), CallError> {
        self.mutate(
            Method::PUT,
            "/actions",
            &serde_json::json!({"action_type":"InstanceStart"}),
        )
        .await
    }

    pub async fn pause(&self) -> Result<(), CallError> {
        self.mutate(Method::PATCH, "/vm", &serde_json::json!({"state":"Paused"}))
            .await
    }

    pub async fn resume(&self) -> Result<(), CallError> {
        self.mutate(
            Method::PATCH,
            "/vm",
            &serde_json::json!({"state":"Resumed"}),
        )
        .await
    }

    pub async fn create_snapshot(&self, value: &SnapshotCreate) -> Result<(), CallError> {
        self.mutate(Method::PUT, "/snapshot/create", value).await
    }

    pub async fn load_snapshot(&self, value: &SnapshotLoad) -> Result<(), CallError> {
        self.mutate(Method::PUT, "/snapshot/load", value).await
    }

    async fn mutate<T: Serialize>(
        &self,
        method: Method,
        path: &'static str,
        value: &T,
    ) -> Result<(), CallError> {
        let body = serde_json::to_vec(value).map_err(|_| {
            CallError::new(
                DispatchState::NotSent,
                ErrorCode::InvalidRequest,
                "cannot encode Firecracker API request",
            )
        })?;
        if body.len() > MAX_API_BYTES {
            return Err(CallError::new(
                DispatchState::NotSent,
                ErrorCode::QuotaExceeded,
                "Firecracker API request exceeds limit",
            ));
        }
        self.exchange(Some((method, path, body))).await.map(|_| ())
    }

    async fn exchange(
        &self,
        mutation: Option<(Method, &'static str, Vec<u8>)>,
    ) -> Result<InstanceInfo, CallError> {
        let mut dispatched = false;
        let result = tokio::time::timeout(self.timeout, async {
            let stream = authenticated_socket(&self.socket, self.peer).await?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(|_| {
                        failure(DispatchState::NotSent, "private VMM HTTP setup failed")
                    })?;
            let _connection = ConnectionTask(tokio::spawn(async move {
                let _ = connection.await;
            }));
            if mutation.is_none() {
                dispatched = true;
            }
            let identity_dispatch = if dispatched {
                DispatchState::Uncertain
            } else {
                DispatchState::NotSent
            };
            let bytes = send(
                &mut sender,
                Method::GET,
                "/",
                Vec::new(),
                StatusCode::OK,
                identity_dispatch,
            )
            .await?;
            let info: InstanceInfo = serde_json::from_slice(&bytes)
                .map_err(|_| failure(identity_dispatch, "invalid VMM identity response"))?;
            if info.id != self.peer.instance.to_string()
                || info.app_name != "Firecracker"
                || info.vmm_version != SUPPORTED_VMM_VERSION
            {
                return Err(failure(
                    identity_dispatch,
                    "VMM instance or version identity mismatch",
                ));
            }
            if let Some((method, path, body)) = mutation {
                dispatched = true;
                send(
                    &mut sender,
                    method,
                    path,
                    body,
                    StatusCode::NO_CONTENT,
                    DispatchState::Uncertain,
                )
                .await?;
            }
            Ok(info)
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
                "private VMM API deadline exceeded",
            ))
        })
    }
}

async fn send(
    sender: &mut SendRequest<Full<Bytes>>,
    method: Method,
    path: &'static str,
    body: Vec<u8>,
    expected: StatusCode,
    dispatch: DispatchState,
) -> Result<Vec<u8>, CallError> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .map_err(|_| failure(dispatch, "cannot build private VMM request"))?;
    let mut response = sender
        .send_request(request)
        .await
        .map_err(|_| failure(dispatch, "private VMM response is uncertain"))?;
    let status = response.status();
    if response
        .headers()
        .get(header::CONTENT_LENGTH)
        .is_some_and(|length| {
            length
                .to_str()
                .ok()
                .and_then(|text| text.parse::<u64>().ok())
                .is_none_or(|length| {
                    length > MAX_API_BYTES as u64
                        || (status == StatusCode::NO_CONTENT && length != 0)
                })
        })
        || (status == StatusCode::NO_CONTENT
            && response.headers().contains_key(header::TRANSFER_ENCODING))
    {
        return Err(failure(
            dispatch,
            "invalid or oversized private VMM response",
        ));
    }
    let mut bytes = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|_| failure(dispatch, "incomplete private VMM response"))?;
        let data = frame
            .data_ref()
            .ok_or_else(|| failure(dispatch, "unexpected private VMM response trailers"))?;
        if data.len() > MAX_API_BYTES.saturating_sub(bytes.len()) {
            return Err(failure(dispatch, "private VMM response exceeds limit"));
        }
        bytes.extend_from_slice(data);
    }
    if status == expected && (status != StatusCode::NO_CONTENT || bytes.is_empty()) {
        return Ok(bytes);
    }
    if matches!(status.as_u16(), 400 | 404 | 409 | 422) {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fault {
            fault_message: String,
        }
        if let Ok(fault) = serde_json::from_slice::<Fault>(&bytes)
            && !fault.fault_message.is_empty()
        {
            return Err(CallError::new(
                if dispatch == DispatchState::NotSent {
                    dispatch
                } else {
                    DispatchState::Rejected
                },
                match status.as_u16() {
                    404 => ErrorCode::NotFound,
                    409 => ErrorCode::InvalidState,
                    _ => ErrorCode::InvalidRequest,
                },
                "Firecracker API rejected operation",
            ));
        }
    }
    Err(failure(dispatch, "unexpected private VMM API response"))
}
