//! Private host stdio control, with bounded frames and no replay after uncertainty.
//! A correlated reply is a transport result; callers still validate native state.
use crate::{Allocation, Config, Endpoint};
use goldenhoop_protocol::ApiError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    time::Instant,
};

pub const MAX_FRAME: u64 = 256 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub id: u64,
    pub command: Request,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    BindNative {
        plan: crate::native::NativeBridgePlan,
    },
    Open {
        allocation: Allocation,
    },
    Install {},
    Apply {
        expected_revision: u64,
        config: Config,
    },
    Quarantine {
        expected_revision: u64,
    },
    Renew {
        expected_revision: u64,
    },
    Inspect {},
    EnableEthernet {
        expected_revision: u64,
    },
    BindSource {
        expected_revision: u64,
        endpoint: Endpoint,
    },
    ProtectDestinations {
        expected_revision: u64,
        private_exceptions: Vec<String>,
        control_addresses: Vec<std::net::IpAddr>,
    },
    ListenDns {
        expected_revision: u64,
    },
    EnableDns {
        expected_revision: u64,
        upstream: std::net::SocketAddr,
        remaining_seconds: u16,
    },
    Resolve {
        wire: Vec<u8>,
        #[serde(default)]
        tcp: bool,
    },
    DnsSource {
        name: String,
        #[serde(default)]
        aaaa: bool,
    },
    Remove {
        expected_revision: u64,
    },
}

#[derive(Debug)]
pub enum Reply {
    Result(Value),
    /// A controller error does not attest that external state is unchanged.
    Error(ApiError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    UncertainChannel,
    InvalidRequest,
    ExpiredDeadline,
    Deadline,
    Io,
    EndOfStream,
    InvalidReply,
    ReplyTooLarge,
    SequenceExhausted,
}
impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UncertainChannel => "controller channel requires independent recovery",
            Self::InvalidRequest => "control request is invalid or exceeds the frame limit",
            Self::ExpiredDeadline => "control deadline expired before dispatch",
            Self::Deadline => "controller exchange exceeded its deadline",
            Self::Io => "controller channel I/O failed",
            Self::EndOfStream => "controller closed before replying",
            Self::InvalidReply => "controller reply is invalid or does not match the request",
            Self::ReplyTooLarge => "controller reply exceeds the frame limit",
            Self::SequenceExhausted => "controller request sequence is exhausted",
        })
    }
}
impl std::error::Error for CallError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Success {
    id: u64,
    result: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    id: u64,
    error: ApiError,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Response {
    Success(Success),
    Failure(Failure),
}

#[derive(Default)]
struct Frame(Vec<u8>);
impl std::io::Write for Frame {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > (MAX_FRAME as usize - 1).saturating_sub(self.0.len()) {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One in-flight request per private channel. Cancellation, partial writes, EOF,
/// invalid replies and deadlines permanently fence this channel. Recovery must
/// use the owned journal/native identity and an independently opened controller.
pub struct Client<R, W> {
    reader: BufReader<R>,
    writer: W,
    next_id: Option<u64>,
    uncertain: bool,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Client<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            next_id: Some(1),
            uncertain: false,
        }
    }

    pub fn is_uncertain(&self) -> bool {
        self.uncertain
    }

    pub async fn call(&mut self, command: Request, deadline: Instant) -> Result<Reply, CallError> {
        if self.uncertain {
            return Err(CallError::UncertainChannel);
        }
        let id = self.next_id.ok_or(CallError::SequenceExhausted)?;
        let mut frame = Frame::default();
        serde_json::to_writer(&mut frame, &Envelope { id, command })
            .map_err(|_| CallError::InvalidRequest)?;
        frame.0.push(b'\n');
        if Instant::now() >= deadline {
            return Err(CallError::ExpiredDeadline);
        }
        self.next_id = id.checked_add(1);
        // Set before the first await so dropping a polled call cannot replay it.
        self.uncertain = true;
        let reply = tokio::time::timeout_at(deadline, self.exchange(id, &frame.0))
            .await
            .map_err(|_| CallError::Deadline)??;
        self.uncertain = false;
        Ok(reply)
    }

    async fn exchange(&mut self, id: u64, frame: &[u8]) -> Result<Reply, CallError> {
        self.writer
            .write_all(frame)
            .await
            .map_err(|_| CallError::Io)?;
        self.writer.flush().await.map_err(|_| CallError::Io)?;
        let mut bytes = Vec::new();
        let size = (&mut self.reader)
            .take(MAX_FRAME + 1)
            .read_until(b'\n', &mut bytes)
            .await
            .map_err(|_| CallError::Io)?;
        if size == 0 {
            return Err(CallError::EndOfStream);
        }
        if size as u64 > MAX_FRAME {
            return Err(CallError::ReplyTooLarge);
        }
        if bytes.last() != Some(&b'\n') {
            return Err(CallError::InvalidReply);
        }
        if !self.reader.buffer().is_empty() {
            return Err(CallError::InvalidReply);
        }
        match serde_json::from_slice::<Response>(&bytes).map_err(|_| CallError::InvalidReply)? {
            Response::Success(reply) if reply.id == id => Ok(Reply::Result(reply.result)),
            Response::Failure(reply) if reply.id == id => Ok(Reply::Error(reply.error)),
            _ => Err(CallError::InvalidReply),
        }
    }
}
