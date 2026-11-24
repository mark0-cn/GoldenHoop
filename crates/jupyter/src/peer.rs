//! Authenticated single-kernel conversation. Process lifetime belongs to the agent.
use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::{Value, json};
use tokio::time::Instant;
use uuid::Uuid;

use crate::{
    Codec, Message,
    ipc::{Role, Socket},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Shell,
    Output,
}

pub struct Observation {
    pub channel: Channel,
    pub message: Message,
}

pub struct Peer {
    codec: Codec,
    shell: Socket,
    output: Socket,
    epoch: Option<String>,
}

/// Both conventions name Unix sockets beneath the caller's private directory.
/// Some existing kernels use a colon even for the IPC transport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IpcNaming {
    #[default]
    Dash,
    Colon,
}
impl IpcNaming {
    pub fn path(self, prefix: &Path, port: u16) -> PathBuf {
        let separator = match self {
            Self::Dash => '-',
            Self::Colon => ':',
        };
        PathBuf::from(format!("{}{separator}{port}", prefix.display()))
    }
}

impl Peer {
    /// Caller generates/owns the private prefix and bounds the entire handshake.
    pub async fn connect(prefix: &Path, uid: u32, key: Vec<u8>) -> io::Result<Self> {
        Self::connect_named(prefix, uid, key, IpcNaming::Dash).await
    }

    pub async fn connect_named(
        prefix: &Path,
        uid: u32,
        key: Vec<u8>,
        naming: IpcNaming,
    ) -> io::Result<Self> {
        let output = Socket::connect(&naming.path(prefix, 2), Role::Subscriber, uid)
            .await
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("kernel output IPC connection: {error}"),
                )
            })?;
        let shell = Socket::connect(&naming.path(prefix, 1), Role::Dealer, uid)
            .await
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("kernel shell IPC connection: {error}"),
                )
            })?;
        let codec = Codec::new(key, Uuid::new_v4()).map_err(invalid)?;
        Ok(Self {
            codec,
            shell,
            output,
            epoch: None,
        })
    }

    pub async fn next(&mut self) -> io::Result<Observation> {
        let (channel, raw) = tokio::select! {
            value = self.shell.receive() => (Channel::Shell, value?),
            value = self.output.receive() => (Channel::Output, value?),
        };
        let message = self.codec.decode(&raw).map_err(invalid)?;
        if !message.buffers().is_empty() {
            return Err(invalid(
                "unsigned kernel binary-buffer extension is unsupported",
            ));
        }
        if !version(&message.header()["version"]) {
            return Err(invalid("unsupported Jupyter header version"));
        }
        match &self.epoch {
            Some(epoch) if epoch != message.kernel_session() => {
                return Err(invalid("kernel session changed; context cannot be resumed"));
            }
            None => self.epoch = Some(message.kernel_session().to_owned()),
            _ => {}
        }
        Ok(Observation { channel, message })
    }

    /// Only kernel-info is retried. Code requests are never retried here.
    pub async fn ready(&mut self) -> io::Result<Value> {
        for _ in 0..10 {
            let id = Uuid::new_v4();
            let parent = id.to_string();
            self.shell
                .send(
                    self.codec
                        .request(id, "kernel_info_request", json!({}))
                        .map_err(invalid)?,
                )
                .await?;
            let deadline = Instant::now() + Duration::from_millis(500);
            let (mut reply, mut idle) = (None, false);
            while Instant::now() < deadline {
                let next = match tokio::time::timeout_at(deadline, self.next()).await {
                    Ok(value) => value?,
                    Err(_) => break,
                };
                if next.message.parent_id() != Some(parent.as_str()) {
                    continue;
                }
                if next.channel == Channel::Shell
                    && next.message.message_type() == "kernel_info_reply"
                {
                    let content = next.message.content();
                    if !kernel_info_supported(content) {
                        return Err(invalid("kernel-info status or protocol is unsupported"));
                    }
                    reply = Some(content.clone());
                }
                if next.channel == Channel::Output
                    && next.message.message_type() == "status"
                    && next.message.content()["execution_state"] == "idle"
                {
                    idle = true;
                }
                if idle && let Some(reply) = reply {
                    return Ok(reply);
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "authenticated kernel-info/output readiness was not observed",
        ))
    }

    pub async fn execute(&mut self, id: Uuid, code: &str) -> io::Result<()> {
        let content = json!({"code":code,"silent":false,"store_history":true,"user_expressions":{},"allow_stdin":false,"stop_on_error":true});
        let request = self
            .codec
            .request(id, "execute_request", content)
            .map_err(invalid)?;
        self.shell.send(request).await
    }
}

fn kernel_info_supported(content: &Value) -> bool {
    if !version(&content["protocol_version"]) {
        return false;
    }
    match content.get("status") {
        Some(Value::String(status)) => status == "ok",
        // Existing 5.0-5.3 kernels omit this metadata status. Readiness still
        // requires authenticated matching shell info AND matching output idle.
        // This exception never applies to execute replies or code completion.
        None => matches!(
            content["protocol_version"].as_str(),
            Some("5.0" | "5.1" | "5.2" | "5.3")
        ),
        _ => false,
    }
}

fn version(value: &Value) -> bool {
    value
        .as_str()
        .and_then(|value| value.split_once('.'))
        .is_some_and(|(major, minor)| {
            major == "5" && minor.parse::<u32>().is_ok_and(|minor| minor <= 5)
        })
}
fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_info_omission_is_metadata_only_and_explicit_failure_is_never_readiness() {
        for protocol in ["5.0", "5.1", "5.2", "5.3", "5.4", "5.5"] {
            let mut content = json!({"protocol_version": protocol});
            assert_eq!(
                kernel_info_supported(&content),
                matches!(protocol, "5.0" | "5.1" | "5.2" | "5.3")
            );
            content["status"] = json!("ok");
            assert!(kernel_info_supported(&content));
            for bad in [json!("error"), json!("unknown"), Value::Null, json!(true)] {
                content["status"] = bad;
                assert!(!kernel_info_supported(&content));
            }
        }
        for protocol in ["4.1", "5.6", "6.0", "invalid"] {
            assert!(!kernel_info_supported(
                &json!({"protocol_version":protocol,"status":"ok"})
            ));
        }
    }
}
