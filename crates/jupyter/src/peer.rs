//! Authenticated single-kernel conversation. Process lifetime belongs to the agent.
use std::{io, path::Path, time::Duration};

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

impl Peer {
    /// Caller generates/owns the private prefix and bounds the entire handshake.
    pub async fn connect(prefix: &Path, uid: u32, key: Vec<u8>) -> io::Result<Self> {
        let output = Socket::connect(
            Path::new(&format!("{}-2", prefix.display())),
            Role::Subscriber,
            uid,
        )
        .await?;
        let shell = Socket::connect(
            Path::new(&format!("{}-1", prefix.display())),
            Role::Dealer,
            uid,
        )
        .await?;
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
                    if content["status"] != "ok" || !version(&content["protocol_version"]) {
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
