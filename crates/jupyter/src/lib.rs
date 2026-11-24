//! Bounded Jupyter wire framing. This does not launch or establish trust in a kernel.
use chrono::{SecondsFormat, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2_11::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
pub mod ipc;
#[cfg(target_os = "linux")]
pub mod peer;

pub const DELIMITER: &[u8] = b"<IDS|MSG>";
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_FRAMES: usize = 64;
const MAX_ROUTING_FRAMES: usize = 8;
const MAX_ROUTING_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Limits,
    Malformed,
    Authentication,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Limits => "kernel message exceeds wire limits",
            Self::Malformed => "kernel message is malformed",
            Self::Authentication => "kernel JSON message authentication failed",
        })
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Guest-local key material is deliberately neither serializable nor Debug.
pub struct Codec {
    key: Zeroizing<Vec<u8>>,
    session: Uuid,
}

/// Only the four JSON frames are authenticated by the Jupyter signature.
/// Routing IDs and optional binary buffers are outside that signature's scope.
#[derive(Debug, Clone)]
pub struct Message {
    header: Value,
    parent: Value,
    metadata: Value,
    content: Value,
    buffers: Vec<Vec<u8>>,
}
impl Message {
    pub fn header(&self) -> &Value {
        &self.header
    }
    pub fn parent(&self) -> &Value {
        &self.parent
    }
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }
    pub fn content(&self) -> &Value {
        &self.content
    }
    pub fn buffers(&self) -> &[Vec<u8>] {
        &self.buffers
    }
    pub fn message_type(&self) -> &str {
        self.header["msg_type"].as_str().expect("validated header")
    }
    pub fn message_id(&self) -> &str {
        self.header["msg_id"].as_str().expect("validated header")
    }
    pub fn kernel_session(&self) -> &str {
        self.header["session"].as_str().expect("validated header")
    }
    pub fn parent_id(&self) -> Option<&str> {
        self.parent.get("msg_id").and_then(Value::as_str)
    }
}

impl Codec {
    pub fn new(key: Vec<u8>, session: Uuid) -> Result<Self> {
        let key = Zeroizing::new(key);
        if !(32..=128).contains(&key.len()) || session.is_nil() {
            return Err(Error::Malformed);
        }
        Ok(Self { key, session })
    }
    fn mac(&self) -> Hmac<Sha256> {
        Hmac::<Sha256>::new_from_slice(self.key.as_slice()).expect("HMAC accepts the bounded key")
    }

    pub fn request(&self, id: Uuid, message_type: &str, content: Value) -> Result<Vec<Vec<u8>>> {
        if id.is_nil() || !text(message_type, 128) || !content.is_object() {
            return Err(Error::Malformed);
        }
        let header = json!({"msg_id":id,"session":self.session,"username":"goldenhoop","date":Utc::now().to_rfc3339_opts(SecondsFormat::Millis,true),"msg_type":message_type,"version":"5.3"});
        let values = [header, json!({}), json!({}), content];
        let parts = values
            .iter()
            .map(|value| serde_json::to_vec(value).map_err(|_| Error::Malformed))
            .collect::<Result<Vec<_>>>()?;
        if parts.iter().any(|part| part.len() > MAX_JSON_BYTES) {
            return Err(Error::Limits);
        }
        let mut mac = self.mac();
        for part in &parts {
            mac.update(part);
        }
        let signature = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mut frames = vec![DELIMITER.to_vec(), signature.into_bytes()];
        frames.extend(parts);
        Ok(frames)
    }

    /// Authenticate original bytes before decoding JSON; do not reserialize for MAC.
    pub fn decode<B: AsRef<[u8]>>(&self, frames: &[B]) -> Result<Message> {
        if frames.len() > MAX_FRAMES {
            return Err(Error::Limits);
        }
        let total = frames
            .iter()
            .try_fold(0usize, |total, frame| {
                total.checked_add(frame.as_ref().len())
            })
            .ok_or(Error::Limits)?;
        if total > MAX_MESSAGE_BYTES {
            return Err(Error::Limits);
        }
        let delimiter = frames
            .iter()
            .take(MAX_ROUTING_FRAMES + 1)
            .position(|frame| frame.as_ref() == DELIMITER)
            .ok_or(Error::Malformed)?;
        if frames[..delimiter]
            .iter()
            .any(|frame| frame.as_ref().len() > MAX_ROUTING_BYTES)
        {
            return Err(Error::Limits);
        }
        if frames.len() - delimiter < 6 {
            return Err(Error::Malformed);
        }
        let signature = signature_bytes(frames[delimiter + 1].as_ref())?;
        let payload = &frames[delimiter + 2..delimiter + 6];
        if payload
            .iter()
            .any(|frame| frame.as_ref().len() > MAX_JSON_BYTES)
        {
            return Err(Error::Limits);
        }
        let mut mac = self.mac();
        for frame in payload {
            mac.update(frame.as_ref());
        }
        mac.verify_slice(&signature)
            .map_err(|_| Error::Authentication)?;
        let mut values = payload.iter().map(|frame| {
            serde_json::from_slice::<Value>(frame.as_ref()).map_err(|_| Error::Malformed)
        });
        let header = values.next().expect("four frames")?;
        let parent = values.next().expect("four frames")?;
        let metadata = values.next().expect("four frames")?;
        let content = values.next().expect("four frames")?;
        if !header.is_object()
            || !parent.is_object()
            || !metadata.is_object()
            || !content.is_object()
        {
            return Err(Error::Malformed);
        }
        for field in ["msg_id", "session", "msg_type", "version"] {
            if !header
                .get(field)
                .and_then(Value::as_str)
                .is_some_and(|value| text(value, if field == "version" { 16 } else { 256 }))
            {
                return Err(Error::Malformed);
            }
        }
        if parent
            .get("msg_id")
            .is_some_and(|value| !value.as_str().is_some_and(|value| text(value, 256)))
        {
            return Err(Error::Malformed);
        }
        let buffers = frames[delimiter + 6..]
            .iter()
            .map(|frame| frame.as_ref().to_vec())
            .collect();
        Ok(Message {
            header,
            parent,
            metadata,
            content,
            buffers,
        })
    }
}

fn text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}
fn signature_bytes(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() != 64 {
        return Err(Error::Authentication);
    }
    let mut signature = [0; 32];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        signature[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Ok(signature)
}
fn hex(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Error::Authentication),
    }
}
