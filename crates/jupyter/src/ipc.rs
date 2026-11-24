//! Single-peer ZMTP 3.0/NULL over generated Unix paths, with no reconnect or resend.
//! NULL is framing, not authentication. The caller also uses the Jupyter HMAC codec.
use std::{collections::BTreeMap, io, path::Path};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use tokio_util::codec::{Decoder, Encoder, Framed};
use uuid::Uuid;

use crate::{MAX_FRAMES, MAX_JSON_BYTES, MAX_MESSAGE_BYTES};

const COMMAND_LIMIT: usize = 16 * 1024;

#[derive(Clone, Copy)]
pub enum Role {
    Dealer,
    Subscriber,
}

/// One connection, bounded by the decoder rather than a background receive queue.
/// `receive` can be cancelled and resumed. A cancelled/failed send poisons writes;
/// callers must collect the context rather than guessing whether delivery occurred.
pub struct Socket {
    framed: Framed<UnixStream, Frames>,
    writable: bool,
}

impl Socket {
    /// The path must be generated beneath a caller-owned private kernel directory.
    /// The deadline for the entire handshake is the caller's responsibility.
    pub async fn connect(path: &Path, role: Role, kernel_uid: u32) -> io::Result<Self> {
        let mut stream = UnixStream::connect(path).await?;
        if stream.peer_cred()?.uid() != kernel_uid {
            return Err(invalid("kernel IPC peer has an unexpected UID"));
        }
        let mut greeting = [0u8; 64];
        greeting[0] = 0xff;
        greeting[9] = 0x7f;
        greeting[10] = 3;
        greeting[12..16].copy_from_slice(b"NULL");
        stream.write_all(&greeting).await?;
        stream.read_exact(&mut greeting).await?;
        // Signature padding and filler are intentionally not interpreted.
        if greeting[0] != 0xff
            || greeting[9] != 0x7f
            || greeting[10] < 3
            || &greeting[12..16] != b"NULL"
            || greeting[16..32].iter().any(|byte| *byte != 0)
            || greeting[32] > 1
        {
            return Err(invalid("unsupported kernel IPC greeting"));
        }
        let mut framed = Framed::new(stream, Frames::default());
        let mut ready = BytesMut::from(&b"\x05READY"[..]);
        let own_type = match role {
            Role::Dealer => "DEALER",
            Role::Subscriber => "SUB",
        };
        property(&mut ready, b"Socket-Type", own_type.as_bytes());
        property(&mut ready, b"Identity", Uuid::new_v4().as_bytes());
        framed.send(Packet::Command(ready.freeze())).await?;
        let peer = match framed.next().await.transpose()? {
            Some(Packet::Command(value)) => metadata(&value)?,
            _ => return Err(invalid("kernel IPC READY was not observed")),
        };
        let compatible = match role {
            Role::Dealer => peer
                .get("socket-type")
                .is_some_and(|value| value == b"ROUTER"),
            Role::Subscriber => peer
                .get("socket-type")
                .is_some_and(|value| value == b"PUB" || value == b"XPUB"),
        };
        if !compatible {
            return Err(invalid("kernel IPC peer has an incompatible socket type"));
        }
        if matches!(role, Role::Subscriber) {
            // Advertised ZMTP 3.0 uses a one-byte subscription message, not the
            // ZMTP 3.1 SUBSCRIBE command. Empty topic subscribes to all output.
            framed
                .send(Packet::Data(vec![Bytes::from_static(b"\x01")]))
                .await?;
        }
        Ok(Self {
            framed,
            writable: true,
        })
    }

    pub async fn send(&mut self, frames: Vec<Vec<u8>>) -> io::Result<()> {
        if !self.writable {
            return Err(invalid("kernel IPC delivery is unknown; writes are closed"));
        }
        self.writable = false;
        self.framed
            .send(Packet::Data(frames.into_iter().map(Bytes::from).collect()))
            .await?;
        self.writable = true;
        Ok(())
    }

    pub async fn receive(&mut self) -> io::Result<Vec<Bytes>> {
        match self.framed.next().await.transpose()? {
            Some(Packet::Data(frames)) => Ok(frames),
            Some(Packet::Command(_)) => Err(invalid("unexpected kernel IPC command")),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "kernel IPC ended",
            )),
        }
    }
}

fn property(output: &mut BytesMut, name: &[u8], value: &[u8]) {
    output.put_u8(name.len() as u8);
    output.extend_from_slice(name);
    output.put_u32(value.len() as u32);
    output.extend_from_slice(value);
}

fn metadata(mut input: &[u8]) -> io::Result<BTreeMap<String, Vec<u8>>> {
    if !input.starts_with(b"\x05READY") {
        return Err(invalid("kernel IPC handshake is not READY"));
    }
    input.advance(6);
    let mut properties = BTreeMap::new();
    while !input.is_empty() {
        let length = input.get_u8() as usize;
        if length == 0 || input.len() < length + 4 {
            return Err(invalid("truncated kernel IPC property"));
        }
        let name = std::str::from_utf8(&input[..length])
            .map_err(|_| invalid("invalid kernel IPC property name"))?
            .to_ascii_lowercase();
        input.advance(length);
        let length = input.get_u32() as usize;
        if input.len() < length || properties.len() >= 32 {
            return Err(invalid("invalid kernel IPC property size"));
        }
        if properties.insert(name, input[..length].to_vec()).is_some() {
            return Err(invalid("duplicate kernel IPC property"));
        }
        input.advance(length);
    }
    Ok(properties)
}

enum Packet {
    Command(Bytes),
    Data(Vec<Bytes>),
}

#[derive(Default)]
struct Frames {
    parts: Vec<Bytes>,
    bytes: usize,
}

impl Decoder for Frames {
    type Item = Packet;
    type Error = io::Error;

    fn decode(&mut self, input: &mut BytesMut) -> io::Result<Option<Packet>> {
        loop {
            if input.len() < 2 {
                return Ok(None);
            }
            let flags = input[0];
            if !matches!(flags, 0..=4 | 6) {
                return Err(invalid("invalid kernel IPC flags"));
            }
            let header = if flags & 2 != 0 { 9 } else { 2 };
            if input.len() < header {
                return Ok(None);
            }
            let length = if header == 9 {
                u64::from_be_bytes(input[1..9].try_into().expect("checked length"))
            } else {
                u64::from(input[1])
            };
            let command = flags & 4 != 0;
            let limit = if command {
                COMMAND_LIMIT
            } else {
                MAX_JSON_BYTES
            };
            // Reject declared length before reserving or allocating any body.
            if length > limit as u64
                || self.parts.len() >= MAX_FRAMES
                || self.bytes.saturating_add(length as usize) > MAX_MESSAGE_BYTES
            {
                return Err(invalid("kernel IPC message exceeds receive limits"));
            }
            let length = length as usize;
            if input.len() < header + length {
                input.reserve(header + length - input.len());
                return Ok(None);
            }
            input.advance(header);
            let part = input.split_to(length).freeze();
            if command {
                if !self.parts.is_empty() {
                    return Err(invalid(
                        "kernel IPC command interrupted a multipart message",
                    ));
                }
                return Ok(Some(Packet::Command(part)));
            }
            self.bytes += length;
            self.parts.push(part);
            if flags & 1 == 0 {
                self.bytes = 0;
                return Ok(Some(Packet::Data(std::mem::take(&mut self.parts))));
            }
        }
    }

    fn decode_eof(&mut self, input: &mut BytesMut) -> io::Result<Option<Packet>> {
        let packet = self.decode(input)?;
        if packet.is_none() && (!input.is_empty() || !self.parts.is_empty()) {
            return Err(invalid("kernel IPC ended within a message"));
        }
        Ok(packet)
    }
}

impl Encoder<Packet> for Frames {
    type Error = io::Error;

    fn encode(&mut self, packet: Packet, output: &mut BytesMut) -> io::Result<()> {
        let (command, parts) = match packet {
            Packet::Command(bytes) => (true, vec![bytes]),
            Packet::Data(parts) => (false, parts),
        };
        if parts.is_empty()
            || parts.len() > MAX_FRAMES
            || parts.iter().map(Bytes::len).sum::<usize>() > MAX_MESSAGE_BYTES
            || parts.iter().any(|part| {
                part.len()
                    > if command {
                        COMMAND_LIMIT
                    } else {
                        MAX_JSON_BYTES
                    }
            })
        {
            return Err(invalid("kernel IPC request exceeds send limits"));
        }
        for (index, part) in parts.iter().enumerate() {
            let flags = if command {
                4
            } else {
                u8::from(index + 1 < parts.len())
            };
            if part.len() > 255 {
                output.put_u8(flags | 2);
                output.put_u64(part.len() as u64);
            } else {
                output.put_u8(flags);
                output.put_u8(part.len() as u8);
            }
            output.extend_from_slice(part);
        }
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn refuses_declared_lengths_and_unfinished_multipart_before_body_allocation() {
        let mut decoder = Frames::default();
        let mut input = BytesMut::from(&b"\x02\xff\xff\xff\xff\xff\xff\xff\xff"[..]);
        let capacity = input.capacity();
        assert!(decoder.decode(&mut input).is_err());
        assert_eq!(input.capacity(), capacity);
        for _ in 0..MAX_FRAMES {
            let mut input = BytesMut::from(&b"\x01\x00"[..]);
            assert!(decoder.decode(&mut input).unwrap().is_none());
        }
        assert!(
            decoder
                .decode(&mut BytesMut::from(&b"\x00\x00"[..]))
                .is_err()
        );
        assert!(decoder.decode_eof(&mut BytesMut::new()).is_err());
    }

    #[tokio::test]
    async fn receive_survives_cancellation_and_refuses_truncated_eof() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let mut socket = Socket {
            framed: Framed::new(reader, Frames::default()),
            writable: true,
        };
        writer.write_all(b"\x01\x03ab").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), socket.receive())
                .await
                .is_err()
        );
        writer.write_all(b"c\x00\x01d").await.unwrap();
        let parts = socket.receive().await.unwrap();
        assert_eq!(
            parts,
            [Bytes::from_static(b"abc"), Bytes::from_static(b"d")]
        );
        writer.write_all(b"\x01\x00").await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(socket.receive().await.is_err());
    }

    #[tokio::test]
    async fn interrupted_send_cannot_be_replayed_and_wrong_peer_uid_is_refused() {
        use std::os::fd::AsRawFd;
        let (sender, _unread) = UnixStream::pair().unwrap();
        let size: libc::c_int = 4096;
        // SAFETY: the descriptor is an owned live Unix socket and size/length match.
        let result = unsafe {
            libc::setsockopt(
                sender.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        };
        assert_eq!(result, 0);
        let mut socket = Socket {
            framed: Framed::new(sender, Frames::default()),
            writable: true,
        };
        let data = vec![vec![0; MAX_JSON_BYTES]];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), socket.send(data))
                .await
                .is_err()
        );
        assert!(!socket.writable);
        assert!(
            socket
                .send(vec![b"must-not-replay".to_vec()])
                .await
                .is_err()
        );

        let private = tempfile::tempdir().unwrap();
        let path = private.path().join("peer");
        let _listener = tokio::net::UnixListener::bind(&path).unwrap();
        // SAFETY: querying the current effective UID has no preconditions.
        let other_uid = unsafe { libc::geteuid() }.wrapping_add(1);
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            Socket::connect(&path, Role::Dealer, other_uid),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        drop(_listener);
        private.close().unwrap();
    }

    #[test]
    fn rejects_duplicate_or_truncated_handshake_properties() {
        let mut ready = BytesMut::from(&b"\x05READY"[..]);
        property(&mut ready, b"Socket-Type", b"ROUTER");
        assert_eq!(metadata(&ready).unwrap()["socket-type"], b"ROUTER");
        property(&mut ready, b"socket-type", b"PUB");
        assert!(metadata(&ready).is_err());
        assert!(metadata(b"\x05READY\x0bS").is_err());
    }
}
