//! Fixed-name Docker archive envelopes. The host never extracts source or
//! converter archives. Entry bytes flow through bounded readers into storage.
use bollard::{Docker, query_parameters::DownloadFromContainerOptions};
use futures_util::StreamExt;
use goldenhoop_artifacts::{BlobStore, LargeBlobRef};
use goldenhoop_image_builder::PrepareRequest;
use std::{io, pin::Pin};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::io::StreamReader;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unexpected converter file envelope",
    )
}
fn header(bytes: [u8; 512]) -> io::Result<tar::Header> {
    let value = tar::Header::from_byte_slice(&bytes).clone();
    let calculated = bytes
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                32u32
            } else {
                u32::from(*b)
            }
        })
        .sum::<u32>();
    if value.cksum()? != calculated {
        return Err(invalid());
    }
    Ok(value)
}
fn pax(bytes: &[u8], expected: &str) -> io::Result<Option<u64>> {
    let mut rest = bytes;
    let mut size = None;
    let mut keys = std::collections::HashSet::new();
    while !rest.is_empty() {
        let space = rest.iter().position(|b| *b == b' ').ok_or_else(invalid)?;
        let length = std::str::from_utf8(&rest[..space])
            .map_err(|_| invalid())?
            .parse::<usize>()
            .map_err(|_| invalid())?;
        if length <= space + 2 || length > rest.len() || rest[length - 1] != b'\n' {
            return Err(invalid());
        }
        let pair = std::str::from_utf8(&rest[space + 1..length - 1]).map_err(|_| invalid())?;
        let (key, value) = pair.split_once('=').ok_or_else(invalid)?;
        if !keys.insert(key) || value.contains('\0') {
            return Err(invalid());
        }
        match key {
            "path" if value == expected => (),
            "size" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                size = Some(value.parse().map_err(|_| invalid())?)
            }
            "mtime" | "atime" | "ctime" if value.len() <= 128 => (),
            _ => return Err(invalid()),
        }
        rest = &rest[length..];
    }
    Ok(size)
}
pub(crate) struct FileStream {
    pub reader: Pin<Box<dyn AsyncRead + Send>>,
    pub size: u64,
}
impl FileStream {
    async fn parse(
        mut reader: Pin<Box<dyn AsyncRead + Send>>,
        expected: &str,
        maximum: u64,
    ) -> io::Result<Self> {
        let mut bytes = [0u8; 512];
        reader.read_exact(&mut bytes).await?;
        let mut entry = header(bytes)?;
        let mut extended_size = None;
        if entry.entry_type().as_byte() == b'x' {
            let size = entry.size()?;
            if size == 0 || size > 8192 {
                return Err(invalid());
            }
            let mut extension = vec![0u8; size as usize];
            reader.read_exact(&mut extension).await?;
            extended_size = pax(&extension, expected)?;
            let mut padding = vec![0u8; ((512 - size % 512) % 512) as usize];
            reader.read_exact(&mut padding).await?;
            if padding.iter().any(|b| *b != 0) {
                return Err(invalid());
            }
            reader.read_exact(&mut bytes).await?;
            entry = header(bytes)?;
        }
        let size = extended_size.unwrap_or(entry.size()?);
        if !entry.entry_type().is_file()
            || entry.path_bytes().as_ref() != expected.as_bytes()
            || size == 0
            || size > maximum
        {
            return Err(invalid());
        }
        Ok(Self { reader, size })
    }
    pub async fn open(
        docker: &Docker,
        id: &str,
        path: &str,
        expected: &str,
        maximum: u64,
    ) -> io::Result<Self> {
        let body =
            Box::pin(docker.download_from_container(
                id,
                Some(DownloadFromContainerOptions { path: path.into() }),
            ));
        let reader = StreamReader::new(
            body.map(|v| v.map_err(|_| io::Error::other("converter file download failed"))),
        );
        Self::parse(Box::pin(reader), expected, maximum).await
    }
    pub async fn finish(mut self) -> io::Result<()> {
        // Called only after exactly size bytes have been consumed. Refuse a
        // truncated archive, a second entry, or unbounded trailing data.
        let mut end = Vec::new();
        self.reader
            .as_mut()
            .take(65537)
            .read_to_end(&mut end)
            .await?;
        if end.len() > 65536
            || end.len() < ((512 - self.size % 512) % 512) as usize + 1024
            || end.iter().any(|b| *b != 0)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub async fn small(mut self) -> io::Result<Vec<u8>> {
        if self.size > 65536 {
            return Err(invalid());
        }
        let mut bytes = vec![0; self.size as usize];
        self.reader.read_exact(&mut bytes).await?;
        self.finish().await?;
        Ok(bytes)
    }
}
fn input_header(path: &str, size: u64) -> io::Result<[u8; 512]> {
    let mut header = tar::Header::new_gnu();
    header.set_path(path)?;
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(size);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mode(0o400);
    header.set_mtime(0);
    header.set_cksum();
    Ok(*header.as_bytes())
}
async fn padding(output: &mut (impl AsyncWrite + Unpin), size: u64) -> io::Result<()> {
    output
        .write_all(&[0u8; 512][..((512 - size % 512) % 512) as usize])
        .await
}
pub(crate) async fn input(
    mut output: impl AsyncWrite + Unpin,
    blobs: &BlobStore,
    archive: &LargeBlobRef,
    request: &PrepareRequest,
) -> Result<(), goldenhoop_protocol::ApiError> {
    use goldenhoop_protocol::{ApiError, ErrorCode};
    let failed = |_: io::Error| {
        ApiError::new(
            ErrorCode::BackendUnavailable,
            "private converter input transfer unconfirmed",
        )
    };
    let bytes = serde_json::to_vec(request).map_err(|_| failed(invalid()))?;
    output
        .write_all(&input_header("prepare.json", bytes.len() as u64).map_err(failed)?)
        .await
        .map_err(failed)?;
    output.write_all(&bytes).await.map_err(failed)?;
    padding(&mut output, bytes.len() as u64)
        .await
        .map_err(failed)?;
    output
        .write_all(&input_header("source.tar", archive.size_bytes).map_err(failed)?)
        .await
        .map_err(failed)?;
    blobs.download_large(archive, &mut output).await?;
    padding(&mut output, archive.size_bytes)
        .await
        .map_err(failed)?;
    output.write_all(&[0u8; 1024]).await.map_err(failed)?;
    output.shutdown().await.map_err(failed)?;
    Ok(())
}

/// Stream a descriptor-bound immutable copy in a fixed envelope. This handles
/// trusted tar headers only; no ext4 bytes are parsed by the host parent.
pub(crate) async fn rootfs_input(
    mut output: impl AsyncWrite + Unpin,
    mut disk: std::fs::File,
    request: &goldenhoop_image_builder::RootfsInspectionRequest,
) -> io::Result<()> {
    use sha2::{Digest, Sha256};
    use std::{
        io::{Seek, SeekFrom},
        os::unix::fs::MetadataExt,
    };
    request.validate()?;
    let before = disk.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.mode() & 0o7777 != 0o400
        || before.nlink() != 1
        || before.len() != request.disk.size_bytes
    {
        return Err(invalid());
    }
    disk.seek(SeekFrom::Start(0))?;
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() > 65536 {
        return Err(invalid());
    }
    output
        .write_all(&input_header("inspect-rootfs.json", bytes.len() as u64)?)
        .await?;
    output.write_all(&bytes).await?;
    padding(&mut output, bytes.len() as u64).await?;
    output
        .write_all(&input_header("rootfs.ext4", before.len())?)
        .await?;
    let mut disk = tokio::fs::File::from_std(disk);
    let mut remaining = before.len();
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 65536];
    while remaining > 0 {
        let maximum = remaining.min(buffer.len() as u64) as usize;
        let count = disk.read(&mut buffer[..maximum]).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "rootfs input shortened",
            ));
        }
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count]).await?;
        remaining -= count as u64;
    }
    let after = disk.metadata().await?;
    if disk.read(&mut buffer[..1]).await? != 0
        || format!("{:x}", hash.finalize()) != request.disk.sha256
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.len() != before.len()
        || after.uid() != before.uid()
        || after.mode() != before.mode()
        || after.nlink() != 1
        || (
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) != (
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        )
    {
        return Err(invalid());
    }
    padding(&mut output, before.len()).await?;
    output.write_all(&[0u8; 1024]).await?;
    output.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn file_envelopes_refuse_wrong_names_links_checksums_truncation_and_extra_entries() {
        let mut bytes = Vec::from(input_header("rootfs.ext4", 3).unwrap());
        bytes.extend_from_slice(b"abc");
        bytes.resize(2048, 0);
        assert_eq!(
            FileStream::parse(
                Box::pin(std::io::Cursor::new(bytes.clone())),
                "rootfs.ext4",
                3
            )
            .await
            .unwrap()
            .small()
            .await
            .unwrap(),
            b"abc"
        );
        assert!(
            FileStream::parse(Box::pin(std::io::Cursor::new(bytes.clone())), "foreign", 3)
                .await
                .is_err()
        );
        let mut corrupt = bytes.clone();
        corrupt[1] ^= 1;
        assert!(
            FileStream::parse(Box::pin(std::io::Cursor::new(corrupt)), "rootfs.ext4", 3)
                .await
                .is_err()
        );
        let mut truncated = bytes.clone();
        truncated.truncate(1024);
        assert!(
            FileStream::parse(Box::pin(std::io::Cursor::new(truncated)), "rootfs.ext4", 3)
                .await
                .unwrap()
                .small()
                .await
                .is_err()
        );
        let mut extra = bytes.clone();
        extra[1024] = b'x';
        assert!(
            FileStream::parse(Box::pin(std::io::Cursor::new(extra)), "rootfs.ext4", 3)
                .await
                .unwrap()
                .small()
                .await
                .is_err()
        );
        let mut link = tar::Header::new_gnu();
        link.set_path("rootfs.ext4").unwrap();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        link.set_link_name("outside").unwrap();
        link.set_cksum();
        assert!(
            FileStream::parse(
                Box::pin(std::io::Cursor::new(link.as_bytes().to_vec())),
                "rootfs.ext4",
                3
            )
            .await
            .is_err()
        );
        assert!(pax(b"20 path=../outside\n", "rootfs.ext4").is_err());
        assert!(pax(b"19 GNU.sparse=1.0\n", "rootfs.ext4").is_err());
    }
}
