//! A Ready job can be consumed only while its permanent producer/collector
//! lock is held. The output is an anonymous, verified host file, never a public
//! filesystem path. It remains independent of source-blob collection afterwards.
use super::*;
use crate::{PreparedImageReference, ReadyImageInfo};
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path},
};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

/// Private host handoff. This type is deliberately not serializable: neither
/// storage credentials, private blob references nor host paths are consumer API
/// fields. A future receiver must recheck the content on its own descriptor.
pub struct MaterializedImage {
    installation_id: Uuid,
    info: ReadyImageInfo,
    file: File,
}
impl MaterializedImage {
    pub fn installation_id(&self) -> Uuid {
        self.installation_id
    }
    pub fn info(&self) -> &ReadyImageInfo {
        &self.info
    }
    pub fn file(&self) -> &File {
        &self.file
    }
    pub fn into_parts(self) -> (ReadyImageInfo, File) {
        (self.info, self.file)
    }
}

fn ready_state(
    job: &ImageJob,
    blobs: &BlobStore,
    policy: &BuilderInventory,
    allow_runc_development: bool,
) -> Result<(State, ReadyImageInfo), ApiError> {
    policy.validate().map_err(|_| conflict())?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Intent {
        format: u32,
        role: String,
        request: ImagePrepareRequest,
        storage_binding: String,
    }
    let intent: Intent = serde_json::from_value(job.request.clone()).map_err(|_| conflict())?;
    intent.request.validate()?;
    if job.installation_id != blobs.installation_id()
        || intent.format != 1
        || intent.role != ROLE
        || intent.storage_binding != blobs.binding()
        || intent.request.id != job.id
        || intent.request.generation != job.generation
    {
        return Err(conflict());
    }
    if intent.request.runtime == BuilderRuntime::RuncDevelopment && !allow_runc_development {
        return Err(ApiError::new(
            ErrorCode::UnsupportedCapability,
            "consuming a development converter image requires explicit development opt-in",
        ));
    }
    let value = state(job, &intent.request, blobs)?;
    if value.phase != Phase::Ready
        || value.error.is_some()
        || value.inventory.as_ref() != Some(policy)
    {
        return Err(conflict());
    }
    let manifest = value.manifest.clone().ok_or_else(conflict)?;
    let reference = PreparedImageReference::for_manifest(job.id, &manifest)?;
    Ok((
        value,
        ReadyImageInfo {
            reference,
            manifest,
        },
    ))
}

fn staging_error() -> ApiError {
    let mut error = ApiError::new(
        ErrorCode::BackendUnavailable,
        "private anonymous image staging or disk integrity is unconfirmed",
    );
    error.retryable = false;
    error
}

fn anonymous_file(path: &Path) -> Result<File, ApiError> {
    if unsafe { libc::geteuid() } != 0
        || !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
    {
        return Err(staging_error());
    }
    let mut ancestor = Some(path);
    while let Some(current) = ancestor {
        let meta = std::fs::symlink_metadata(current).map_err(|_| staging_error())?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != 0
            || meta.mode() & 0o022 != 0
            || (current == path && meta.mode() & 0o7777 != 0o700)
        {
            return Err(staging_error());
        }
        ancestor = current.parent();
    }
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| staging_error())?;
    let meta = parent.metadata().map_err(|_| staging_error())?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o7777 != 0o700 {
        return Err(staging_error());
    }
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: parent is live, stat is read only after successful initialization.
    if unsafe { libc::fstatfs(parent.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(staging_error());
    }
    let kind = unsafe { stat.assume_init() }.f_type;
    if ![0xef53, 0x58465342, 0x9123683e, 0x01021994, 0x794c7630].contains(&kind) {
        return Err(staging_error());
    }
    // The pinned directory descriptor, not another path lookup, selects the
    // filesystem. No named-partial-file fallback is allowed on unsupported FS.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c".".as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(staging_error());
    }
    // SAFETY: successful openat returns a new owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(|_| staging_error())?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 0
        || meta.len() != 0
        || meta.dev() != parent.metadata().map_err(|_| staging_error())?.dev()
    {
        return Err(staging_error());
    }
    Ok(file)
}

async fn download(
    blobs: &BlobStore,
    disk: &LargeBlobRef,
    staging_root: &Path,
) -> Result<File, ApiError> {
    let file = anonymous_file(staging_root)?;
    let mut file = tokio::fs::File::from_std(file);
    // download_large checks chunk bounds, chunk hashes and the whole digest.
    // Re-read this actual output descriptor as well before handing it off.
    tokio::time::timeout(Duration::from_secs(300), async {
        blobs.download_large(disk, &mut file).await?;
        file.flush().await.map_err(|_| staging_error())?;
        file.sync_all().await.map_err(|_| staging_error())?;
        file.rewind().await.map_err(|_| staging_error())?;
        let mut digest = Sha256::new();
        let mut size = 0u64;
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let length = file.read(&mut buffer).await.map_err(|_| staging_error())?;
            if length == 0 {
                break;
            }
            size = size
                .checked_add(length as u64)
                .filter(|n| *n <= disk.size_bytes)
                .ok_or_else(staging_error)?;
            digest.update(&buffer[..length]);
        }
        let meta = file.metadata().await.map_err(|_| staging_error())?;
        if size != disk.size_bytes
            || meta.len() != size
            || meta.nlink() != 0
            || meta.uid() != 0
            || meta.mode() & 0o7777 != 0o600
            || format!("{:x}", digest.finalize()) != disk.sha256
        {
            return Err(staging_error());
        }
        file.rewind().await.map_err(|_| staging_error())?;
        Ok::<_, ApiError>(())
    })
    .await
    .map_err(|_| staging_error())??;
    Ok(file.into_std().await)
}

impl ImagePreparer {
    /// Ready metadata is not a reusable assertion that the stored bytes still
    /// exist. materialize_ready revalidates readiness and the actual content.
    pub async fn inspect_ready(
        &self,
        id: Uuid,
        policy: &BuilderInventory,
    ) -> Result<ReadyImageInfo, ApiError> {
        let lease = self.coordinator.acquire_reader(id)?;
        let job = self.store.image_job(id).await?;
        let (value, info) = ready_state(&job, &self.blobs, policy, self.allow_runc_development)?;
        lease.check(value.coordination.as_ref(), true)?;
        self.absent(&job, &value).await?;
        Ok(info)
    }

    /// Holds the same permanent lock as preparation, reconciliation and
    /// collection until a complete independent copy has been verified. No VM,
    /// provider or named cache file is allocated by this operation.
    pub async fn materialize_ready(
        &self,
        reference: &PreparedImageReference,
        policy: &BuilderInventory,
        staging_root: &Path,
    ) -> Result<MaterializedImage, ApiError> {
        reference.validate()?;
        let lease = self.coordinator.acquire_reader(reference.id)?;
        let job = self.store.image_job(reference.id).await?;
        let (value, info) = ready_state(&job, &self.blobs, policy, self.allow_runc_development)?;
        if &info.reference != reference {
            return Err(conflict());
        }
        lease.check(value.coordination.as_ref(), true)?;
        self.absent(&job, &value).await?;
        let file = download(
            &self.blobs,
            value.disk.as_ref().ok_or_else(conflict)?,
            staging_root,
        )
        .await?;
        // CAS writers obey the same lease; also reject an unexpected out-of-band
        // metadata change. An error drops the anonymous file without a pathname.
        let current = self.store.image_job(job.id).await?;
        if current.revision != job.revision || current.request_sha256 != job.request_sha256 {
            return Err(conflict());
        }
        self.absent(&job, &value).await?;
        drop(lease);
        Ok(MaterializedImage {
            installation_id: job.installation_id,
            info,
            file,
        })
    }
}

#[cfg(test)]
mod tests;
