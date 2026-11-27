//! Administrator-pinned prepared disks, independent of mutable job availability.
use super::*;
use goldenhoop_image_builder::{BuilderInventory, MAX_DISK_BYTES, PrepareRequest};
use goldenhoop_images::{PreparedImageReference, ReadyImageInfo};
use std::io::Seek;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedImagePolicy {
    pub inventory: BuilderInventory,
    pub max_disk_bytes: u64,
    pub disk_budget_bytes: u64,
    /// Administrator-provisioned, root-private tmpfs. Its actual kernel limit
    /// bounds all workers' temporary copies, independently of manager lifetime.
    pub staging_root: PathBuf,
    pub staging_bytes: u64,
    #[serde(default)]
    pub allow_runc_development: bool,
}
impl PreparedImagePolicy {
    pub fn validate(&self) -> Result<()> {
        self.inventory.validate()?;
        if !(64 * MIB..=MAX_DISK_BYTES).contains(&self.max_disk_bytes)
            || !self.max_disk_bytes.is_multiple_of(4096)
            || self.disk_budget_bytes < self.max_disk_bytes
            || self.staging_bytes < self.max_disk_bytes
            || self.staging_bytes > 4 * MAX_DISK_BYTES
            || !self.staging_bytes.is_multiple_of(MIB)
            || !self.staging_root.is_absolute()
            || self.staging_root.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(invalid("invalid prepared image policy or disk/staging budget").into());
        }
        Ok(())
    }
    pub fn validate_info(&self, info: &ReadyImageInfo) -> Result<()> {
        self.validate()?;
        info.reference.validate()?;
        let manifest = &info.manifest;
        manifest.validate_for(
            &PrepareRequest {
                generation: info.reference.generation,
                archive: manifest.archive.clone(),
                agent: manifest.agent.clone(),
                init: manifest.init.clone(),
                disk_bytes: manifest.disk.size_bytes,
            },
            &self.inventory,
        )?;
        if info.reference != PreparedImageReference::for_manifest(info.reference.id, manifest)?
            || manifest.disk.size_bytes > self.max_disk_bytes
        {
            return Err(invalid("prepared image reference, policy or disk bound differs").into());
        }
        Ok(())
    }

    pub fn staging_directory(&self) -> Result<File> {
        self.validate()?;
        if unsafe { libc::geteuid() } != 0 {
            return Err(invalid("prepared image staging requires root").into());
        }
        let mut ancestor = Some(self.staging_root.as_path());
        while let Some(path) = ancestor {
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || (path == self.staging_root && metadata.mode() & 0o7777 != 0o700)
            {
                return Err(invalid("prepared staging ancestry is not trusted").into());
            }
            ancestor = path.parent();
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&self.staging_root)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err(invalid("prepared staging ownership differs").into());
        }
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let stat = unsafe { stat.assume_init() };
        let bytes = u64::try_from(stat.f_bsize)?
            .checked_mul(stat.f_blocks)
            .ok_or_else(|| invalid("prepared staging capacity overflow"))?;
        if stat.f_type != libc::TMPFS_MAGIC
            || bytes > self.staging_bytes
            || bytes < self.max_disk_bytes
        {
            return Err(invalid("prepared staging requires an actually bounded tmpfs").into());
        }
        Ok(directory)
    }
    pub(super) fn validate_input(&self, info: &ReadyImageInfo, file: &File) -> Result<()> {
        self.validate_info(info)?;
        let staging = self.staging_directory()?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 0
            || metadata.dev() != staging.metadata()?.dev()
            || metadata.len() != info.manifest.disk.size_bytes
        {
            return Err(invalid("prepared input is not the private bounded staging file").into());
        }
        let mut source = file.try_clone()?;
        source.rewind()?;
        if crate::fileio::digest(source.try_clone()?)?
            != (
                info.manifest.disk.sha256.clone(),
                info.manifest.disk.size_bytes,
            )
        {
            return Err(invalid("prepared input bytes differ from the immutable manifest").into());
        }
        source.rewind()?;
        Ok(())
    }
}

impl DriverConfig {
    pub(super) fn selected_artifacts(
        &self,
        generation: Uuid,
        info: &ReadyImageInfo,
    ) -> Result<BootInput> {
        self.prepared_images
            .as_ref()
            .ok_or_else(|| invalid("prepared images are not configured"))?
            .validate_info(info)?;
        let mut artifacts = self.artifacts.clone();
        artifacts.rootfs = Artifact {
            path: self.paths(generation)?.jail.join("rootfs.ext4"),
            sha256: info.manifest.disk.sha256.clone(),
            size: info.manifest.disk.size_bytes,
        };
        Ok(artifacts)
    }
    pub(super) fn validate_journal_image(&self, record: &VmJournal) -> Result<()> {
        let expected = match &record.selected_image {
            Some(info) => self.selected_artifacts(record.owner.generation, info)?,
            None => self.artifacts.clone(),
        };
        if record.artifacts != expected || record.supervisor_artifact != self.supervisor {
            return Err(invalid("native generation image or executable artifacts differ").into());
        }
        Ok(())
    }
}

pub(super) struct Input {
    pub info: ReadyImageInfo,
    pub file: File,
}

/// Only the dedicated supervisor's private CLI calls this. Duplicate the
/// explicitly inherited input into a CLOEXEC-owned descriptor and close the
/// original so it cannot escape through a later VMM exec.
pub fn inherited_input(descriptor: u32) -> Result<File> {
    if !(3..=i32::MAX as u32).contains(&descriptor) {
        return Err(invalid("invalid inherited image descriptor").into());
    }
    let fd = unsafe { libc::fcntl(descriptor as i32, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::close(descriptor as i32) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(file)
}

#[cfg(test)]
mod tests;
