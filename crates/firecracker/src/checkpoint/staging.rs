//! Independently copied unnamed content. Durable publication and producer/GC
//! fences belong to the capture coordinator, not to these read-only descriptors.
use super::*;
use std::{
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path},
};

pub struct CheckpointFiles {
    pub state: File,
    pub memory: File,
    pub disk: File,
}

pub struct StagedCheckpoint {
    manifest: CheckpointManifest,
    files: CheckpointFiles,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    size: u64,
    links: u64,
    owner: u32,
    mode: u32,
    changed: (i64, i64),
    modified: (i64, i64),
}

fn stamp(file: &File, expected_uid: u32) -> io::Result<Stamp> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o6022 != 0
        || metadata.nlink() > 1
    {
        return Err(invalid(
            "checkpoint input type, owner, mode or link count differs",
        ));
    }
    Ok(Stamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        links: metadata.nlink(),
        owner: metadata.uid(),
        mode: metadata.mode(),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
    })
}

fn staging_directory(path: &Path) -> io::Result<File> {
    if unsafe { libc::geteuid() } != 0
        || !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
        || std::fs::canonicalize(path)? != path
    {
        return Err(invalid(
            "checkpoint staging requires a canonical root-owned directory",
        ));
    }
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(invalid(
                "checkpoint staging ancestry is writable or untrusted",
            ));
        }
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
        return Err(invalid("checkpoint staging directory is not private"));
    }
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut filesystem) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // Host disk staging only. No named fallback, remote-lock assumption or tmpfs
    // substitution for the potentially large memory+drive reservation.
    if ![0xef53, 0x58465342, 0x9123683e, 0x794c7630].contains(&i128::from(filesystem.f_type)) {
        return Err(invalid(
            "checkpoint staging requires supported local disk storage",
        ));
    }
    Ok(directory)
}

fn anonymous(directory: &File) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 0
        || metadata.len() != 0
        || metadata.dev() != directory.metadata()?.dev()
    {
        return Err(invalid("checkpoint unnamed output ownership differs"));
    }
    Ok(file)
}

fn read_only(file: File) -> io::Result<File> {
    file.set_permissions(std::fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    // Reopen only our own live descriptor, never an input-supplied proc path.
    // The new descriptor has its own offset and no write access. Dropping the
    // original removes the sole writable descriptor created by this module.
    let result = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    let observed = result.metadata()?;
    if (metadata.dev(), metadata.ino()) != (observed.dev(), observed.ino())
        || observed.nlink() != 0
        || observed.mode() & 0o7777 != 0o400
        || observed.len() != metadata.len()
    {
        return Err(invalid("checkpoint read-only output identity differs"));
    }
    Ok(result)
}

impl StagedCheckpoint {
    /// The caller supplies a trusted immutable reference, exact runtime policy,
    /// authenticated input descriptors and an already reserved logical byte
    /// budget. This verifies content, not that any VMM is paused or absent.
    /// No source pathname, producer liveness or same-boot receipt is required.
    pub fn materialize(
        manifest: CheckpointManifest,
        reference: &CheckpointReference,
        expected_runtime: &CheckpointRuntime,
        reserved_bytes: u64,
        inputs: CheckpointFiles,
        input_uid: u32,
        staging_root: &Path,
    ) -> io::Result<Self> {
        manifest
            .admit(reference, expected_runtime, reserved_bytes)
            .map_err(invalid)?;
        let directory = staging_directory(staging_root)?;
        let sources = [inputs.state, inputs.memory, inputs.disk];
        let before = sources
            .iter()
            .map(|f| stamp(f, input_uid))
            .collect::<io::Result<Vec<_>>>()?;
        if before.iter().enumerate().any(|(i, a)| {
            before[..i]
                .iter()
                .any(|b| (a.device, a.inode) == (b.device, b.inode))
        }) {
            return Err(invalid("checkpoint roles alias the same source inode"));
        }
        let mut outputs = Vec::with_capacity(3);
        for (input, content) in
            sources
                .iter()
                .zip([&manifest.state, &manifest.memory, &manifest.disk])
        {
            let file = crate::fileio::copy_to(
                input.try_clone()?,
                anonymous(&directory)?,
                &content.sha256,
                content.size_bytes,
            )?;
            outputs.push(read_only(file)?);
        }
        for (input, observed) in sources.iter().zip(before) {
            if stamp(input, input_uid)? != observed {
                return Err(invalid("checkpoint input changed during materialization"));
            }
        }
        let [state, memory, disk]: [File; 3] = outputs
            .try_into()
            .map_err(|_| invalid("checkpoint output count differs"))?;
        Ok(Self {
            manifest,
            files: CheckpointFiles {
                state,
                memory,
                disk,
            },
        })
    }

    pub fn manifest(&self) -> &CheckpointManifest {
        &self.manifest
    }
    pub fn files(&self) -> &CheckpointFiles {
        &self.files
    }
    pub fn into_parts(self) -> (CheckpointManifest, CheckpointFiles) {
        (self.manifest, self.files)
    }
}

#[cfg(test)]
mod tests;
