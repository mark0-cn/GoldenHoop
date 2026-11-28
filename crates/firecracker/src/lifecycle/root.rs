//! A VM root remains owned during partial collection, even after its marker is gone.
use super::recovery::{PathIdentity, absent};
use super::*;
use std::{
    ffi::{CString, OsStr},
    os::unix::ffi::OsStrExt,
    time::UNIX_EPOCH,
};

const ATTRIBUTE: &std::ffi::CStr = c"user.goldenhoop.vmroot.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    format: u32,
    pub generation: Uuid,
    path: PathBuf,
    parent: PathIdentity,
    inode: PathIdentity,
    birth_seconds: u64,
    birth_nanoseconds: u32,
    nonce: Uuid,
    pid_namespace_device: u64,
    pid_namespace_inode: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cgroup_namespace: Option<(u64, u64)>,
    pub producer: ProcessIdentity,
}

pub(crate) struct Root {
    path: PathBuf,
    parent: File,
    directory: File,
    receipt: Receipt,
}

/// A historical directory identity whose original producer and path are now
/// positively absent in the same observer context. Construction stays here.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CollectedDirectory {
    receipt: Receipt,
    parent_birth: (u64, u32),
}
impl Receipt {
    pub(crate) fn binding_matches(
        &self,
        path: &Path,
        generation: Uuid,
        producer: &ProcessIdentity,
    ) -> bool {
        self.format == 1
            && self.path == path
            && self.generation == generation
            && !generation.is_nil()
            && !self.nonce.is_nil()
            && self.producer == *producer
            && producer.uid == 0
            && self.inode.device_inode().1 != 0
            && self.parent.device_inode().1 != 0
            && self.birth_nanoseconds < 1_000_000_000
            && self.pid_namespace_inode != 0
            && self.cgroup_namespace.is_some_and(|(_, inode)| inode != 0)
    }
    pub(crate) fn confirm_collected(
        &self,
        path: &Path,
        generation: Uuid,
        producer: &ProcessIdentity,
    ) -> Result<CollectedDirectory> {
        if self.format != 1
            || self.nonce.is_nil()
            || self.generation != generation
            || self.path != path
            || self.producer != *producer
            || self.inode.device_inode().1 == 0
            || self.cgroup_namespace.is_none()
        {
            return Err(invalid("collected root receipt ownership differs").into());
        }
        let parent = parent(path)?;
        let proof = CollectedDirectory {
            receipt: self.clone(),
            parent_birth: birth(&parent.metadata()?)?,
        };
        proof.verify()?;
        Ok(proof)
    }
}
impl CollectedDirectory {
    pub(crate) fn context_matches(&self, boot: &str, device: u64, inode: u64) -> bool {
        self.receipt.producer.boot_id == boot
            && self.receipt.pid_namespace_device == device
            && self.receipt.pid_namespace_inode == inode
            && inode != 0
    }
    pub(crate) fn binding_matches(
        &self,
        path: &Path,
        generation: Uuid,
        producer: &ProcessIdentity,
    ) -> bool {
        let r = &self.receipt;
        r.format == 1
            && !r.nonce.is_nil()
            && r.generation == generation
            && !generation.is_nil()
            && r.path == path
            && r.producer == *producer
            && producer.uid == 0
            && r.inode.device_inode().1 != 0
            && r.parent.device_inode().1 != 0
            && r.birth_nanoseconds < 1_000_000_000
            && self.parent_birth.1 < 1_000_000_000
            && r.pid_namespace_inode != 0
            && r.cgroup_namespace.is_some_and(|(_, inode)| inode != 0)
    }
    pub(crate) fn verify(&self) -> Result<()> {
        let expected = &self.receipt;
        let namespace = File::open("/proc/self/ns/pid")?.metadata()?;
        let cgroup = File::open("/proc/self/ns/cgroup")?.metadata()?;
        let parent = parent(&expected.path)?;
        if expected.producer.boot_id != boot_id()?
            || namespace.dev() != expected.pid_namespace_device
            || namespace.ino() != expected.pid_namespace_inode
            || expected.cgroup_namespace != Some((cgroup.dev(), cgroup.ino()))
            || !expected.parent.matches(&parent.metadata()?)
            || birth(&parent.metadata()?)? != self.parent_birth
            || !super::reaper::process_absent(&expected.producer)?
            || !absent(&expected.path)?
        {
            return Err(
                invalid("collected root producer/context/parent/path is unconfirmed").into(),
            );
        }
        Ok(())
    }
    pub(crate) fn matches(
        &self,
        path: &Path,
        generation: Uuid,
        parent: (u64, u64, u64, u32),
        inode: (u64, u64, u64, u32),
    ) -> bool {
        let r = &self.receipt;
        let (parent_device, parent_inode) = r.parent.device_inode();
        let (device, number) = r.inode.device_inode();
        r.format == 1
            && !r.nonce.is_nil()
            && r.cgroup_namespace.is_some()
            && r.path == path
            && r.generation == generation
            && parent
                == (
                    parent_device,
                    parent_inode,
                    self.parent_birth.0,
                    self.parent_birth.1,
                )
            && inode == (device, number, r.birth_seconds, r.birth_nanoseconds)
    }
}

fn birth(metadata: &std::fs::Metadata) -> Result<(u64, u32)> {
    // A device/inode number alone can be reused after all previous handles die.
    // Require stable kernel creation evidence; unsupported stores fail closed.
    let value = metadata.created()?.duration_since(UNIX_EPOCH)?;
    Ok((value.as_secs(), value.subsec_nanos()))
}

fn child(directory: &File, name: &OsStr, flags: i32) -> Result<File> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(invalid("invalid VM root entry name").into());
    }
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: 0x0f,
    }; // NO_XDEV, NO_MAGICLINKS, NO_SYMLINKS, BENEATH
    let name = CString::new(bytes)?;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory.as_raw_fd(),
            name.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

fn unlink(directory: &File, name: &OsStr, is_directory: bool) -> Result<()> {
    let name = CString::new(name.as_bytes())?;
    if unsafe {
        libc::unlinkat(
            directory.as_raw_fd(),
            name.as_ptr(),
            if is_directory { libc::AT_REMOVEDIR } else { 0 },
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn parent(path: &Path) -> Result<File> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("VM root has no parent"))?;
    if !path.is_absolute() || std::fs::canonicalize(parent)? != parent {
        return Err(invalid("VM root parent is not canonical and absolute").into());
    }
    for directory in parent.ancestors() {
        let value = std::fs::symlink_metadata(directory)?;
        if !value.is_dir() || value.uid() != 0 || value.mode() & 0o022 != 0 {
            return Err(invalid("VM root ancestor is not trusted").into());
        }
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut fs) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if ![0xef53, 0x58465342, 0x9123683e, 0x794c7630, 0x01021994].contains(&(fs.f_type as u64)) {
        return Err(invalid("VM root store is not a supported local filesystem").into());
    }
    Ok(directory)
}

fn read_receipt(file: &File) -> Result<Receipt> {
    let length = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            ATTRIBUTE.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if length == 0 || length > 16384 {
        return Err(invalid("VM root receipt length invalid").into());
    }
    let mut bytes = vec![0; length as usize];
    let read = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            ATTRIBUTE.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if read != length {
        return Err(invalid("VM root receipt changed while reading").into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

impl Root {
    pub(crate) fn create(path: &Path, generation: Uuid) -> Result<Self> {
        let parent = parent(path)?;
        let name = path
            .file_name()
            .ok_or_else(|| invalid("VM root name absent"))?;
        let cname = CString::new(name.as_bytes())?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), cname.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let directory =
            child(&parent, name, libc::O_RDONLY | libc::O_DIRECTORY).map_err(|error| {
                invalid(format!(
                    "created VM root descriptor unavailable; collection unconfirmed: {error}"
                ))
            })?;
        let created = (|| -> Result<Receipt> {
            let metadata = directory.metadata()?;
            if metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 || generation.is_nil() {
                return Err(invalid("created VM root owner/mode/generation invalid").into());
            }
            let (birth_seconds, birth_nanoseconds) = birth(&metadata)?;
            let namespace = File::open("/proc/self/ns/pid")?.metadata()?;
            let receipt = Receipt {
                format: 1,
                generation,
                path: path.to_owned(),
                parent: PathIdentity::capture(path.parent().unwrap(), false)?,
                inode: PathIdentity::capture(path, false)?,
                birth_seconds,
                birth_nanoseconds,
                nonce: Uuid::new_v4(),
                pid_namespace_device: namespace.dev(),
                pid_namespace_inode: namespace.ino(),
                cgroup_namespace: Some({
                    let value = File::open("/proc/self/ns/cgroup")?.metadata()?;
                    (value.dev(), value.ino())
                }),
                producer: process_identity(std::process::id())?,
            };
            if !receipt.inode.matches(&metadata) || !receipt.parent.matches(&parent.metadata()?) {
                return Err(invalid("created VM root object changed").into());
            }
            let bytes = serde_json::to_vec(&receipt)?;
            if unsafe {
                libc::fsetxattr(
                    directory.as_raw_fd(),
                    ATTRIBUTE.as_ptr(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::XATTR_CREATE,
                )
            } != 0
            {
                return Err(io::Error::last_os_error().into());
            }
            directory.sync_all()?;
            parent.sync_all()?;
            Ok(receipt)
        })();
        let receipt = match created {
            Ok(receipt) => receipt,
            Err(error) => {
                // No descendant effect is allowed before this complete receipt.
                // Roll back only the exact still-empty directory created above.
                let rollback = (|| -> Result<()> {
                    let actual =
                        child(&parent, name, libc::O_RDONLY | libc::O_DIRECTORY)?.metadata()?;
                    let original = directory.metadata()?;
                    if actual.dev() != original.dev() || actual.ino() != original.ino() {
                        return Err(invalid("unacknowledged root was replaced").into());
                    }
                    unlink(&parent, name, true)?;
                    parent.sync_all()?;
                    if !absent(path)? {
                        return Err(invalid("unacknowledged root remains").into());
                    }
                    Ok(())
                })();
                return Err(match rollback {
                    Ok(()) => error,
                    Err(collection) => invalid(format!(
                        "{error}; root collection unconfirmed: {collection}"
                    ))
                    .into(),
                });
            }
        };
        let root = Self {
            path: path.to_owned(),
            parent,
            directory,
            receipt,
        };
        root.verify()?;
        Ok(root)
    }

    pub(crate) fn recorded(
        path: &Path,
        receipt: Option<&Receipt>,
        generation: Uuid,
        producer: Option<&ProcessIdentity>,
    ) -> Result<Option<Self>> {
        if absent(path)? {
            return Ok(None);
        }
        let receipt = receipt.ok_or_else(|| invalid("VM root inode receipt unrecorded"))?;
        if receipt.format != 1
            || receipt.path != path
            || receipt.generation != generation
            || receipt.nonce.is_nil()
            || receipt.producer.uid != 0
            || receipt.producer.boot_id != boot_id()?
            || producer != Some(&receipt.producer)
        {
            return Err(invalid("VM root receipt context differs").into());
        }
        let parent = parent(path)?;
        let directory = child(
            &parent,
            path.file_name()
                .ok_or_else(|| invalid("VM root name absent"))?,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let root = Self {
            path: path.to_owned(),
            parent,
            directory,
            receipt: receipt.clone(),
        };
        root.verify()?;
        Ok(Some(root))
    }

    pub(crate) fn receipt(&self) -> Receipt {
        self.receipt.clone()
    }

    pub(crate) fn verify(&self) -> Result<()> {
        let namespace = File::open("/proc/self/ns/pid")?.metadata()?;
        let cgroup = File::open("/proc/self/ns/cgroup")?.metadata()?;
        if self.receipt.producer.boot_id != boot_id()?
            || namespace.dev() != self.receipt.pid_namespace_device
            || namespace.ino() != self.receipt.pid_namespace_inode
            || self
                .receipt
                .cgroup_namespace
                .is_some_and(|expected| expected != (cgroup.dev(), cgroup.ino()))
        {
            return Err(invalid("VM root boot/PID namespace differs").into());
        }
        let path_parent = self
            .path
            .parent()
            .ok_or_else(|| invalid("VM root parent absent"))?;
        if !PathIdentity::verify(path_parent, Some(&self.receipt.parent), false)?
            || !self.receipt.parent.matches(&self.parent.metadata()?)
        {
            return Err(invalid("VM root parent changed").into());
        }
        let current = child(
            &self.parent,
            self.path
                .file_name()
                .ok_or_else(|| invalid("VM root name absent"))?,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        for file in [&self.directory, &current] {
            let value = file.metadata()?;
            if !self.receipt.inode.matches(&value)
                || value.uid() != 0
                || value.mode() & 0o777 != 0o700
                || birth(&value)? != (self.receipt.birth_seconds, self.receipt.birth_nanoseconds)
                || read_receipt(file)? != self.receipt
            {
                return Err(invalid("VM root actual inode/birth/receipt differs").into());
            }
        }
        Ok(())
    }

    pub(crate) fn fence_producer(&self) -> Result<()> {
        let expected = &self.receipt.producer;
        if expected.pid == std::process::id() && process_identity(expected.pid)? == *expected {
            return Ok(());
        }
        if !super::reaper::process_absent(expected)? {
            return Err(invalid("original VM root producer is not collected").into());
        }
        Ok(())
    }

    pub(crate) fn marker(&self) -> Result<Option<serde_json::Value>> {
        self.verify()?;
        let file = match child(
            &self.directory,
            OsStr::new("intent.json"),
            libc::O_RDONLY | libc::O_NONBLOCK,
        ) {
            Ok(file) => file,
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > 65536
        {
            return Err(invalid("VM root marker type/ownership/size invalid").into());
        }
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(invalid("VM root marker exceeds limit").into());
        }
        self.verify()?;
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    fn contents(&self, directory: &File, depth: u32, budget: &mut usize) -> Result<()> {
        if depth > 64 {
            return Err(invalid("VM root collection depth exceeded").into());
        }
        let cap = cap_std::fs::Dir::from_std_file(directory.try_clone()?);
        let mut names = cap
            .entries()?
            .map(|e| e.map(|v| v.file_name()))
            .collect::<io::Result<Vec<_>>>()?;
        // Collection no longer depends on keeping the marker until last.
        names.sort_by_key(|name| (name != OsStr::new("intent.json"), name.clone()));
        for name in names {
            if *budget == 0 {
                return Err(invalid("VM root collection entry limit exceeded").into());
            }
            *budget -= 1;
            self.verify()?;
            let node = child(directory, &name, libc::O_PATH)?;
            let metadata = node.metadata()?;
            if metadata.is_dir() {
                let sub = child(directory, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                if !same(&metadata, &sub.metadata()?) {
                    return Err(invalid("VM root descendant changed").into());
                }
                self.contents(&sub, depth + 1, budget)?;
            }
            self.verify()?;
            if !same(
                &metadata,
                &child(directory, &name, libc::O_PATH)?.metadata()?,
            ) {
                return Err(invalid("VM root entry changed before unlink").into());
            }
            unlink(directory, &name, metadata.is_dir())?;
            #[cfg(test)]
            tests::barrier(&self.path, &name);
        }
        directory.sync_all()?;
        Ok(())
    }

    pub(crate) fn remove_all(&self) -> Result<()> {
        self.verify()?;
        self.fence_producer()?;
        self.contents(&self.directory, 0, &mut 100000)?;
        self.verify()?;
        unlink(
            &self.parent,
            self.path
                .file_name()
                .ok_or_else(|| invalid("VM root name absent"))?,
            true,
        )?;
        self.parent.sync_all()?;
        if self.directory.metadata()?.nlink() != 0 || !absent(&self.path)? {
            return Err(invalid("original VM root collection unconfirmed").into());
        }
        Ok(())
    }
}

fn same(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino() && a.file_type() == b.file_type()
}

#[cfg(test)]
mod tests;
