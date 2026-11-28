//! Descriptor/inode receipts for the independent rootfs store. No guest parser.
use super::*;
use std::{ffi::CString, os::fd::FromRawFd, time::UNIX_EPOCH};

const ROOT: &std::ffi::CStr = c"user.goldenhoop.rootfs.store.v1";
const OBJECT: &std::ffi::CStr = c"user.goldenhoop.rootfs.disk.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    device: u64,
    inode: u64,
    birth_seconds: u64,
    birth_nanoseconds: u32,
}
impl Identity {
    pub fn of(file: &File) -> Result<Self> {
        let metadata = file.metadata()?;
        let birth = metadata.created()?.duration_since(UNIX_EPOCH)?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            birth_seconds: birth.as_secs(),
            birth_nanoseconds: birth.subsec_nanos(),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    format: u16,
    installation: Uuid,
    store: Uuid,
    path: PathBuf,
    parent: Identity,
    directory: Identity,
    quota: Identity,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockHeader {
    format: u16,
    store: Uuid,
    #[serde(default)]
    capture: Option<Uuid>,
    #[serde(default)]
    intent_sha256: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DiskReceipt {
    format: u16,
    store: Uuid,
    capture: Uuid,
    reference: RootfsReference,
    disk_id: Uuid,
    content: RootfsArtifact,
    inode: Identity,
}
pub(super) struct Directory {
    pub path: PathBuf,
    file: File,
    binding: Binding,
}
pub(super) fn record_name(id: Uuid) -> String {
    format!("capture-{id}.json")
}
fn job_name(id: Uuid) -> String {
    format!("capture-{id}.lock")
}
fn disk_name(id: Uuid) -> String {
    format!("capture-{id}.disk")
}
fn component(name: &str) -> Result<CString> {
    if name.is_empty()
        || name.len() > 128
        || name == "."
        || name == ".."
        || name
            .bytes()
            .any(|b| b == b'/' || b == b'\\' || b.is_ascii_control())
    {
        return Err(invalid("invalid rootfs store component").into());
    }
    Ok(CString::new(name)?)
}
fn attribute<T: serde::de::DeserializeOwned>(file: &File, name: &std::ffi::CStr) -> Result<T> {
    let mut bytes = vec![0u8; 16384];
    let count = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if count == 0 || count as usize >= bytes.len() {
        return Err(invalid("rootfs receipt exceeds bound").into());
    }
    Ok(serde_json::from_slice(&bytes[..count as usize])?)
}
fn attach(file: &File, name: &std::ffi::CStr, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 16384 {
        return Err(invalid("rootfs receipt exceeds bound").into());
    }
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            bytes.as_ptr().cast(),
            bytes.len(),
            libc::XATTR_CREATE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    file.sync_all()?;
    Ok(())
}
fn parent(path: &Path) -> Result<File> {
    if unsafe { libc::geteuid() } != 0
        || !path.is_absolute()
        || path.components().any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid("rootfs store requires root and a canonical absolute path").into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("rootfs store parent missing"))?;
    if std::fs::canonicalize(parent)? != parent {
        return Err(invalid("rootfs store parent redirects").into());
    }
    for ancestor in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(invalid("rootfs store ancestry is untrusted").into());
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if ![0xef53, 0x58465342, 0x9123683e, 0x794c7630].contains(&i128::from(filesystem.f_type)) {
        return Err(invalid("rootfs store requires supported local disk storage").into());
    }
    Ok(file)
}
fn child(directory: &File, name: &str, write: bool) -> Result<Option<File>> {
    let name = component(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            (if write { libc::O_RDWR } else { libc::O_RDONLY })
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error.into());
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}
fn metadata_file(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > 65536
    {
        return Err(invalid("rootfs metadata ownership or type differs").into());
    }
    Ok(())
}
pub(super) fn lock(file: &File, exclusive: bool) -> Result<()> {
    (if exclusive {
        fs2::FileExt::try_lock_exclusive(file)
    } else {
        fs2::FileExt::try_lock_shared(file)
    })
    .map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            let mut busy = goldenhoop_protocol::ApiError::new(
                goldenhoop_protocol::ErrorCode::BackendUnavailable,
                "rootfs content is leased; inspect the original capture again",
            );
            busy.retryable = true;
            busy.into()
        } else {
            error.into()
        }
    })
}
impl Directory {
    pub fn initialize(path: &Path, installation: Uuid) -> Result<Self> {
        if installation.is_nil() {
            return Err(invalid("rootfs installation is nil").into());
        }
        let parent = parent(path)?;
        let name = component(
            path.file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| invalid("rootfs store name missing"))?,
        )?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let store = Uuid::new_v4();
        metadata::initial_json(
            &path.join("quota.lock"),
            &serde_json::json!({"format":1,"store":store}),
        )?;
        let quota = child(&file, "quota.lock", false)?
            .ok_or_else(|| invalid("rootfs quota lock absent"))?;
        metadata_file(&quota)?;
        let binding = Binding {
            format: 1,
            installation,
            store,
            path: path.to_owned(),
            parent: Identity::of(&parent)?,
            directory: Identity::of(&file)?,
            quota: Identity::of(&quota)?,
        };
        // Unacknowledged directories are quarantined, never adopted by name.
        attach(&file, ROOT, &binding)?;
        parent.sync_all()?;
        Self::open(path, installation)
    }
    pub fn open(path: &Path, installation: Uuid) -> Result<Self> {
        let parent = parent(path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let m = file.metadata()?;
        let binding: Binding = attribute(&file, ROOT)?;
        if !m.is_dir()
            || m.uid() != 0
            || m.mode() & 0o7777 != 0o700
            || binding.format != 1
            || installation.is_nil()
            || binding.installation != installation
            || binding.store.is_nil()
            || binding.path != path
            || binding.parent != Identity::of(&parent)?
            || binding.directory != Identity::of(&file)?
        {
            return Err(invalid("rootfs store persistent identity differs").into());
        }
        let root = Self {
            path: path.to_owned(),
            file,
            binding,
        };
        root.quota(false)?;
        Ok(root)
    }
    pub fn duplicate(&self) -> Result<Self> {
        self.current()?;
        Ok(Self {
            path: self.path.clone(),
            file: self.file.try_clone()?,
            binding: self.binding.clone(),
        })
    }
    pub fn current(&self) -> Result<()> {
        let parent = parent(&self.path)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)?;
        let m = file.metadata()?;
        if !m.is_dir()
            || m.uid() != 0
            || m.mode() & 0o7777 != 0o700
            || Identity::of(&parent)? != self.binding.parent
            || Identity::of(&file)? != self.binding.directory
            || attribute::<Binding>(&file, ROOT)? != self.binding
        {
            return Err(invalid("rootfs store was replaced").into());
        }
        Ok(())
    }
    pub fn store(&self) -> Uuid {
        self.binding.store
    }
    pub fn installation(&self) -> Uuid {
        self.binding.installation
    }
    pub fn quota(&self, exclusive: bool) -> Result<File> {
        let file = child(&self.file, "quota.lock", exclusive)?
            .ok_or_else(|| invalid("rootfs quota lock missing; no replacement created"))?;
        metadata_file(&file)?;
        if Identity::of(&file)? != self.binding.quota
            || self.read_json::<serde_json::Value>("quota.lock")?
                != serde_json::json!({"format":1,"store":self.store()})
        {
            return Err(invalid("rootfs quota identity differs").into());
        }
        lock(&file, exclusive)?;
        Ok(file)
    }
    pub fn read_json<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<T> {
        let mut file =
            child(&self.file, name, false)?.ok_or_else(|| invalid("rootfs metadata absent"))?;
        metadata_file(&file)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(65537)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(invalid("rootfs metadata exceeds bound").into());
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
    pub fn record(&self, id: Uuid) -> Result<Record> {
        let record: Record = self.read_json(&record_name(id))?;
        record.validate(self)?;
        if id.is_nil() || record.intent.source.capture != id {
            return Err(invalid("rootfs record does not belong to the requested capture").into());
        }
        Ok(record)
    }
    pub fn exists(&self, name: &str) -> Result<bool> {
        Ok(child(&self.file, name, false)?.is_some())
    }
    pub fn recover(&self, selected: &[&str]) -> Result<()> {
        self.current()?;
        let result = metadata::recover_entries(&self.path, selected, true, |name, bytes| {
            if name.ends_with(".lock") {
                let header: LockHeader = serde_json::from_slice(bytes)?;
                if header.format != 1
                    || header.store != self.store()
                    || match header.capture {
                        Some(id) => {
                            id.is_nil()
                                || job_name(id) != name
                                || !header.intent_sha256.as_ref().is_some_and(|s| valid_sha(s))
                        }
                        None => name != "quota.lock" || header.intent_sha256.is_some(),
                    }
                {
                    return Err(invalid("pending rootfs lock identity differs").into());
                }
            } else if name.starts_with("boot-") && name.ends_with(".json") {
                super::boots::validate_pending(self, name, bytes)?;
            } else {
                let record: Record = serde_json::from_slice(bytes)?;
                record.validate(self)?;
                if record_name(record.intent.source.capture) != name {
                    return Err(invalid("pending rootfs record name differs").into());
                }
            }
            Ok(())
        })?;
        if !result.unconfirmed.is_empty() {
            return Err(invalid("rootfs metadata writer remains unconfirmed").into());
        }
        Ok(())
    }
    pub fn recover_capture(&self, id: Uuid) -> Result<()> {
        self.recover(&[&record_name(id), &job_name(id)])
    }
    pub fn job(
        &self,
        intent: &RootfsCaptureIntent,
        identity: Option<&Identity>,
        exclusive: bool,
    ) -> Result<(File, Identity)> {
        let name = job_name(intent.source.capture);
        let expected = serde_json::json!({"format":1,"store":self.store(),"capture":intent.source.capture,"intent_sha256":intent.fingerprint().map_err(invalid)?});
        if identity.is_none() && !self.exists(&name)? {
            metadata::initial_json(&self.path.join(&name), &expected)?;
        }
        let file = child(&self.file, &name, true)?
            .ok_or_else(|| invalid("rootfs capture mutex missing; no replacement created"))?;
        metadata_file(&file)?;
        let actual = Identity::of(&file)?;
        if identity.is_some_and(|i| i != &actual)
            || self.read_json::<serde_json::Value>(&name)? != expected
        {
            return Err(invalid("rootfs capture mutex identity differs").into());
        }
        lock(&file, exclusive)?;
        Ok((file, actual))
    }
    pub fn records(&self) -> Result<Vec<Record>> {
        self.recover(&[])?;
        let mut records = Vec::new();
        let mut disks = Vec::new();
        for (count, entry) in std::fs::read_dir(&self.path)?.enumerate() {
            if count >= 32768 {
                return Err(invalid("rootfs store inventory exceeds bound").into());
            }
            let entry = entry?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| invalid("rootfs store entry is not UTF8"))?;
            if let Some(raw) = name
                .strip_prefix("capture-")
                .and_then(|s| s.strip_suffix(".disk"))
            {
                let id = Uuid::parse_str(raw)?;
                if id.is_nil() || disk_name(id) != name {
                    return Err(invalid("rootfs disk filename differs").into());
                }
                disks.push(id);
            }
            if let Some(raw) = name
                .strip_prefix("capture-")
                .and_then(|s| s.strip_suffix(".json"))
            {
                let id = Uuid::parse_str(raw)?;
                if id.is_nil() || record_name(id) != name || records.len() >= 8192 {
                    return Err(invalid("rootfs record inventory differs or exceeds bound").into());
                }
                let record: Record = self.read_json(name)?;
                record.validate(self)?;
                if record.intent.source.capture != id {
                    return Err(invalid("rootfs record filename differs").into());
                }
                records.push(record);
            }
        }
        for id in disks {
            let record = records
                .iter()
                .find(|r| r.intent.source.capture == id)
                .ok_or_else(|| {
                    invalid("unacknowledged rootfs disk is preserved; admission refused")
                })?;
            let receipt = record
                .disk
                .as_ref()
                .ok_or_else(|| invalid("rootfs named disk has no original receipt"))?;
            let file = self
                .owned(receipt)?
                .ok_or_else(|| invalid("rootfs named disk was lost during inventory"))?;
            if record.phase == Phase::Collected
                || file.metadata()?.len() != receipt.content.size_bytes
            {
                return Err(
                    invalid("rootfs stored disk identity or reserved length differs").into(),
                );
            }
        }
        Ok(records)
    }
    pub fn anonymous(&self) -> Result<File> {
        self.current()?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                c".".as_ptr(),
                libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    pub fn seal(&self, file: File, manifest: &RootfsManifest) -> Result<(File, DiskReceipt)> {
        use std::os::unix::fs::PermissionsExt;
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != 0
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 0
            || m.dev() != self.file.metadata()?.dev()
            || m.len() != manifest.disk.size_bytes
        {
            return Err(invalid("rootfs unnamed disk ownership differs").into());
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o400))?;
        let receipt = DiskReceipt {
            format: 1,
            store: self.store(),
            capture: manifest.intent.source.capture,
            reference: manifest.reference().map_err(invalid)?,
            disk_id: manifest.intent.disk_id,
            content: manifest.disk.clone(),
            inode: Identity::of(&file)?,
        };
        attach(&file, OBJECT, &receipt)?;
        let result = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        if Identity::of(&result)? != receipt.inode {
            return Err(invalid("rootfs read-only descriptor differs").into());
        }
        drop(file);
        Ok((result, receipt))
    }
    pub fn validate_receipt(&self, receipt: &DiskReceipt, manifest: &RootfsManifest) -> Result<()> {
        if receipt.format != 1
            || receipt.store != self.store()
            || receipt.capture != manifest.intent.source.capture
            || receipt.disk_id != manifest.intent.disk_id
            || receipt.content != manifest.disk
            || receipt.reference != manifest.reference().map_err(invalid)?
        {
            return Err(invalid("rootfs disk receipt differs from its manifest").into());
        }
        Ok(())
    }
    pub fn owned(&self, receipt: &DiskReceipt) -> Result<Option<File>> {
        self.current()?;
        let Some(file) = child(&self.file, &disk_name(receipt.capture), false)? else {
            return Ok(None);
        };
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != 0
            || m.mode() & 0o7777 != 0o400
            || m.nlink() != 1
            || Identity::of(&file)? != receipt.inode
            || attribute::<DiskReceipt>(&file, OBJECT)? != *receipt
        {
            return Err(
                invalid("rootfs disk inode, owner or receipt differs; collection refused").into(),
            );
        }
        Ok(Some(file))
    }
    pub fn publish(&self, file: &File, receipt: &DiskReceipt) -> Result<()> {
        self.current()?;
        if Identity::of(file)? != receipt.inode
            || attribute::<DiskReceipt>(file, OBJECT)? != *receipt
        {
            return Err(invalid("rootfs publish descriptor differs").into());
        }
        let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        let target = component(&disk_name(receipt.capture))?;
        if unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                source.as_ptr(),
                self.file.as_raw_fd(),
                target.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error.into());
            }
        }
        self.file.sync_all()?;
        self.owned(receipt)?
            .ok_or_else(|| invalid("rootfs linked disk absent"))?;
        Ok(())
    }
    pub fn verified(&self, receipt: &DiskReceipt) -> Result<File> {
        use std::io::Seek;
        let mut file = self
            .owned(receipt)?
            .ok_or_else(|| invalid("rootfs disk absent"))?;
        if crate::fileio::digest_exact(file.try_clone()?, receipt.content.size_bytes)?
            != (receipt.content.sha256.clone(), receipt.content.size_bytes)
        {
            return Err(invalid("rootfs stored disk content differs").into());
        }
        file.rewind()?;
        Ok(file)
    }
    pub fn collect(&self, id: Uuid, receipt: Option<&DiskReceipt>) -> Result<()> {
        self.current()?;
        let name = disk_name(id);
        if let Some(receipt) = receipt {
            if receipt.capture != id {
                return Err(invalid("rootfs collection ID differs").into());
            }
            if self.owned(receipt)?.is_some() {
                self.owned(receipt)?
                    .ok_or_else(|| invalid("rootfs disk disappeared during collection"))?;
                if unsafe { libc::unlinkat(self.file.as_raw_fd(), component(&name)?.as_ptr(), 0) }
                    != 0
                {
                    return Err(io::Error::last_os_error().into());
                }
                self.file.sync_all()?;
            }
        } else if self.exists(&name)? {
            return Err(invalid("unacknowledged rootfs disk is preserved").into());
        }
        if self.exists(&name)? {
            return Err(invalid("rootfs disk absence unconfirmed").into());
        }
        Ok(())
    }
}
