//! Persistent object identity is separate from a producer's boot/process fence.
use super::*;
use std::{ffi::CString, time::UNIX_EPOCH};

const ROOT_ATTRIBUTE: &std::ffi::CStr = c"user.goldenhoop.checkpoint.root.v1";
const READY_ATTRIBUTE: &std::ffi::CStr = c"user.goldenhoop.checkpoint.ready.v1";
const OBJECT_ATTRIBUTE: &std::ffi::CStr = c"user.goldenhoop.checkpoint.object.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    device: u64,
    inode: u64,
    birth_seconds: u64,
    birth_nanoseconds: u32,
}
impl Identity {
    pub(super) fn of(file: &File) -> Result<Self> {
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
    nonce: Uuid,
    path: PathBuf,
    parent: Identity,
    directory: Identity,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    binding: Binding,
    quota: Identity,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LockHeader {
    format: u16,
    store: Uuid,
    capture: Option<Uuid>,
    intent_sha256: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceDirectory {
    path: PathBuf,
    generation: Uuid,
    parent: Identity,
    inode: Identity,
}

/// A new target is named before allocation. This grants no authority to adopt
/// or delete an occupied path; its acknowledged directory is recorded later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Destination {
    path: PathBuf,
    parent: Identity,
    generation: Uuid,
}
impl Destination {
    pub(crate) fn observe(path: &Path, generation: Uuid) -> Result<Self> {
        let directory = parent(path)?;
        if generation.is_nil() {
            return Err(invalid("nil restore destination generation").into());
        }
        Ok(Self {
            path: path.to_owned(),
            parent: Identity::of(&directory)?,
            generation,
        })
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn validate(
        &self,
        generation: Uuid,
        store: &Path,
        source: &SourceDirectory,
    ) -> Result<()> {
        if self.generation != generation
            || generation.is_nil()
            || !self.path.is_absolute()
            || self.path.components().any(|p| {
                matches!(
                    p,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || self.path.starts_with(store)
            || store.starts_with(&self.path)
            || self.path.starts_with(&source.path)
            || source.path.starts_with(&self.path)
        {
            return Err(invalid("restore destination scope overlaps or differs").into());
        }
        component(
            self.path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| invalid("restore destination name absent"))?,
        )?;
        Ok(())
    }
    pub(super) fn require_absent(&self) -> Result<()> {
        let directory = parent(&self.path)?;
        if Identity::of(&directory)? != self.parent {
            return Err(invalid("restore destination parent changed").into());
        }
        let name = component(
            self.path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| invalid("restore target name absent"))?,
        )?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Err(invalid("restore target still exists; reservation retained").into());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error.into());
        }
        Ok(())
    }
    pub(super) fn acknowledge(&self) -> Result<SourceDirectory> {
        let observed = SourceDirectory::observe(&self.path, self.generation)?;
        self.matches(&observed)?;
        Ok(observed)
    }
    pub(super) fn matches(&self, directory: &SourceDirectory) -> Result<()> {
        if directory.path != self.path
            || directory.generation != self.generation
            || directory.parent != self.parent
        {
            return Err(invalid("restore target directory receipt differs").into());
        }
        Ok(())
    }
}
impl SourceDirectory {
    pub(crate) fn observe(path: &Path, generation: Uuid) -> Result<Self> {
        let p = parent(path)?;
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let m = f.metadata()?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o7777 != 0o700 || generation.is_nil() {
            return Err(invalid("checkpoint source directory ownership differs").into());
        }
        Ok(Self {
            path: path.to_owned(),
            generation,
            parent: Identity::of(&p)?,
            inode: Identity::of(&f)?,
        })
    }
    pub(super) fn validate(&self, generation: Uuid, store: &Path) -> Result<()> {
        if self.generation != generation
            || !self.path.is_absolute()
            || self.path.components().any(|p| {
                matches!(
                    p,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
            || store.starts_with(&self.path)
            || self.path.starts_with(store)
        {
            return Err(
                invalid("checkpoint source directory and durable store overlap or differ").into(),
            );
        }
        Ok(())
    }
    pub(super) fn require_absent(&self) -> Result<()> {
        let p = parent(&self.path)?;
        if Identity::of(&p)? != self.parent {
            return Err(invalid("checkpoint source parent identity changed").into());
        }
        let name = component(
            self.path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| invalid("checkpoint source name missing"))?,
        )?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                p.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Err(invalid(
                "checkpoint source directory still exists; raw-output quota remains reserved",
            )
            .into());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::NotFound {
            return Err(e.into());
        }
        Ok(())
    }
    pub(super) fn require_present(&self) -> Result<()> {
        let observed = Self::observe(&self.path, self.generation)?;
        if observed.parent != self.parent || observed.inode != self.inode {
            return Err(invalid("checkpoint source directory inode changed").into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObjectReceipt {
    format: u16,
    store: Uuid,
    capture: Uuid,
    manifest_sha256: String,
    role: String,
    object: CheckpointContent,
    inode: Identity,
}

pub(super) struct Root {
    pub path: PathBuf,
    directory: File,
    ready: Ready,
}
fn continuation_name(id: Uuid) -> String {
    format!("continuation-{id}.lock")
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
        return Err(invalid("invalid checkpoint store component").into());
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
        return Err(invalid("checkpoint receipt exceeds bound").into());
    }
    Ok(serde_json::from_slice(&bytes[..count as usize])?)
}
fn attach(file: &File, name: &std::ffi::CStr, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 16384 {
        return Err(invalid("checkpoint receipt exceeds bound").into());
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
        return Err(
            invalid("checkpoint store requires Linux root and an absolute canonical path").into(),
        );
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("checkpoint store parent missing"))?;
    if std::fs::canonicalize(parent)? != parent {
        return Err(invalid("checkpoint store parent is not canonical").into());
    }
    for ancestor in parent.ancestors() {
        let m = std::fs::symlink_metadata(ancestor)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(invalid("checkpoint store ancestry is untrusted").into());
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
        return Err(invalid("checkpoint store requires supported local disk storage").into());
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
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(e.into());
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}
fn metadata_file(file: &File) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || m.len() > 65536
    {
        return Err(invalid("checkpoint metadata ownership/type/link count differs").into());
    }
    Ok(())
}
pub(super) fn object_name(id: Uuid, role: &str) -> String {
    format!("capture-{id}-{role}.bin")
}
pub(super) fn record_name(id: Uuid) -> String {
    format!("capture-{id}.json")
}
pub(super) fn lock_name(id: Uuid) -> String {
    format!("capture-{id}.lock")
}

impl Root {
    pub(super) fn continuation_exists(&self, id: Uuid) -> Result<bool> {
        Ok(child(&self.directory, &continuation_name(id), false)?.is_some())
    }
    pub(super) fn new_continuation(
        &self,
        id: Uuid,
        intent_sha256: &str,
    ) -> Result<(File, Identity)> {
        if self.continuation_exists(id)? {
            return Err(invalid(
                "checkpoint continuation witness already exists; original claim must be reconciled",
            )
            .into());
        }
        metadata::initial_json(
            &self.path.join(continuation_name(id)),
            &LockHeader {
                format: 1,
                store: self.nonce(),
                capture: Some(id),
                intent_sha256: Some(intent_sha256.into()),
            },
        )?;
        let file = child(&self.directory, &continuation_name(id), true)?
            .ok_or_else(|| invalid("continuation witness missing after initialization"))?;
        metadata_file(&file)?;
        let identity = Identity::of(&file)?;
        let lease = self.continuation_mutex(id, &identity, intent_sha256)?;
        fs2::FileExt::try_lock_exclusive(&lease)?;
        Ok((lease, identity))
    }
    pub(super) fn continuation_mutex(
        &self,
        id: Uuid,
        expected: &Identity,
        intent_sha256: &str,
    ) -> Result<File> {
        self.current()?;
        let file = child(&self.directory, &continuation_name(id), true)?
            .ok_or_else(|| invalid("original continuation witness missing"))?;
        metadata_file(&file)?;
        if Identity::of(&file)? != *expected
            || self.json::<LockHeader>(&continuation_name(id))?
                != (LockHeader {
                    format: 1,
                    store: self.nonce(),
                    capture: Some(id),
                    intent_sha256: Some(intent_sha256.into()),
                })
        {
            return Err(
                invalid("continuation witness identity or immutable intent differs").into(),
            );
        }
        Ok(file)
    }
    pub(super) fn duplicate(&self) -> Result<Self> {
        self.current()?;
        Ok(Self {
            path: self.path.clone(),
            directory: self.directory.try_clone()?,
            ready: self.ready.clone(),
        })
    }
    pub fn initialize(path: &Path, installation: Uuid) -> Result<Self> {
        if installation.is_nil() {
            return Err(invalid("nil checkpoint installation").into());
        }
        let parent = parent(path)?;
        let name = component(
            path.file_name()
                .and_then(|p| p.to_str())
                .ok_or_else(|| invalid("checkpoint root name missing"))?,
        )?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let binding = Binding {
            format: 1,
            installation,
            nonce: Uuid::new_v4(),
            path: path.to_owned(),
            parent: Identity::of(&parent)?,
            directory: Identity::of(&directory)?,
        };
        // An unacknowledged mkdir without this receipt is never adopted/deleted.
        attach(&directory, ROOT_ATTRIBUTE, &binding)?;
        parent.sync_all()?;
        metadata::initial_json(
            &path.join("quota.lock"),
            &LockHeader {
                format: 1,
                store: binding.nonce,
                capture: None,
                intent_sha256: None,
            },
        )?;
        let quota = child(&directory, "quota.lock", true)?
            .ok_or_else(|| invalid("checkpoint quota lock absent after publication"))?;
        metadata_file(&quota)?;
        let ready = Ready {
            binding,
            quota: Identity::of(&quota)?,
        };
        attach(&directory, READY_ATTRIBUTE, &ready)?;
        parent.sync_all()?;
        Self::open(path, installation)
    }
    pub fn open(path: &Path, installation: Uuid) -> Result<Self> {
        let parent = parent(path)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let m = directory.metadata()?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o7777 != 0o700 {
            return Err(invalid("checkpoint root ownership differs").into());
        }
        let binding: Binding = attribute(&directory, ROOT_ATTRIBUTE)?;
        let ready: Ready = attribute(&directory, READY_ATTRIBUTE)?;
        if binding.format != 1
            || binding.installation != installation
            || installation.is_nil()
            || binding.nonce.is_nil()
            || binding.path != path
            || binding.parent != Identity::of(&parent)?
            || binding.directory != Identity::of(&directory)?
            || ready.binding != binding
        {
            return Err(invalid("checkpoint persistent root receipt differs").into());
        }
        let root = Self {
            path: path.to_owned(),
            directory,
            ready,
        };
        root.quota(false)?;
        Ok(root)
    }
    pub fn nonce(&self) -> Uuid {
        self.ready.binding.nonce
    }
    pub fn installation(&self) -> Uuid {
        self.ready.binding.installation
    }
    pub fn current(&self) -> Result<()> {
        let p = parent(&self.path)?;
        let m = std::fs::symlink_metadata(&self.path)?;
        if !m.is_dir()
            || m.uid() != 0
            || m.mode() & 0o7777 != 0o700
            || Identity::of(&p)? != self.ready.binding.parent
        {
            return Err(invalid("checkpoint parent/root changed").into());
        }
        let d = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)?;
        if Identity::of(&d)? != self.ready.binding.directory
            || attribute::<Ready>(&d, READY_ATTRIBUTE)? != self.ready
        {
            return Err(invalid("checkpoint directory identity changed").into());
        }
        Ok(())
    }
    pub fn json<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<T> {
        self.current()?;
        let mut f = child(&self.directory, name, false)?
            .ok_or_else(|| invalid("checkpoint metadata absent"))?;
        metadata_file(&f)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut f).take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err(invalid("checkpoint metadata exceeds bound").into());
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
    pub fn quota(&self, exclusive: bool) -> Result<File> {
        let f = child(&self.directory, "quota.lock", exclusive)?
            .ok_or_else(|| invalid("checkpoint quota lock missing; no replacement is created"))?;
        metadata_file(&f)?;
        if Identity::of(&f)? != self.ready.quota {
            return Err(invalid("checkpoint quota lock inode changed").into());
        }
        let actual: LockHeader = self.json("quota.lock")?;
        if actual
            != (LockHeader {
                format: 1,
                store: self.nonce(),
                capture: None,
                intent_sha256: None,
            })
        {
            return Err(invalid("checkpoint quota binding differs").into());
        }
        if exclusive {
            fs2::FileExt::try_lock_exclusive(&f)?;
        } else {
            fs2::FileExt::try_lock_shared(&f)?;
        }
        Ok(f)
    }
    pub fn ensure_job_lock(&self, id: Uuid, intent_sha256: &str) -> Result<Identity> {
        self.current()?;
        let name = lock_name(id);
        if child(&self.directory, &name, false)?.is_none() {
            metadata::initial_json(
                &self.path.join(&name),
                &LockHeader {
                    format: 1,
                    store: self.nonce(),
                    capture: Some(id),
                    intent_sha256: Some(intent_sha256.into()),
                },
            )?;
        }
        let f = child(&self.directory, &name, true)?
            .ok_or_else(|| invalid("checkpoint job lock absent"))?;
        metadata_file(&f)?;
        if self.json::<LockHeader>(&name)?
            != (LockHeader {
                format: 1,
                store: self.nonce(),
                capture: Some(id),
                intent_sha256: Some(intent_sha256.into()),
            })
        {
            return Err(invalid("checkpoint job lock binding differs").into());
        }
        Identity::of(&f)
    }
    pub fn job_mutex(
        &self,
        id: Uuid,
        expected: &Identity,
        intent_sha256: &str,
        exclusive: bool,
    ) -> Result<File> {
        self.current()?;
        let name = lock_name(id);
        let f = child(&self.directory, &name, exclusive)?
            .ok_or_else(|| invalid("checkpoint job mutex missing"))?;
        metadata_file(&f)?;
        if Identity::of(&f)? != *expected
            || self.json::<LockHeader>(&name)?
                != (LockHeader {
                    format: 1,
                    store: self.nonce(),
                    capture: Some(id),
                    intent_sha256: Some(intent_sha256.into()),
                })
        {
            return Err(invalid("checkpoint job mutex identity differs").into());
        }
        Ok(f)
    }
    pub fn job_lock(
        &self,
        id: Uuid,
        expected: &Identity,
        intent_sha256: &str,
        exclusive: bool,
    ) -> Result<File> {
        let f = self.job_mutex(id, expected, intent_sha256, exclusive)?;
        if exclusive {
            fs2::FileExt::try_lock_exclusive(&f)?;
        } else {
            fs2::FileExt::try_lock_shared(&f)?;
        }
        Ok(f)
    }
    pub fn recover(&self) -> Result<()> {
        self.recover_selected(&[])
    }
    pub fn recover_capture(&self, id: Uuid) -> Result<()> {
        let record = record_name(id);
        let lock = lock_name(id);
        let continuation = continuation_name(id);
        self.recover_selected(&[&record, &lock, &continuation])
    }
    fn recover_selected(&self, selected: &[&str]) -> Result<()> {
        self.current()?;
        let result = metadata::recover_entries(&self.path, selected, true, |name, bytes| {
            if name == "quota.lock" || name.ends_with(".lock") {
                let h: LockHeader = serde_json::from_slice(bytes)?;
                if h.format != 1
                    || h.store != self.nonce()
                    || !h
                        .capture
                        .map(|id| name == lock_name(id) || name == continuation_name(id))
                        .unwrap_or(name == "quota.lock")
                    || match h.capture {
                        Some(id) => {
                            id.is_nil() || !h.intent_sha256.as_ref().is_some_and(|s| valid_sha(s))
                        }
                        None => h.intent_sha256.is_some(),
                    }
                {
                    return Err(invalid("pending checkpoint lock differs").into());
                }
            } else {
                let r: Record = serde_json::from_slice(bytes)?;
                r.validate(self)?;
                if record_name(r.intent.source.capture) != name {
                    return Err(invalid("pending checkpoint record name differs").into());
                }
            }
            Ok(())
        })?;
        if !result.unconfirmed.is_empty() {
            return Err(invalid("checkpoint metadata writer remains unconfirmed").into());
        }
        Ok(())
    }
    pub fn records(&self) -> Result<Vec<Record>> {
        self.current()?;
        let mut result = Vec::new();
        for (count, entry) in std::fs::read_dir(&self.path)?.enumerate() {
            if count >= 8192 {
                return Err(invalid("checkpoint catalog exceeds bound").into());
            }
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| invalid("invalid checkpoint catalog name"))?;
            if let Some(id) = name
                .strip_prefix("capture-")
                .and_then(|n| n.strip_suffix(".json"))
            {
                let id = Uuid::parse_str(id)?;
                if id.is_nil() || record_name(id) != name {
                    return Err(invalid("noncanonical checkpoint record name").into());
                }
                let r: Record = self.json(&name)?;
                r.validate(self)?;
                result.push(r);
            }
        }
        Ok(result)
    }
    pub fn receipts(
        &self,
        manifest: &CheckpointManifest,
        files: &CheckpointFiles,
    ) -> Result<Vec<ObjectReceipt>> {
        let reference = manifest.reference().map_err(invalid)?;
        [
            (&files.state, &manifest.state, "state"),
            (&files.memory, &manifest.memory, "memory"),
            (&files.disk, &manifest.disk, "disk"),
        ]
        .into_iter()
        .map(|(f, o, role)| {
            let m = f.metadata()?;
            if !m.is_file()
                || m.uid() != 0
                || m.mode() & 0o7777 != 0o400
                || m.nlink() != 0
                || m.len() != o.size_bytes
            {
                return Err(invalid("fresh checkpoint publication descriptor differs").into());
            }
            let r = ObjectReceipt {
                format: 1,
                store: self.nonce(),
                capture: reference.capture,
                manifest_sha256: reference.manifest_sha256.clone(),
                role: role.into(),
                object: o.clone(),
                inode: Identity::of(f)?,
            };
            attach(f, OBJECT_ATTRIBUTE, &r)?;
            Ok(r)
        })
        .collect()
    }
    pub fn validate_receipts(
        &self,
        manifest: &CheckpointManifest,
        receipts: &[ObjectReceipt],
    ) -> Result<()> {
        let reference = manifest.reference().map_err(invalid)?;
        if receipts.len() != 3 {
            return Err(invalid("checkpoint object receipt count differs").into());
        }
        for (r, (role, object)) in receipts.iter().zip([
            ("state", &manifest.state),
            ("memory", &manifest.memory),
            ("disk", &manifest.disk),
        ]) {
            if r.format != 1
                || r.store != self.nonce()
                || r.capture != reference.capture
                || r.manifest_sha256 != reference.manifest_sha256
                || r.role != role
                || &r.object != object
            {
                return Err(invalid("checkpoint receipt content/role/store differs").into());
            }
        }
        Ok(())
    }
    fn owned(&self, r: &ObjectReceipt) -> Result<Option<File>> {
        self.current()?;
        let name = object_name(r.capture, &r.role);
        let Some(f) = child(&self.directory, &name, false)? else {
            return Ok(None);
        };
        let m = f.metadata()?;
        if !m.is_file()
            || m.uid() != 0
            || m.mode() & 0o7777 != 0o400
            || m.nlink() != 1
            || Identity::of(&f)? != r.inode
            || attribute::<ObjectReceipt>(&f, OBJECT_ATTRIBUTE)? != *r
        {
            return Err(invalid(
                "checkpoint object inode/receipt/ownership differs; collection refused",
            )
            .into());
        }
        Ok(Some(f))
    }
    pub fn publish_object(&self, file: &File, r: &ObjectReceipt) -> Result<()> {
        self.current()?;
        if Identity::of(file)? != r.inode
            || attribute::<ObjectReceipt>(file, OBJECT_ATTRIBUTE)? != *r
        {
            return Err(invalid("checkpoint publish descriptor differs").into());
        }
        let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        let target = component(&object_name(r.capture, &r.role))?;
        if unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                source.as_ptr(),
                self.directory.as_raw_fd(),
                target.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        } != 0
        {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::AlreadyExists {
                return Err(e.into());
            }
        }
        self.directory.sync_all()?;
        self.owned(r)?
            .ok_or_else(|| invalid("checkpoint linked object absent"))?;
        Ok(())
    }
    pub fn verify_objects(&self, receipts: &[ObjectReceipt]) -> Result<CheckpointFiles> {
        let mut files = Vec::new();
        for r in receipts {
            let f = self
                .owned(r)?
                .ok_or_else(|| invalid("checkpoint object absent"))?;
            if f.metadata()?.len() != r.object.size_bytes
                || crate::fileio::digest(f.try_clone()?)?
                    != (r.object.sha256.clone(), r.object.size_bytes)
            {
                return Err(invalid("checkpoint object content is corrupt").into());
            }
            use std::io::Seek;
            let mut f = f;
            f.rewind()?;
            files.push(f);
        }
        let [state, memory, disk]: [File; 3] = files
            .try_into()
            .map_err(|_| invalid("checkpoint object count differs"))?;
        Ok(CheckpointFiles {
            state,
            memory,
            disk,
        })
    }
    pub fn collect_objects(&self, id: Uuid, receipts: &[ObjectReceipt]) -> Result<()> {
        for role in ["state", "memory", "disk"] {
            let name = object_name(id, role);
            let r = receipts.iter().find(|r| r.role == role);
            if let Some(r) = r {
                if self.owned(r)?.is_some() {
                    // Recheck the precise object immediately before unlinkat.
                    self.owned(r)?.ok_or_else(|| {
                        invalid("checkpoint object disappeared during collection")
                    })?;
                    let c = component(&name)?;
                    if unsafe { libc::unlinkat(self.directory.as_raw_fd(), c.as_ptr(), 0) } != 0 {
                        return Err(io::Error::last_os_error().into());
                    }
                    self.directory.sync_all()?;
                }
            } else if child(&self.directory, &name, false)?.is_some() {
                return Err(invalid("unacknowledged checkpoint object is preserved").into());
            }
            if child(&self.directory, &name, false)?.is_some() {
                return Err(invalid("checkpoint object absence unconfirmed").into());
            }
        }
        Ok(())
    }
}
