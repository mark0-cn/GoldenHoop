//! Inode-bound metadata publication. The complete receipt is attached before
//! an unnamed file acquires a name; recovery never guesses from a filename.
use super::super::*;
use std::{ffi::CString, sync::OnceLock, time::Duration};

const ATTRIBUTE: &[u8] = b"user.goldenhoop.metadata.v1\0";
const LIMIT: usize = 65536;
const RECEIPT_LIMIT: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inode {
    device: u64,
    inode: u64,
}
impl Inode {
    fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Content {
    inode: Inode,
    length: u64,
    sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preimage {
    content: Content,
    change_seconds: i64,
    change_nanoseconds: i64,
    receipt_sha256: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    process: ProcessIdentity,
    pid_namespace: Inode,
}
fn actor() -> Result<Actor> {
    static IDENTITY: OnceLock<std::result::Result<Actor, String>> = OnceLock::new();
    let current = IDENTITY
        .get_or_init(|| {
            (|| -> Result<Actor> {
                Ok(Actor {
                    process: process_identity(std::process::id())?,
                    pid_namespace: Inode::of(&std::fs::metadata("/proc/self/ns/pid")?),
                })
            })()
            .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| invalid(error.clone()))?;
    if current.process.pid != std::process::id() {
        return Err(invalid("metadata cannot be published from an unexecuted fork").into());
    }
    Ok(current.clone())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    format: u32,
    directory: PathBuf,
    parent: Inode,
    target: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    binding: Binding,
    transaction: Uuid,
    mutex: Inode,
    actor: Actor,
    previous: Option<Preimage>,
    content: Content,
}

struct Parent {
    file: File,
    path: PathBuf,
    inode: Inode,
    uid: u32,
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
        return Err(invalid("invalid private metadata component").into());
    }
    Ok(CString::new(name)?)
}
impl Parent {
    fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute()
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(invalid("private metadata directory is not canonical").into());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let value = file.metadata()?;
        let uid = unsafe { libc::geteuid() };
        if !value.is_dir() || value.uid() != uid || value.mode() & 0o077 != 0 {
            return Err(invalid("private metadata directory ownership differs").into());
        }
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        // Local kernel lock/inode semantics only; no remote-filesystem recovery.
        if ![0xef53, 0x58465342, 0x9123683e, 0x794c7630, 0x01021994]
            .contains(&i128::from(filesystem.f_type))
        {
            return Err(invalid("native metadata requires a supported local filesystem").into());
        }
        Ok(Self {
            inode: Inode::of(&value),
            file,
            path: path.into(),
            uid,
        })
    }
    fn binding(&self, target: &str) -> Result<Binding> {
        component(target)?;
        if target.starts_with(".gh-meta-") {
            return Err(invalid("metadata target collides with coordination namespace").into());
        }
        Ok(Binding {
            format: 1,
            directory: self.path.clone(),
            parent: self.inode.clone(),
            target: target.into(),
        })
    }
    fn current(&self) -> Result<()> {
        let value = std::fs::symlink_metadata(&self.path)?;
        if !value.is_dir()
            || value.uid() != self.uid
            || value.mode() & 0o077 != 0
            || Inode::of(&value) != self.inode
        {
            return Err(invalid("metadata parent inode changed").into());
        }
        Ok(())
    }
    fn open_file(&self, name: &str, write: bool) -> Result<Option<File>> {
        let name = component(name)?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                (if write { libc::O_RDWR } else { libc::O_RDONLY })
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
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
    fn unnamed(&self, bytes: &[u8]) -> Result<File> {
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
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)?;
        Ok(file)
    }
    fn link(&self, file: &File, name: &str) -> Result<()> {
        self.current()?;
        let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        let target = component(name)?;
        // The documented /proc form also works without CAP_DAC_READ_SEARCH.
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
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
    fn bytes(&self, file: &File, limit: usize, linked: bool) -> Result<Vec<u8>> {
        use std::os::unix::fs::FileExt;
        let value = file.metadata()?;
        if !value.is_file()
            || value.uid() != self.uid
            || value.mode() & 0o777 != 0o600
            || value.nlink() != u64::from(linked)
            || value.len() > limit as u64
        {
            return Err(invalid("private metadata file ownership/type/length differs").into());
        }
        let mut bytes = vec![0; value.len() as usize];
        file.read_exact_at(&mut bytes, 0)?;
        let after = file.metadata()?;
        if Inode::of(&after) != Inode::of(&value)
            || after.len() != value.len()
            || (
                after.ctime(),
                after.ctime_nsec(),
                after.mtime(),
                after.mtime_nsec(),
            ) != (
                value.ctime(),
                value.ctime_nsec(),
                value.mtime(),
                value.mtime_nsec(),
            )
        {
            return Err(invalid("private metadata changed while reading").into());
        }
        Ok(bytes)
    }
    fn content(&self, file: &File, linked: bool) -> Result<Content> {
        let bytes = self.bytes(file, LIMIT, linked)?;
        Ok(Content {
            inode: Inode::of(&file.metadata()?),
            length: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
        })
    }
    fn previous(&self, target: &str) -> Result<Option<Content>> {
        self.open_file(target, false)?
            .map(|file| self.content(&file, true))
            .transpose()
    }
    fn preimage(&self, target: &str) -> Result<Option<Preimage>> {
        let Some(file) = self.open_file(target, false)? else {
            return Ok(None);
        };
        let content = self.content(&file, true)?;
        let metadata = file.metadata()?;
        let mut bytes = [0u8; RECEIPT_LIMIT + 1];
        let count = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                ATTRIBUTE.as_ptr().cast(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        let receipt_sha256 = if count >= 0 {
            if count as usize > RECEIPT_LIMIT {
                return Err(invalid("metadata preimage receipt exceeds bound").into());
            }
            Some(format!("{:x}", Sha256::digest(&bytes[..count as usize])))
        } else if io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA) {
            None
        } else {
            return Err(io::Error::last_os_error().into());
        };
        Ok(Some(Preimage {
            content,
            change_seconds: metadata.ctime(),
            change_nanoseconds: metadata.ctime_nsec(),
            receipt_sha256,
        }))
    }
    fn remove(&self, name: &str, expected: &Content) -> Result<()> {
        let Some(file) = self.open_file(name, false)? else {
            return Ok(());
        };
        if self.content(&file, true)? != *expected {
            return Err(
                invalid("metadata collection inode/content differs; object preserved").into(),
            );
        }
        self.current()?;
        let name = component(name)?;
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        self.file.sync_all()?;
        Ok(())
    }
}
fn mutex_name(target: &str) -> String {
    format!(".gh-meta-{:x}.lock", Sha256::digest(target.as_bytes()))
}
struct Guard {
    parent: Parent,
    file: File,
    binding: Binding,
    mutex: Inode,
}
impl Guard {
    fn acquire(parent: Parent, target: &str) -> Result<Self> {
        let binding = parent.binding(target)?;
        let name = mutex_name(target);
        let file = loop {
            if let Some(file) = parent.open_file(&name, true)? {
                let actual: Binding =
                    serde_json::from_slice(&parent.bytes(&file, RECEIPT_LIMIT, true)?)?;
                if actual != binding {
                    return Err(invalid("metadata mutex binding differs").into());
                }
                break file;
            }
            let file = parent.unnamed(&serde_json::to_vec(&binding)?)?;
            file.sync_all()?;
            match parent.link(&file, &name) {
                Ok(()) => {
                    parent.file.sync_all()?;
                    break file;
                }
                Err(error)
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::AlreadyExists) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match fs2::FileExt::try_lock_exclusive(&file) {
                Ok(()) => break,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => return Err(error.into()),
            }
        }
        let guard = Self {
            mutex: Inode::of(&file.metadata()?),
            parent,
            file,
            binding,
        };
        guard.current()?;
        Ok(guard)
    }
    fn current(&self) -> Result<()> {
        self.parent.current()?;
        let named = self
            .parent
            .open_file(&mutex_name(&self.binding.target), false)?
            .ok_or_else(|| invalid("metadata mutex disappeared"))?;
        if Inode::of(&named.metadata()?) != self.mutex
            || Inode::of(&self.file.metadata()?) != self.mutex
        {
            return Err(invalid("metadata mutex inode changed").into());
        }
        if let Some(target) = self.parent.open_file(&self.binding.target, false)? {
            let mut bytes = [0u8; RECEIPT_LIMIT + 1];
            let size = unsafe {
                libc::fgetxattr(
                    target.as_raw_fd(),
                    ATTRIBUTE.as_ptr().cast(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if size >= 0 {
                if size as usize > RECEIPT_LIMIT {
                    return Err(invalid("committed metadata receipt exceeds bound").into());
                }
                let receipt: Receipt = serde_json::from_slice(&bytes[..size as usize])?;
                if receipt.binding != self.binding
                    || receipt.mutex != self.mutex
                    || receipt.content != self.parent.content(&target, true)?
                {
                    return Err(invalid("committed metadata object/mutex context differs").into());
                }
            } else if io::Error::last_os_error().raw_os_error() != Some(libc::ENODATA) {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
    fn receipt(&self, file: &File, name: &str) -> Result<Receipt> {
        let mut value = vec![0u8; RECEIPT_LIMIT + 1];
        let count = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                ATTRIBUTE.as_ptr().cast(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if count as usize > RECEIPT_LIMIT {
            return Err(invalid("metadata receipt exceeds limit").into());
        }
        let receipt: Receipt = serde_json::from_slice(&value[..count as usize])?;
        if receipt.binding != self.binding
            || receipt.mutex != self.mutex
            || receipt.transaction.is_nil()
            || name != pending_name(receipt.transaction)
            || self.parent.content(file, true)? != receipt.content
        {
            return Err(invalid("metadata receipt object/context differs").into());
        }
        Ok(receipt)
    }
    fn publish(&self, name: &str, receipt: &Receipt) -> Result<()> {
        self.current()?;
        if self.parent.previous(name)? != Some(receipt.content.clone()) {
            return Err(
                invalid("metadata pending inode/content changed; publication refused").into(),
            );
        }
        if self.parent.preimage(&self.binding.target)? != receipt.previous {
            return Err(invalid("metadata target preimage changed; publication refused").into());
        }
        let source = component(name)?;
        let target = component(&self.binding.target)?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.parent.file.as_raw_fd(),
                source.as_ptr(),
                self.parent.file.as_raw_fd(),
                target.as_ptr(),
                if receipt.previous.is_none() {
                    libc::RENAME_NOREPLACE
                } else {
                    0
                },
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        self.parent.file.sync_all()?;
        if self.parent.previous(&self.binding.target)? != Some(receipt.content.clone()) {
            return Err(invalid("metadata publication observation differs").into());
        }
        Ok(())
    }
}
fn pending_name(id: Uuid) -> String {
    format!(".gh-meta-{id}.pending")
}
fn pending_id(name: &str) -> Option<Uuid> {
    let id = name.strip_prefix(".gh-meta-")?.strip_suffix(".pending")?;
    let value = Uuid::parse_str(id).ok()?;
    (value.to_string() == id && !value.is_nil()).then_some(value)
}
fn pending_names(parent: &Parent) -> Result<Vec<String>> {
    parent.current()?;
    let mut result = Vec::new();
    for (count, entry) in std::fs::read_dir(&parent.path)?.enumerate() {
        if count >= 8192 {
            return Err(invalid("metadata inventory exceeds bound").into());
        }
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| invalid("metadata filename is not UTF-8"))?;
        if pending_id(&name).is_some() {
            result.push(name);
        }
    }
    result.sort();
    Ok(result)
}
fn raw_receipt(parent: &Parent, name: &str) -> Result<Option<(File, Receipt)>> {
    let Some(file) = parent.open_file(name, false)? else {
        return Ok(None);
    };
    let mut bytes = [0u8; RECEIPT_LIMIT + 1];
    let count = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            ATTRIBUTE.as_ptr().cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if count as usize > RECEIPT_LIMIT {
        return Err(invalid("metadata receipt exceeds bound").into());
    }
    let receipt = serde_json::from_slice(&bytes[..count as usize])?;
    Ok(Some((file, receipt)))
}
fn recover_locked(
    guard: &Guard,
    own_retry: bool,
    verify: &impl Fn(&str, &[u8]) -> Result<()>,
) -> Result<usize> {
    let current = actor()?;
    let mut recovered = 0;
    for name in pending_names(&guard.parent)? {
        let Some((file, header)) = raw_receipt(&guard.parent, &name)? else {
            continue;
        };
        if header.binding.target != guard.binding.target {
            continue;
        }
        let receipt = guard.receipt(&file, &name)?;
        if receipt.actor.pid_namespace != current.pid_namespace
            || receipt.actor.process.boot_id != current.process.boot_id
            || receipt.actor.process.uid != current.process.uid
            || receipt.actor.process.executable_sha256 != current.process.executable_sha256
            || !(own_retry && receipt.actor == current)
                && !super::super::reaper::process_absent(&receipt.actor.process)?
        {
            return Err(invalid(
                "metadata original producer is not fenced in this boot/namespace/binary",
            )
            .into());
        }
        let bytes = guard.parent.bytes(&file, LIMIT, true)?;
        let _: serde_json::Value = serde_json::from_slice(&bytes)?;
        verify(&guard.binding.target, &bytes)?;
        guard.publish(&name, &receipt)?;
        recovered += 1;
    }
    Ok(recovered)
}

pub(super) fn write(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    write_observed(path, bytes, replace, |_| {})
}
fn write_observed(path: &Path, bytes: &[u8], replace: bool, observe: impl Fn(&str)) -> Result<()> {
    if bytes.len() > LIMIT {
        return Err(invalid("private metadata exceeds limit").into());
    }
    let parent = Parent::open(
        path.parent()
            .ok_or_else(|| invalid("metadata parent missing"))?,
    )?;
    let target = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("metadata target missing"))?;
    let guard = Guard::acquire(parent, target)?;
    recover_locked(&guard, true, &|_, _| Ok(()))?;
    let previous = guard.parent.preimage(target)?;
    if !replace && previous.is_some() {
        return Err(io::Error::from(io::ErrorKind::AlreadyExists).into());
    }
    let file = guard.parent.unnamed(bytes)?;
    let receipt = Receipt {
        binding: guard.binding.clone(),
        transaction: Uuid::new_v4(),
        mutex: guard.mutex.clone(),
        actor: actor()?,
        previous,
        content: guard.parent.content(&file, false)?,
    };
    let encoded = serde_json::to_vec(&receipt)?;
    if encoded.len() > RECEIPT_LIMIT {
        return Err(invalid("metadata receipt exceeds bound").into());
    }
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            ATTRIBUTE.as_ptr().cast(),
            encoded.as_ptr().cast(),
            encoded.len(),
            libc::XATTR_CREATE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    file.sync_all()?;
    observe("anonymous_synced");
    let name = pending_name(receipt.transaction);
    guard.current()?;
    guard.parent.link(&file, &name)?;
    let result = (|| -> Result<()> {
        guard.parent.file.sync_all()?;
        observe("pending_synced");
        guard.receipt(&file, &name)?;
        guard.publish(&name, &receipt)?;
        observe("published_synced");
        Ok(())
    })();
    if let Err(original) = result {
        if let Err(collection) = guard.parent.remove(&name, &receipt.content) {
            return Err(invalid(format!(
                "metadata write failed: {original}; collection unconfirmed: {collection}"
            ))
            .into());
        }
        return Err(original);
    }
    Ok(())
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Recovery {
    pub completed: Vec<String>,
    pub unconfirmed: Vec<String>,
}
pub(super) fn recover(
    parent: &Path,
    selected: &[&str],
    allow_unconfirmed: bool,
    verify: impl Fn(&str, &[u8]) -> Result<()>,
) -> Result<Recovery> {
    let opened = Parent::open(parent)?;
    let mut targets = std::collections::BTreeSet::new();
    for name in pending_names(&opened)? {
        if let Some((file, receipt)) = raw_receipt(&opened, &name)? {
            if !selected.is_empty() && !selected.contains(&receipt.binding.target.as_str()) {
                continue;
            }
            if opened.binding(&receipt.binding.target)? != receipt.binding
                || pending_name(receipt.transaction) != name
                || opened.content(&file, true)? != receipt.content
            {
                return Err(invalid("metadata pending parent/object binding differs").into());
            }
            // A recovery cannot manufacture a replacement for the original
            // kernel mutex. Validate it before any coordination-file creation.
            let mutex = opened
                .open_file(&mutex_name(&receipt.binding.target), false)?
                .ok_or_else(|| invalid("recorded metadata mutex is absent"))?;
            let binding: Binding =
                serde_json::from_slice(&opened.bytes(&mutex, RECEIPT_LIMIT, true)?)?;
            if binding != receipt.binding || Inode::of(&mutex.metadata()?) != receipt.mutex {
                return Err(invalid("recorded metadata mutex inode/context differs").into());
            }
            targets.insert(receipt.binding.target);
        }
    }
    let mut result = Recovery::default();
    for target in targets {
        let recovered = (|| -> Result<usize> {
            let guard = Guard::acquire(Parent::open(parent)?, &target)?;
            recover_locked(&guard, false, &verify)
        })();
        match recovered {
            Ok(count) if count > 0 => result.completed.push(target),
            Ok(_) => (),
            Err(_) if allow_unconfirmed => result.unconfirmed.push(target),
            Err(error) => return Err(error),
        }
    }
    Ok(result)
}

/// Before an installation marker exists, accept only complete coordination
/// bindings and inode-bound intents for the two exact installation claims.
pub(super) fn unmarked_inventory(root: &Path, installation: Uuid) -> Result<()> {
    let parent = Parent::open(root)?;
    for entry in std::fs::read_dir(root)? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| invalid("invalid root inventory name"))?;
        if name == "installation.lock" {
            continue;
        }
        let mut coordination = false;
        for target in ["installation.lock", "installation.json"] {
            if name == mutex_name(target) {
                let file = parent
                    .open_file(&name, false)?
                    .ok_or_else(|| invalid("metadata mutex disappeared"))?;
                let binding: Binding =
                    serde_json::from_slice(&parent.bytes(&file, RECEIPT_LIMIT, true)?)?;
                if binding != parent.binding(target)? {
                    return Err(invalid("unmarked mutex binding differs").into());
                }
                coordination = true;
            }
        }
        if coordination {
            continue;
        }
        if pending_id(&name).is_some() {
            let (file, receipt) = raw_receipt(&parent, &name)?
                .ok_or_else(|| invalid("unmarked pending disappeared"))?;
            if parent.binding(&receipt.binding.target)? != receipt.binding
                || pending_name(receipt.transaction) != name
                || parent.content(&file, true)? != receipt.content
            {
                return Err(invalid("unmarked pending inode/context differs").into());
            }
            claim_bytes(
                root,
                installation,
                &receipt.binding.target,
                &parent.bytes(&file, LIMIT, true)?,
            )?;
            continue;
        }
        return Err(invalid("unmarked native root is occupied; refusing adoption").into());
    }
    Ok(())
}
pub(super) fn claim_bytes(
    root: &Path,
    installation: Uuid,
    target: &str,
    bytes: &[u8],
) -> Result<()> {
    let expected = match target {
        "installation.lock" => {
            serde_json::json!({"format":1,"installation_id":installation,"data_root":root})
        }
        "installation.json" => serde_json::json!({"format":1,"installation_id":installation}),
        _ => return Err(invalid("unmarked pending target is not an installation claim").into()),
    };
    if serde_json::from_slice::<serde_json::Value>(bytes)? != expected {
        return Err(invalid("pending installation identity differs").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
