//! An acknowledged kernel object, never authority inferred from its pathname.
use super::recovery::PathIdentity;
use super::*;
use std::ffi::CString;

fn open_beneath(directory: &File, name: &str, flags: i32) -> Result<File> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(invalid("invalid cgroup member name").into());
    }
    // Linux open_how ABI. Require the same resolution fences as the cgroup-v2
    // path in OpenContainers; unsupported kernels fail without a path fallback.
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: 0x01 | 0x02 | 0x04 | 0x08,
    }; // NO_XDEV/MAGICLINKS/SYMLINKS, BENEATH
    let name = CString::new(name)?;
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

pub(crate) struct Group {
    path: PathBuf,
    identity: PathIdentity,
    directory: File,
}

impl Group {
    pub(crate) fn capture(path: &Path) -> Result<Self> {
        Self::open(path, &PathIdentity::capture(path, false)?)
    }

    pub(crate) fn open(path: &Path, identity: &PathIdentity) -> Result<Self> {
        // Native generation groups are direct children of this trusted mount.
        if path.parent() != Some(Path::new("/sys/fs/cgroup")) {
            return Err(invalid("native cgroup is not a direct unified child").into());
        }
        let mount = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/sys/fs/cgroup")?;
        let directory = open_beneath(
            &mount,
            path.file_name()
                .and_then(|v| v.to_str())
                .ok_or_else(|| invalid("invalid group name"))?,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut fs) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if i128::from(fs.f_type) != i128::from(libc::CGROUP2_SUPER_MAGIC) {
            return Err(invalid("native group descriptor is not cgroup v2").into());
        }
        let group = Self {
            path: path.to_owned(),
            identity: identity.clone(),
            directory,
        };
        group.verify()?;
        Ok(group)
    }

    pub(crate) fn identity(&self) -> PathIdentity {
        self.identity.clone()
    }

    pub(crate) fn verify(&self) -> Result<()> {
        if !PathIdentity::verify(&self.path, Some(&self.identity), false)?
            || !self.identity.matches(&self.directory.metadata()?)
        {
            return Err(invalid("acknowledged cgroup object no longer exists at its path").into());
        }
        Ok(())
    }

    pub(crate) fn file(&self, name: &str, write: bool) -> Result<File> {
        self.verify()?;
        let file = open_beneath(
            &self.directory,
            name,
            if write {
                libc::O_WRONLY
            } else {
                libc::O_RDONLY
            },
        )?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.dev() != self.directory.metadata()?.dev()
        {
            return Err(invalid("invalid cgroup descriptor member").into());
        }
        self.verify()?;
        Ok(file)
    }

    pub(crate) fn read(&self, name: &str) -> Result<String> {
        let mut value = String::new();
        self.file(name, false)?
            .take(65537)
            .read_to_string(&mut value)?;
        if value.len() > 65536 {
            return Err(invalid("cgroup observation exceeds limit").into());
        }
        self.verify()?;
        Ok(value)
    }

    pub(crate) fn write(&self, name: &str, value: &[u8]) -> Result<()> {
        self.file(name, true)?.write_all(value)?;
        self.verify()
    }

    pub(crate) fn empty(&self) -> Result<bool> {
        Ok(self
            .read("cgroup.events")?
            .lines()
            .any(|line| line == "populated 0"))
    }

    pub(crate) fn remove_empty(&self) -> Result<()> {
        self.verify()?;
        if !self.empty()? {
            return Err(invalid("acknowledged cgroup remains populated").into());
        }
        std::fs::remove_dir(&self.path)?;
        if !super::recovery::absent(&self.path)? {
            return Err(invalid("acknowledged cgroup path collection unconfirmed").into());
        }
        Ok(())
    }
}

pub(crate) fn recorded(
    path: &Path,
    identity: Option<&PathIdentity>,
    owner: &VmOwner,
) -> Result<Option<Group>> {
    if super::recovery::absent(path)? {
        return Ok(None);
    }
    if owner.host_boot_id != boot_id()? {
        return Err(invalid("another host boot cannot authorize a cgroup").into());
    }
    let identity = identity.ok_or_else(|| invalid("cgroup inode receipt is unrecorded"))?;
    Ok(Some(Group::open(path, identity)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn actual_openat2_descriptor_reads_original_directory_and_refuses_links_and_escape() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("original");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("value"), b"original").unwrap();
        symlink("value", path.join("link")).unwrap();
        let directory = File::open(&path).unwrap();
        for name in ["", ".", "..", "../value", "/value", "link"] {
            assert!(open_beneath(&directory, name, libc::O_RDONLY).is_err());
        }
        std::fs::rename(&path, fixture.path().join("retained")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("value"), b"replacement").unwrap();
        let mut value = String::new();
        open_beneath(&directory, "value", libc::O_RDONLY)
            .unwrap()
            .read_to_string(&mut value)
            .unwrap();
        assert_eq!(value, "original");
        assert_eq!(std::fs::read(path.join("value")).unwrap(), b"replacement");
        drop(directory);
        let path = fixture.path().to_owned();
        fixture.close().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn ordinary_directory_cannot_supply_kernel_cgroup_authority() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(fixture.path().join("cgroup.kill"), b"preserved").unwrap();
        assert!(Group::capture(fixture.path()).is_err());
        assert_eq!(
            std::fs::read(fixture.path().join("cgroup.kill")).unwrap(),
            b"preserved"
        );
        let path = fixture.path().to_owned();
        fixture.close().unwrap();
        assert!(!path.exists());
    }
}
