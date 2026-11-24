use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use goldenhoop_protocol::{ApiError, ErrorCode, FileInfo, FileKind};
use uuid::Uuid;

const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

pub struct Workspace {
    dir: Dir,
    owner: Option<(u32, u32)>,
}

fn io_error(error: std::io::Error) -> ApiError {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorCode::Forbidden,
        std::io::ErrorKind::AlreadyExists => ErrorCode::Conflict,
        std::io::ErrorKind::InvalidInput => ErrorCode::InvalidRequest,
        _ => ErrorCode::Internal,
    };
    ApiError::new(code, format!("workspace operation: {error}"))
}

impl Workspace {
    pub fn open(root: &Path, owner: Option<(u32, u32)>) -> Result<Self, ApiError> {
        Ok(Self {
            dir: Dir::open_ambient_dir(root, ambient_authority()).map_err(io_error)?,
            owner,
        })
    }

    fn relative(path: &str, allow_root: bool) -> Result<PathBuf, ApiError> {
        if path.contains(['\0', '\\']) {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "invalid workspace path",
            ));
        }
        let path = path.strip_prefix("/workspace/").unwrap_or(path);
        let path = if path == "/workspace" { "." } else { path };
        let mut result = PathBuf::new();
        for component in Path::new(path).components() {
            match component {
                Component::Normal(part) => result.push(part),
                Component::CurDir => {}
                _ => {
                    return Err(ApiError::new(
                        ErrorCode::Forbidden,
                        "path escapes workspace",
                    ));
                }
            }
        }
        if result.as_os_str().is_empty() {
            if allow_root {
                return Ok(PathBuf::from("."));
            }
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "a file path is required",
            ));
        }
        Ok(result)
    }

    #[cfg(unix)]
    fn set_owner(&self, file: &cap_std::fs::File) -> Result<(), ApiError> {
        if let Some((uid, gid)) = self.owner {
            // SAFETY: this is an owned, already-open descriptor within the authorized root.
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            let mode = if file.metadata().map_err(io_error)?.is_dir() {
                0o2770
            } else {
                0o660
            };
            // SAFETY: this is the same owned workspace descriptor. GID 1000 is
            // shared by commands and agent-assigned kernel identities.
            if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn set_owner<T>(&self, _file: &T) -> Result<(), ApiError> {
        let _ = self.owner;
        Ok(())
    }

    pub fn cwd_handle(&self, path: &str) -> Result<std::fs::File, ApiError> {
        Ok(self
            .dir
            .open_dir(Self::relative(path, true)?)
            .map_err(io_error)?
            .into_std_file())
    }

    pub fn write(&self, path: &str, data_base64: &str) -> Result<(), ApiError> {
        if data_base64.len() as u64 > MAX_FILE_BYTES.div_ceil(3) * 4 {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "file exceeds 16 MiB transfer limit",
            ));
        }
        let data = STANDARD
            .decode(data_base64)
            .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "invalid base64 file data"))?;
        if data.len() as u64 > MAX_FILE_BYTES {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "file exceeds 16 MiB transfer limit",
            ));
        }
        let relative = Self::relative(path, false)?;
        let mut parent = self.dir.try_clone().map_err(io_error)?;
        if let Some(ancestors) = relative.parent() {
            for part in ancestors.components() {
                let name = Path::new(part.as_os_str());
                parent = match parent.open_dir(name) {
                    Ok(directory) => directory,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        match parent.create_dir(name) {
                            Ok(()) => {}
                            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                            Err(error) => return Err(io_error(error)),
                        }
                        parent.open_dir(name).map_err(io_error)?
                    }
                    Err(error) => return Err(io_error(error)),
                };
                // cap-std directory handles may be O_PATH descriptors on Linux.
                // fchown requires an ordinary open descriptor instead.
                #[cfg(unix)]
                self.set_owner(&parent.open(".").map_err(io_error)?)?;
            }
        }
        let name = relative
            .file_name()
            .ok_or_else(|| ApiError::new(ErrorCode::InvalidRequest, "file name is required"))?;
        let temporary = format!(".goldenhoop-{}", Uuid::new_v4());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let outcome = (|| {
            let mut file = parent.open_with(&temporary, &options).map_err(io_error)?;
            self.set_owner(&file)?;
            file.write_all(&data).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            parent.rename(&temporary, &parent, name).map_err(io_error)
        })();
        if outcome.is_err() {
            let _ = parent.remove_file(&temporary);
        }
        outcome
    }

    pub fn read(&self, path: &str, max_bytes: u64) -> Result<String, ApiError> {
        if max_bytes == 0 || max_bytes > MAX_FILE_BYTES {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "file read limit must be 1..16777216",
            ));
        }
        let path = Self::relative(path, false)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = self
            .dir
            .open_with(path, &options)
            .map_err(io_error)?
            .into_std();
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file() {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "only regular files can be read",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() > 1 {
                return Err(ApiError::new(
                    ErrorCode::Forbidden,
                    "hard-linked files cannot be exported",
                ));
            }
        }
        if metadata.len() > max_bytes {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "file exceeds requested transfer limit",
            ));
        }
        let mut bytes = Vec::new();
        file.take(max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() as u64 > max_bytes {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "file grew beyond transfer limit",
            ));
        }
        Ok(STANDARD.encode(bytes))
    }

    pub fn list(&self, path: &str) -> Result<Vec<FileInfo>, ApiError> {
        let relative = Self::relative(path, true)?;
        let mut entries = Vec::new();
        for entry in self
            .dir
            .open_dir(&relative)
            .map_err(io_error)?
            .entries()
            .map_err(io_error)?
        {
            if entries.len() == 1_000 {
                return Err(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "directory exceeds 1000 entries",
                ));
            }
            let entry = entry.map_err(io_error)?;
            let kind = entry.file_type().map_err(io_error)?;
            let kind = if kind.is_symlink() {
                FileKind::Symlink
            } else if kind.is_dir() {
                FileKind::Directory
            } else if kind.is_file() {
                FileKind::File
            } else {
                FileKind::Other
            };
            entries.push(FileInfo {
                path: relative
                    .join(entry.file_name())
                    .to_string_lossy()
                    .into_owned(),
                kind,
                size: if kind == FileKind::File {
                    entry.metadata().map_err(io_error)?.len()
                } else {
                    0
                },
            });
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    pub fn remove(&self, path: &str) -> Result<(), ApiError> {
        self.dir
            .remove_file(Self::relative(path, false)?)
            .map_err(io_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_roundtrip_and_traversal_refusal() {
        let root = tempfile::tempdir().unwrap();
        let workspace = Workspace::open(root.path(), None).unwrap();
        let data = STANDARD.encode([0, 255, 1, 10]);
        workspace.write("nested/data.bin", &data).unwrap();
        assert_eq!(
            workspace.read("/workspace/nested/data.bin", 64).unwrap(),
            data
        );
        assert!(workspace.read("../private", 64).is_err());
        assert!(workspace.write("/etc/passwd", &data).is_err());
        assert!(workspace.remove(".").is_err());
        assert_eq!(workspace.list(".").unwrap()[0].kind, FileKind::Directory);
    }
    #[test]
    #[cfg(unix)]
    fn symlink_and_hardlink_exports_do_not_escape_authorized_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "not exported").unwrap();
        let workspace = Workspace::open(root.path(), None).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
        assert!(workspace.read("escape/secret", 64).is_err());
        assert!(
            workspace
                .write("escape/overwrite", &STANDARD.encode("bad"))
                .is_err()
        );
        assert!(!outside.path().join("overwrite").exists());
        std::fs::hard_link(outside.path().join("secret"), root.path().join("hard")).unwrap();
        assert!(workspace.read("hard", 64).is_err());
    }
}
