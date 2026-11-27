//! Native restart observations. Receipts authorize only the same filesystem
//! object; process exit, a filename and a disconnected stream are not cleanup.
use super::*;
use goldenhoop_runtime::ObservedState;
use std::os::unix::fs::FileTypeExt;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PathIdentity {
    device: u64,
    inode: u64,
}
impl PathIdentity {
    pub(crate) fn matches(&self, value: &std::fs::Metadata) -> bool {
        self.device == value.dev() && self.inode == value.ino()
    }
    fn metadata(path: &Path, socket: bool) -> Result<std::fs::Metadata> {
        let value = std::fs::symlink_metadata(path)?;
        if value.uid() != 0
            || value.ino() == 0
            || value.file_type().is_symlink()
            || if socket {
                !value.file_type().is_socket() || value.mode() & 0o077 != 0 || value.nlink() != 1
            } else {
                !value.is_dir() || value.mode() & 0o022 != 0
            }
        {
            return Err(invalid("native control object ownership/type/mode differs").into());
        }
        Ok(value)
    }
    pub(crate) fn capture(path: &Path, socket: bool) -> Result<Self> {
        let value = Self::metadata(path, socket)?;
        Ok(Self {
            device: value.dev(),
            inode: value.ino(),
        })
    }
    pub(crate) fn verify(path: &Path, recorded: Option<&Self>, socket: bool) -> Result<bool> {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
            Ok(_) => (),
        }
        let value = Self::metadata(path, socket)?;
        if recorded
            .is_none_or(|expected| expected.device != value.dev() || expected.inode != value.ino())
        {
            return Err(invalid("native control object inode is unrecorded or differs").into());
        }
        Ok(true)
    }
}

pub(super) fn absent(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GenerationRecovery {
    pub sandbox_id: Uuid,
    pub generation: Uuid,
    pub previous_phase: String,
    pub previous_error_sha256: Option<String>,
    pub observed_state: ObservedState,
    pub authenticated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagerRecovery {
    pub previous_epoch: Uuid,
    pub previous_process: ProcessIdentity,
    pub observed_at: DateTime<Utc>,
    pub generations: Vec<GenerationRecovery>,
}
