//! Deliberately small bindings to the pinned Firecracker v1.18.0 API. These
//! validate wire shape, not image trust, host resource enforcement or VM boot.
use goldenhoop_protocol::{ApiError, ErrorCode};
use serde::{Deserialize, Serialize};

fn invalid(message: &'static str) -> ApiError {
    ApiError::new(ErrorCode::InvalidRequest, message)
}

fn jail_path(path: &str) -> Result<(), ApiError> {
    if path.len() > 4096
        || !path.starts_with('/')
        || path[1..].split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || component.chars().any(char::is_control)
                || component.contains('\\')
        })
    {
        return Err(invalid("invalid jailed VMM file path"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum InstanceState {
    #[serde(rename = "Not started")]
    NotStarted,
    Running,
    Paused,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceInfo {
    pub app_name: String,
    pub id: String,
    pub state: InstanceState,
    pub vmm_version: String,
}

#[derive(Debug, Serialize)]
pub struct MachineConfiguration {
    vcpu_count: u8,
    mem_size_mib: u64,
    smt: bool,
    track_dirty_pages: bool,
}

impl MachineConfiguration {
    pub fn new(vcpu_count: u8, mem_size_mib: u64) -> Result<Self, ApiError> {
        if vcpu_count == 0 || mem_size_mib == 0 {
            return Err(invalid("VM CPU and memory must be positive"));
        }
        Ok(Self {
            vcpu_count,
            mem_size_mib,
            smt: false,
            track_dirty_pages: false,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct BootSource {
    kernel_image_path: String,
    boot_args: String,
}

impl BootSource {
    pub fn new(kernel_image_path: String, boot_args: String) -> Result<Self, ApiError> {
        jail_path(&kernel_image_path)?;
        if boot_args.len() > 4096 || boot_args.chars().any(char::is_control) {
            return Err(invalid("invalid VM kernel arguments"));
        }
        Ok(Self {
            kernel_image_path,
            boot_args,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct RootDrive {
    drive_id: &'static str,
    path_on_host: String,
    is_root_device: bool,
    is_read_only: bool,
    io_engine: &'static str,
    cache_type: &'static str,
}

impl RootDrive {
    pub fn new(path: String, read_only: bool) -> Result<Self, ApiError> {
        jail_path(&path)?;
        Ok(Self {
            drive_id: "rootfs",
            path_on_host: path,
            is_root_device: true,
            is_read_only: read_only,
            io_engine: "Sync",
            cache_type: "Writeback",
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Vsock {
    guest_cid: u32,
    uds_path: String,
}

impl Vsock {
    pub fn new(guest_cid: u32, uds_path: String) -> Result<Self, ApiError> {
        jail_path(&uds_path)?;
        if guest_cid < 3 || guest_cid == u32::MAX {
            return Err(invalid("invalid guest vsock CID"));
        }
        Ok(Self {
            guest_cid,
            uds_path,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct SnapshotCreate {
    snapshot_type: &'static str,
    snapshot_path: String,
    mem_file_path: String,
    sync_snapshot_files: bool,
}

impl SnapshotCreate {
    pub fn full(snapshot_path: String, mem_file_path: String) -> Result<Self, ApiError> {
        jail_path(&snapshot_path)?;
        jail_path(&mem_file_path)?;
        if snapshot_path == mem_file_path {
            return Err(invalid("VM state and memory must use different files"));
        }
        Ok(Self {
            snapshot_type: "Full",
            snapshot_path,
            mem_file_path,
            sync_snapshot_files: true,
        })
    }
}

#[derive(Debug, Serialize)]
struct MemoryBackend {
    backend_type: &'static str,
    backend_path: String,
}

#[derive(Debug, Serialize)]
pub struct SnapshotLoad {
    snapshot_path: String,
    mem_backend: MemoryBackend,
    resume_vm: bool,
    track_dirty_pages: bool,
}

impl SnapshotLoad {
    /// Always restore paused so the driver can rotate identity and authority
    /// before any untrusted execution. An API acknowledgement is not restore proof.
    pub fn paused(snapshot_path: String, memory_path: String) -> Result<Self, ApiError> {
        jail_path(&snapshot_path)?;
        jail_path(&memory_path)?;
        if snapshot_path == memory_path {
            return Err(invalid("VM state and memory must use different files"));
        }
        Ok(Self {
            snapshot_path,
            mem_backend: MemoryBackend {
                backend_type: "File",
                backend_path: memory_path,
            },
            resume_vm: false,
            track_dirty_pages: false,
        })
    }
}
