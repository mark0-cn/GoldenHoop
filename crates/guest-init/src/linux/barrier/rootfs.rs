//! An explicit owner for the original guest root filesystem freeze.
//! Dropping an RPC/descriptor never performs an implicit thaw or reopens work.
use super::*;
use goldenhoop_firecracker::control::{
    GuestFilesystemState, GuestRootFilesystem, GuestRootfsBarrierInfo,
};
use std::os::unix::fs::MetadataExt;

struct Root {
    file: File,
    identity: GuestRootFilesystem,
}
impl Root {
    fn open() -> io::Result<Self> {
        if !crate::is_guest_init_context() {
            return Err(invalid("rootfs freeze requires guest root PID1"));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        let metadata = file.metadata()?;
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: the owned descriptor and output allocation remain valid.
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut filesystem) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut flags: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: use libc's public statvfs ABI, never statfs's reserved fields.
        if unsafe { libc::fstatvfs(file.as_raw_fd(), &mut flags) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if !metadata.is_dir()
            || metadata.uid() != 0
            || i128::from(filesystem.f_type) != 0xef53
            || flags.f_flag & libc::ST_RDONLY != 0
        {
            return Err(invalid(
                "rootfs barrier requires the writable ext4 guest root",
            ));
        }
        let fields = bounded_read(&format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
        let mut mount = fields
            .lines()
            .filter_map(|line| line.strip_prefix("mnt_id:"));
        let mount_id = mount
            .next()
            .ok_or_else(|| invalid("root descriptor mount identity missing"))?
            .trim()
            .parse()
            .map_err(|_| invalid("invalid root descriptor mount identity"))?;
        if mount.next().is_some() {
            return Err(invalid("ambiguous root descriptor mount identity"));
        }
        let identity = GuestRootFilesystem {
            device: metadata.dev(),
            inode: metadata.ino(),
            mount_id,
        };
        identity.validate().map_err(invalid)?;
        Ok(Self { file, identity })
    }
    fn verify(&self) -> io::Result<()> {
        let metadata = self.file.metadata()?;
        if metadata.dev() != self.identity.device
            || metadata.ino() != self.identity.inode
            || Self::open()?.identity != self.identity
        {
            return Err(invalid(
                "rootfs descriptor no longer names the original guest root",
            ));
        }
        Ok(())
    }
    fn change(&self, freeze: bool) -> io::Result<()> {
        self.verify()?;
        // Linux UAPI fs.h: _IOWR('X', 119/120, int). libc's encoder also
        // selects the correct ioctl request type/architecture for GNU/musl.
        let command = libc::_IOWR::<libc::c_int>(u32::from(b'X'), if freeze { 119 } else { 120 });
        // SAFETY: fixed no-payload ioctls on the pinned, verified guest root.
        // These calls have no await point; an uncertain/failed result remains
        // fenced. The host RPC deadline does not undo an in-flight kernel call.
        if unsafe { libc::ioctl(self.file.as_raw_fd(), command, 0 as libc::c_ulong) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub(super) struct Active {
    info: GuestRootfsBarrierInfo,
    root: Option<Root>,
}
impl Active {
    fn new(generation: Uuid, barrier: Uuid) -> Self {
        Self {
            info: GuestRootfsBarrierInfo {
                protocol: GUEST_CONTROL_VERSION,
                format: 1,
                generation,
                barrier,
                phase: GuestBarrierPhase::Quiescing,
                workload_frozen: false,
                filesystem: GuestFilesystemState::NotDispatched,
                root: None,
                thaw_started: false,
            },
            root: None,
        }
    }
    pub(super) fn blocks(&self) -> bool {
        self.info.phase != GuestBarrierPhase::Resumed
    }
    fn prepare_capture(&self) -> io::Result<bool> {
        if self.info.thaw_started
            || matches!(
                self.info.filesystem,
                GuestFilesystemState::Unknown | GuestFilesystemState::Thawed
            )
        {
            return Err(invalid(
                "rootfs barrier is uncertain or permanently closed for capture",
            ));
        }
        Ok(self.info.filesystem == GuestFilesystemState::NotDispatched)
    }
    fn begin_thaw(&mut self) -> io::Result<bool> {
        self.info.thaw_started = true;
        self.info.phase = GuestBarrierPhase::Unknown;
        if self.info.filesystem == GuestFilesystemState::Unknown {
            return Err(invalid(
                "rootfs freeze ownership is unconfirmed; source remains fenced",
            ));
        }
        Ok(self.info.filesystem == GuestFilesystemState::Frozen)
    }
    fn observe(&mut self, barrier: &Barrier) -> io::Result<()> {
        let observation = (|| {
            barrier.membership()?;
            if let Some(root) = &self.root {
                root.verify()?;
            }
            frozen()
        })();
        let observed = match observation {
            Ok(value) => value,
            Err(error) => {
                self.info.phase = GuestBarrierPhase::Unknown;
                barrier.admission.close();
                return Err(error);
            }
        };
        self.info.workload_frozen = observed;
        if (self.info.phase == GuestBarrierPhase::Quiesced && !observed)
            || (self.info.phase == GuestBarrierPhase::Resumed && observed)
        {
            self.info.phase = GuestBarrierPhase::Unknown;
            barrier.admission.close();
        }
        self.info
            .validate(self.info.generation, self.info.barrier)
            .map_err(invalid)
    }
}

pub(super) async fn request(
    barrier: &Barrier,
    request: GuestControlRequest,
) -> io::Result<GuestRootfsBarrierInfo> {
    #[derive(PartialEq)]
    enum Operation {
        Capture,
        Status,
        Thaw,
    }
    let (generation, id, operation) = match request {
        GuestControlRequest::RootfsQuiesce {
            generation,
            barrier,
        } => (generation, barrier, Operation::Capture),
        GuestControlRequest::RootfsStatus {
            generation,
            barrier,
        } => (generation, barrier, Operation::Status),
        GuestControlRequest::RootfsThaw {
            generation,
            barrier,
        } => (generation, barrier, Operation::Thaw),
        _ => return Err(invalid("not a rootfs barrier request")),
    };
    let mut state = barrier.state.lock().await;
    if generation.is_nil() || id.is_nil() || barrier.generation().await != Some(generation) {
        return Err(invalid("rootfs barrier generation or identity differs"));
    }
    if state
        .active
        .as_ref()
        .is_some_and(|info| info.phase != GuestBarrierPhase::Resumed)
    {
        return Err(invalid(
            "rootfs request is fenced by the active memory barrier",
        ));
    }
    if operation == Operation::Capture {
        let exact = state.rootfs.as_ref().is_some_and(|active| {
            active.info.barrier == id && active.info.generation == generation
        });
        if !exact {
            if state.rootfs.as_ref().is_some_and(Active::blocks)
                || state.seen.contains(&id)
                || state.seen.len() >= 128
            {
                return Err(invalid(
                    "rootfs barrier is active, spent, foreign or exhausted",
                ));
            }
            state.seen.insert(id);
            state.rootfs = Some(Active::new(generation, id));
        }
        let active = state.rootfs.as_mut().expect("original rootfs intent");
        let freeze_needed = active.prepare_capture()?;
        barrier.admission.close();
        if active.info.phase == GuestBarrierPhase::Quiesced {
            active.observe(barrier)?;
            if active.info.phase == GuestBarrierPhase::Quiesced {
                return Ok(active.info.clone());
            }
        }
        active.info.phase = GuestBarrierPhase::Quiescing;
        let outcome = async {
            let _drained = barrier.admission.drain().await?;
            barrier.membership()?;
            set_frozen(true).await?;
            active.info.workload_frozen = frozen()?;
            if !active.info.workload_frozen {
                return Err(invalid("rootfs workloads are not frozen"));
            }
            if active.root.is_none() {
                let root = Root::open()?;
                active.info.root = Some(root.identity.clone());
                active.root = Some(root);
            }
            let root = active.root.as_ref().expect("pinned guest root");
            if freeze_needed {
                // Record uncertainty before dispatch. EBUSY or another error
                // is never a successful freeze owned by this operation.
                active.info.filesystem = GuestFilesystemState::Unknown;
                root.change(true)?;
                active.info.filesystem = GuestFilesystemState::Frozen;
            }
            root.verify()?;
            barrier.membership()?;
            if !frozen()? {
                return Err(invalid("workloads thawed during rootfs freeze"));
            }
            Ok::<(), io::Error>(())
        }
        .await;
        if let Err(error) = outcome {
            active.info.phase = GuestBarrierPhase::Unknown;
            return Err(error);
        }
        active.info.phase = GuestBarrierPhase::Quiesced;
        active.observe(barrier)?;
        return Ok(active.info.clone());
    }
    let active = state
        .rootfs
        .as_mut()
        .filter(|active| active.info.generation == generation && active.info.barrier == id)
        .ok_or_else(|| invalid("rootfs barrier is not the original current operation"))?;
    if operation == Operation::Status || active.info.phase == GuestBarrierPhase::Resumed {
        active.observe(barrier)?;
        return Ok(active.info.clone());
    }
    barrier.admission.close();
    let thaw_needed = active.begin_thaw()?;
    active.observe(barrier)?;
    // Lost replies/cancelled futures preserve the original owner. A completed
    // filesystem thaw can be retried at the later workload-thaw boundary.
    let outcome = async {
        let _drained = tokio::time::timeout(LIMIT, barrier.admission.effects.write())
            .await
            .map_err(|_| invalid("rootfs thaw request drain unconfirmed"))?;
        barrier.membership()?;
        if thaw_needed {
            let root = active
                .root
                .as_ref()
                .ok_or_else(|| invalid("owned rootfs descriptor missing"))?;
            active.info.filesystem = GuestFilesystemState::Unknown;
            root.change(false)?;
            active.info.filesystem = GuestFilesystemState::Thawed;
        }
        if let Some(root) = &active.root {
            root.verify()?;
        }
        set_frozen(false).await?;
        barrier.membership()?;
        if frozen()? {
            return Err(invalid("rootfs workload thaw is unconfirmed"));
        }
        Ok::<(), io::Error>(())
    }
    .await;
    if let Err(error) = outcome {
        active.info.phase = GuestBarrierPhase::Unknown;
        return Err(error);
    }
    active.info.workload_frozen = false;
    active.info.phase = GuestBarrierPhase::Resumed;
    active.info.validate(generation, id).map_err(invalid)?;
    barrier.admission.open.store(true, Ordering::SeqCst);
    Ok(active.info.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn synthetic_rootfs_ledger_never_replays_uncertain_freezes_or_reopens_after_thaw() {
        let mut active = Active::new(Uuid::new_v4(), Uuid::new_v4());
        assert!(active.blocks());
        assert!(active.prepare_capture().unwrap());
        active.info.filesystem = GuestFilesystemState::Unknown;
        assert!(active.prepare_capture().is_err());
        assert!(active.begin_thaw().is_err());
        assert!(active.info.thaw_started && active.blocks());
        active.info.filesystem = GuestFilesystemState::Frozen;
        assert!(active.prepare_capture().is_err());
        assert!(active.begin_thaw().unwrap());
        active.info.filesystem = GuestFilesystemState::Thawed;
        assert!(!active.begin_thaw().unwrap());
        assert!(active.prepare_capture().is_err());
        active.info.phase = GuestBarrierPhase::Resumed;
        assert!(!active.blocks());
        assert!(active.prepare_capture().is_err());
    }
}
