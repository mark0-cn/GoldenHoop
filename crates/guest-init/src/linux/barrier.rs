//! PID1 remains runnable while its agent and every workload descendant freeze.
//! Closing admission is independent of an RPC future: cancellation never reopens it.
use super::{WORKLOAD_GROUP, invalid};
use goldenhoop_firecracker::control::{
    GUEST_CONTROL_VERSION, GuestBarrierInfo, GuestBarrierPhase, GuestControlRequest,
};
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::sync::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use uuid::Uuid;

const LIMIT: Duration = Duration::from_secs(10);

pub(super) struct Admission {
    open: AtomicBool,
    uncertain: AtomicBool,
    effects: RwLock<()>,
}
pub(super) struct Effect<'a> {
    admission: &'a Admission,
    _guard: RwLockReadGuard<'a, ()>,
    dispatched: bool,
    confirmed: bool,
}
impl Effect<'_> {
    pub(super) fn dispatched(&mut self) {
        self.dispatched = true;
    }
    pub(super) fn confirmed(&mut self) {
        self.confirmed = true;
    }
}
impl Drop for Effect<'_> {
    fn drop(&mut self) {
        if self.dispatched && !self.confirmed {
            // Closing a socket or cancelling a future does not undo an agent
            // effect. No later barrier may call this request drained.
            self.admission.uncertain.store(true, Ordering::SeqCst);
        }
    }
}
impl Admission {
    fn new() -> Self {
        Self {
            open: AtomicBool::new(true),
            uncertain: AtomicBool::new(false),
            effects: RwLock::new(()),
        }
    }
    pub(super) async fn enter(&self) -> io::Result<Effect<'_>> {
        if !self.open.load(Ordering::SeqCst) {
            return Err(invalid("guest workload admission is closed"));
        }
        let guard = self.effects.read().await;
        if !self.open.load(Ordering::SeqCst) {
            return Err(invalid("guest workload admission is closed"));
        }
        Ok(Effect {
            admission: self,
            _guard: guard,
            dispatched: false,
            confirmed: false,
        })
    }
    fn close(&self) {
        self.open.store(false, Ordering::SeqCst);
    }
    async fn drain(&self) -> io::Result<RwLockWriteGuard<'_, ()>> {
        let guard = tokio::time::timeout(LIMIT, self.effects.write())
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "guest request drain unconfirmed")
            })?;
        if self.uncertain.load(Ordering::SeqCst) {
            return Err(invalid("an earlier guest agent effect remains unconfirmed"));
        }
        Ok(guard)
    }
}

#[derive(Default)]
struct State {
    active: Option<GuestBarrierInfo>,
    // A resumed operation cannot become a fresh capture with a stale identifier.
    // Bounded by refusal rather than forgetting earlier acknowledgements.
    seen: HashSet<Uuid>,
}

pub(super) struct Barrier {
    generation: Option<Uuid>,
    agent_pid: u32,
    pub(super) admission: Admission,
    state: Mutex<State>,
}
impl Barrier {
    pub(super) fn new(generation: Option<Uuid>, agent_pid: u32) -> io::Result<Self> {
        if !crate::is_guest_init_context() || agent_pid <= 1 {
            return Err(invalid("guest barrier requires root PID1 and its agent"));
        }
        Ok(Self {
            generation,
            agent_pid,
            admission: Admission::new(),
            state: Mutex::new(State::default()),
        })
    }

    fn membership(&self) -> io::Result<()> {
        if !crate::is_guest_init_context()
            || bounded_read("/proc/1/cgroup")?.trim() != "0::/goldenhoop/control"
            || bounded_read(&format!("/proc/{}/cgroup", self.agent_pid))?.trim()
                != "0::/goldenhoop/workloads"
        {
            return Err(invalid(
                "guest control or agent task-group membership changed",
            ));
        }
        Ok(())
    }

    fn observe(&self, info: &mut GuestBarrierInfo) -> io::Result<()> {
        let frozen = match self.membership().and_then(|()| frozen()) {
            Ok(value) => value,
            Err(error) => {
                info.phase = GuestBarrierPhase::Unknown;
                info.rootfs_synced = false;
                self.admission.close();
                return Err(error);
            }
        };
        info.workload_frozen = frozen;
        if (info.phase == GuestBarrierPhase::Quiesced && !frozen)
            || (info.phase == GuestBarrierPhase::Resumed && frozen)
        {
            info.phase = GuestBarrierPhase::Unknown;
            info.rootfs_synced = false;
            self.admission.close();
        }
        Ok(())
    }

    pub(super) async fn request(
        &self,
        request: GuestControlRequest,
    ) -> io::Result<GuestBarrierInfo> {
        let (generation, barrier) = match request {
            GuestControlRequest::Quiesce {
                generation,
                barrier,
            }
            | GuestControlRequest::BarrierStatus {
                generation,
                barrier,
            }
            | GuestControlRequest::Thaw {
                generation,
                barrier,
            } => (generation, barrier),
            GuestControlRequest::Info => return Err(invalid("not a guest barrier request")),
        };
        if generation.is_nil() || barrier.is_nil() || self.generation != Some(generation) {
            return Err(invalid("guest barrier generation or operation differs"));
        }
        let mut state = self.state.lock().await;
        if matches!(request, GuestControlRequest::Quiesce { .. }) {
            if state
                .active
                .as_ref()
                .is_some_and(|info| info.barrier == barrier)
            {
                let info = state.active.as_mut().expect("active barrier");
                self.observe(info)?;
                if info.phase == GuestBarrierPhase::Resumed {
                    return Err(invalid("resumed guest barrier cannot be reused"));
                }
                if info.phase == GuestBarrierPhase::Quiesced {
                    return Ok(info.clone());
                }
            } else {
                if state
                    .active
                    .as_ref()
                    .is_some_and(|info| info.phase != GuestBarrierPhase::Resumed)
                    || state.seen.contains(&barrier)
                    || state.seen.len() >= 128
                {
                    return Err(invalid("guest barrier is active, spent or exhausted"));
                }
                state.seen.insert(barrier);
                state.active = Some(GuestBarrierInfo {
                    protocol: GUEST_CONTROL_VERSION,
                    generation,
                    barrier,
                    phase: GuestBarrierPhase::Quiescing,
                    workload_frozen: false,
                    rootfs_synced: false,
                });
            }
            self.admission.close();
            let info = state.active.as_mut().expect("active barrier");
            info.phase = GuestBarrierPhase::Quiescing;
            info.rootfs_synced = false;
            let outcome = async {
                let _drained = self.admission.drain().await?;
                self.membership()?;
                set_frozen(true).await?;
                // The agent (including its asynchronous jobs) is frozen too.
                // PID1 alone performs syncfs; tmpfs state belongs to memory capture.
                // No extra task is needed when the guest is at its task limit.
                // A slow/failed sync produces no acknowledgement; the host must
                // keep the barrier unconfirmed rather than assume completion.
                sync_root()?;
                self.membership()?;
                if !frozen()? {
                    return Err(invalid("guest tasks thawed during rootfs sync"));
                }
                Ok::<(), io::Error>(())
            }
            .await;
            if let Err(error) = outcome {
                info.phase = GuestBarrierPhase::Unknown;
                return Err(error);
            }
            info.phase = GuestBarrierPhase::Quiesced;
            info.workload_frozen = true;
            info.rootfs_synced = true;
            return Ok(info.clone());
        }
        let info = state
            .active
            .as_mut()
            .filter(|info| info.barrier == barrier)
            .ok_or_else(|| invalid("guest barrier is not the current operation"))?;
        self.observe(info)?;
        if matches!(request, GuestControlRequest::BarrierStatus { .. }) {
            return Ok(info.clone());
        }
        if info.phase != GuestBarrierPhase::Resumed {
            self.admission.close();
            // Invalidate the capture observation before any thaw side effect.
            info.phase = GuestBarrierPhase::Unknown;
            info.rootfs_synced = false;
            // Explicit thaw is allowed even if a prior agent request is
            // uncertain. It resumes the source; it does not clear that fence.
            let _drained = tokio::time::timeout(LIMIT, self.admission.effects.write())
                .await
                .map_err(|_| invalid("guest thaw request drain unconfirmed"))?;
            self.membership()?;
            set_frozen(false).await?;
            info.phase = GuestBarrierPhase::Resumed;
            info.workload_frozen = false;
            self.admission.open.store(true, Ordering::SeqCst);
        }
        Ok(info.clone())
    }
}

fn bounded_read(path: &str) -> io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut value = String::new();
    file.take(4097).read_to_string(&mut value)?;
    if value.len() > 4096 {
        return Err(invalid("guest barrier observation exceeds limit"));
    }
    Ok(value)
}
fn parse_frozen(events: &str) -> io::Result<bool> {
    let mut found = None;
    for line in events.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some("frozen") {
            let value = match fields.next() {
                Some("0") => false,
                Some("1") => true,
                _ => return Err(invalid("invalid guest frozen state")),
            };
            if found.replace(value).is_some() || fields.next().is_some() {
                return Err(invalid("ambiguous guest frozen state"));
            }
        }
    }
    found.ok_or_else(|| invalid("guest frozen state missing"))
}
fn frozen() -> io::Result<bool> {
    parse_frozen(&bounded_read(&format!("{WORKLOAD_GROUP}/cgroup.events"))?)
}
async fn set_frozen(value: bool) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(format!("{WORKLOAD_GROUP}/cgroup.freeze"))?;
    file.write_all(if value { b"1" } else { b"0" })?;
    let deadline = tokio::time::Instant::now() + LIMIT;
    while frozen()? != value {
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guest freezer transition unconfirmed",
            ));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}
fn sync_root() -> io::Result<()> {
    let root: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    // SAFETY: this is a live owned descriptor of the guest root filesystem.
    if unsafe { libc::syncfs(root.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn closure_excludes_new_effects_and_drain_waits_for_the_accepted_effect() {
        let gate = Admission::new();
        let accepted = gate.enter().await.unwrap();
        gate.close();
        assert!(gate.enter().await.is_err());
        assert!(gate.effects.try_write().is_err());
        drop(accepted);
        let drained = gate.drain().await.unwrap();
        gate.open.store(true, Ordering::SeqCst);
        assert!(gate.effects.try_read().is_err());
        drop(drained);
        assert!(gate.enter().await.is_ok());
    }
    #[tokio::test]
    async fn cancelled_drain_does_not_reopen_admission() {
        let gate = Admission::new();
        let accepted = gate.enter().await.unwrap();
        gate.close();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), gate.drain())
                .await
                .is_err()
        );
        assert!(gate.enter().await.is_err());
        drop(accepted);
        drop(gate.drain().await.unwrap());
        assert!(gate.enter().await.is_err());
    }
    #[tokio::test]
    async fn dispatched_without_a_reply_remains_uncertain_after_the_future_is_dropped() {
        let gate = Admission::new();
        let mut effect = gate.enter().await.unwrap();
        effect.dispatched();
        drop(effect);
        gate.close();
        assert!(gate.drain().await.is_err());
        // A deliberate source thaw/reopen does not pretend to reconcile it.
        gate.open.store(true, Ordering::SeqCst);
        let mut later = gate.enter().await.unwrap();
        later.dispatched();
        later.confirmed();
        drop(later);
        gate.close();
        assert!(gate.drain().await.is_err());
    }
    #[tokio::test]
    async fn a_complete_agent_reply_allows_drain_including_a_rejected_request() {
        let gate = Admission::new();
        let mut effect = gate.enter().await.unwrap();
        effect.dispatched();
        effect.confirmed();
        drop(effect);
        gate.close();
        assert!(gate.drain().await.is_ok());
    }
    #[test]
    fn freezer_observation_requires_one_explicit_kernel_state() {
        assert!(!parse_frozen("populated 1\nfrozen 0\n").unwrap());
        assert!(parse_frozen("frozen 1\npopulated 1\n").unwrap());
        for bad in [
            "",
            "populated 1",
            "frozen",
            "frozen 2",
            "frozen 1 extra",
            "frozen 1\nfrozen 1",
        ] {
            assert!(parse_frozen(bad).is_err(), "{bad}");
        }
    }
}
