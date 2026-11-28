//! Disk-only filesystem barriers are distinct from memory continuation receipts.
use super::{GUEST_CONTROL_VERSION, GuestBarrierPhase};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestFilesystemState {
    NotDispatched,
    Frozen,
    Thawed,
    Unknown,
}

/// The pinned descriptor of the original guest ext4 root, not a host pathname.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRootFilesystem {
    pub device: u64,
    pub inode: u64,
    pub mount_id: u64,
}
impl GuestRootFilesystem {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.device == 0 || self.inode != 2 || self.mount_id == 0 {
            return Err("invalid guest ext4 root descriptor identity");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRootfsBarrierInfo {
    pub protocol: u16,
    pub format: u32,
    pub generation: Uuid,
    pub barrier: Uuid,
    pub phase: GuestBarrierPhase,
    pub workload_frozen: bool,
    pub filesystem: GuestFilesystemState,
    pub root: Option<GuestRootFilesystem>,
    /// A capture can never be reopened after any thaw attempt, even on error.
    pub thaw_started: bool,
}
impl GuestRootfsBarrierInfo {
    pub fn validate(&self, generation: Uuid, barrier: Uuid) -> Result<(), &'static str> {
        if let Some(root) = &self.root {
            root.validate()?;
        }
        if generation.is_nil()
            || barrier.is_nil()
            || self.protocol != GUEST_CONTROL_VERSION
            || self.format != 1
            || self.generation != generation
            || self.barrier != barrier
            || matches!(
                self.filesystem,
                GuestFilesystemState::Frozen | GuestFilesystemState::Thawed
            ) && self.root.is_none()
            || match self.phase {
                GuestBarrierPhase::Quiesced => {
                    self.thaw_started
                        || !self.workload_frozen
                        || self.filesystem != GuestFilesystemState::Frozen
                }
                GuestBarrierPhase::Resumed => {
                    !self.thaw_started
                        || self.workload_frozen
                        || !matches!(
                            self.filesystem,
                            GuestFilesystemState::Thawed | GuestFilesystemState::NotDispatched
                        )
                }
                GuestBarrierPhase::Quiescing => {
                    self.thaw_started || self.filesystem == GuestFilesystemState::Thawed
                }
                GuestBarrierPhase::Unknown => false,
            }
        {
            return Err("rootfs barrier identity, filesystem state or phase differs");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rootfs_control_frames_are_explicit_and_refuse_host_path_or_foreign_authority_fields() {
        let generation = Uuid::new_v4();
        let barrier = Uuid::new_v4();
        for method in ["rootfs_quiesce", "rootfs_status", "rootfs_thaw"] {
            let value = serde_json::json!({"guest_control":method,"generation":generation,"barrier":barrier});
            let _: super::super::GuestControlRequest =
                serde_json::from_value(value.clone()).unwrap();
            for field in ["host_path", "mount", "target_generation"] {
                let mut bad = value.clone();
                bad[field] = serde_json::json!("untrusted");
                assert!(serde_json::from_value::<super::super::GuestControlRequest>(bad).is_err());
            }
        }
    }
    #[test]
    fn cold_barrier_cannot_substitute_sync_only_memory_receipts_or_unknown_freeze() {
        let generation = Uuid::new_v4();
        let barrier = Uuid::new_v4();
        let good = GuestRootfsBarrierInfo {
            protocol: GUEST_CONTROL_VERSION,
            format: 1,
            generation,
            barrier,
            phase: GuestBarrierPhase::Quiesced,
            workload_frozen: true,
            filesystem: GuestFilesystemState::Frozen,
            root: Some(GuestRootFilesystem {
                device: 254,
                inode: 2,
                mount_id: 17,
            }),
            thaw_started: false,
        };
        good.validate(generation, barrier).unwrap();
        assert!(good.validate(Uuid::new_v4(), barrier).is_err());
        assert!(good.validate(generation, Uuid::new_v4()).is_err());
        for state in [
            GuestFilesystemState::NotDispatched,
            GuestFilesystemState::Unknown,
            GuestFilesystemState::Thawed,
        ] {
            let mut bad = good.clone();
            bad.filesystem = state;
            assert!(bad.validate(generation, barrier).is_err());
        }
        let mut bad = good.clone();
        bad.thaw_started = true;
        assert!(bad.validate(generation, barrier).is_err());
        let mut bad = good.clone();
        bad.root = None;
        assert!(bad.validate(generation, barrier).is_err());
        let memory = super::super::GuestBarrierInfo {
            protocol: GUEST_CONTROL_VERSION,
            generation,
            barrier,
            phase: GuestBarrierPhase::Quiesced,
            workload_frozen: true,
            rootfs_synced: true,
        };
        assert!(
            serde_json::from_value::<GuestRootfsBarrierInfo>(serde_json::to_value(memory).unwrap())
                .is_err()
        );
        let mut thawed = good;
        thawed.phase = GuestBarrierPhase::Resumed;
        thawed.thaw_started = true;
        thawed.workload_frozen = false;
        thawed.filesystem = GuestFilesystemState::Thawed;
        thawed.validate(generation, barrier).unwrap();
        thawed.filesystem = GuestFilesystemState::Unknown;
        assert!(thawed.validate(generation, barrier).is_err());
    }
}
