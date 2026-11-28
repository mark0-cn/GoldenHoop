//! Original-VM disk-only capture and explicit source recovery. Callers retain
//! the original VM lease through this synchronous producer and all RPCs.
use super::*;
use crate::{
    checkpoint::CaptureIdentity,
    control::{GUEST_CONTROL_VERSION, GuestBarrierPhase},
    rootfs::{
        RootfsArtifact, RootfsBoot, RootfsCaptureIntent, RootfsOrigin, RootfsReference,
        storage::{RootfsCaptureSession, RootfsStore, RootfsStorePolicy, inspector_fingerprint},
    },
};
use goldenhoop_image_builder::{RootfsGuestConfig, RootfsInspectionInventory};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsCapturePolicy {
    pub store: RootfsStorePolicy,
    pub inventory: RootfsInspectionInventory,
    pub guest: RootfsGuestConfig,
    pub guest_config: RootfsArtifact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspector_image: Option<String>,
}
impl RootfsCapturePolicy {
    pub fn validate(&self) -> Result<()> {
        self.store.validate()?;
        self.inventory.validate()?;
        self.guest.validate()?;
        if self.inspector_image.as_deref().is_some_and(|v| {
            !v.strip_prefix("sha256:").is_some_and(|id| {
                id.len() == 64
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        }) {
            return Err(invalid("rootfs inspector requires an immutable daemon image ID").into());
        }
        if self.guest.control_port != 52
            || self.guest_config.size_bytes == 0
            || self.guest_config.size_bytes > 4096
            || self.guest_config.sha256.len() != 64
            || !self
                .guest_config
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("rootfs capture guest configuration differs").into());
        }
        Ok(())
    }
}
fn artifact(value: &goldenhoop_image_builder::Content) -> RootfsArtifact {
    RootfsArtifact {
        sha256: value.sha256.clone(),
        size_bytes: value.size_bytes,
    }
}

impl Machine {
    fn rootfs_source_disk(&self, input: &BootInput) -> Result<File> {
        self.check_expiry()?;
        self.root_handle
            .as_ref()
            .ok_or_else(|| invalid("rootfs original source root is unacknowledged"))?
            .verify()?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(self.jail.join("rootfs.ext4"))?;
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != VMM_UID
            || m.nlink() != 1
            || m.mode() & 0o6022 != 0
            || m.len() != input.rootfs.size
        {
            return Err(invalid("rootfs original source disk ownership or size differs").into());
        }
        Ok(file)
    }
    pub(crate) async fn reserve_rootfs(
        &self,
        input: &BootInput,
        capture: Uuid,
        policy: &RootfsCapturePolicy,
        store: &RootfsStore,
    ) -> Result<RootfsCaptureSession> {
        policy.validate()?;
        let record = self.record();
        if capture.is_nil() || record.capture_hold.is_some() || record.rootfs_hold.is_some() {
            return Err(invalid("rootfs source is already fenced or its capture ID is nil").into());
        }
        let api = self.capture_api(input)?;
        if api.instance_info().await?.state != InstanceState::Running {
            return Err(invalid("rootfs capture requires the original running source").into());
        }
        let control = AgentClient::new(
            api.clone(),
            self.jail.join("vsock.sock"),
            52,
            Duration::from_secs(20),
        )?
        .control_info()
        .await?;
        if control.pids != record.resources.pids {
            return Err(invalid("rootfs source guest task ceiling differs").into());
        }
        let origin = if let Some(image) = &record.selected_image {
            if image.manifest.agent != policy.inventory.agent
                || image.manifest.init != policy.inventory.init
            {
                return Err(invalid("rootfs prepared-source protected boot assets differ").into());
            }
            RootfsOrigin::Prepared {
                image: image.reference.id,
                generation: image.reference.generation,
                manifest_sha256: image.reference.manifest_sha256.clone(),
                disk: artifact(&image.manifest.disk),
            }
        } else {
            RootfsOrigin::Configured {
                disk: RootfsArtifact {
                    sha256: input.rootfs.sha256.clone(),
                    size_bytes: input.rootfs.size,
                },
            }
        };
        let intent = RootfsCaptureIntent {
            source: CaptureIdentity {
                installation: record.owner.installation_id,
                sandbox: record.owner.sandbox_id,
                source_generation: self.generation,
                capture,
                request_sha256: record.owner.request_sha256.clone(),
            },
            boot: RootfsBoot {
                firecracker_version: crate::api::SUPPORTED_VMM_VERSION.into(),
                firecracker_sha256: input.firecracker.sha256.clone(),
                jailer_sha256: input.jailer.sha256.clone(),
                kernel: RootfsArtifact {
                    sha256: input.kernel.sha256.clone(),
                    size_bytes: input.kernel.size,
                },
                architecture: std::env::consts::ARCH.into(),
                guest_control_version: GUEST_CONTROL_VERSION,
                agent: artifact(&policy.inventory.agent),
                init: artifact(&policy.inventory.init),
                guest_config: policy.guest_config.clone(),
                control_port: policy.guest.control_port,
                workload_pids: policy.guest.pids,
            },
            origin,
            barrier: Uuid::new_v4(),
            inspection_generation: Uuid::new_v4(),
            inspector_inventory_sha256: inspector_fingerprint(&policy.inventory)?,
            disk_id: Uuid::new_v4(),
            disk_bytes: input.rootfs.size,
        };
        let source = self.rootfs_source_disk(input)?;
        store.reserve(intent, api.peer_identity().pid, &source, VMM_UID)
    }
    /// Normal production path writes no workload marker and retains no RAM.
    pub(crate) async fn capture_rootfs(
        &self,
        input: &BootInput,
        session: &mut RootfsCaptureSession,
    ) -> Result<RootfsReference> {
        let intent = session.intent().clone();
        if intent.source.source_generation != self.generation
            || intent.source.sandbox != self.record().owner.sandbox_id
        {
            return Err(invalid("rootfs capture lease differs from the original source").into());
        }
        let source = self.rootfs_source_disk(input)?;
        session.validate_source(&source, VMM_UID)?;
        session.begin()?;
        let api = self.capture_api(input)?;
        if api.instance_info().await?.state != InstanceState::Running {
            return Err(invalid("rootfs capture source stopped running before freeze").into());
        }
        let agent = AgentClient::new(
            api.clone(),
            self.jail.join("vsock.sock"),
            52,
            Duration::from_secs(20),
        )?;
        let frozen = agent.rootfs_quiesce(intent.barrier).await?;
        frozen
            .validate(self.generation, intent.barrier)
            .map_err(invalid)?;
        session.pause_dispatched()?;
        api.pause().await?;
        if api.instance_info().await?.state != InstanceState::Paused {
            return Err(invalid("rootfs original VMM pause is unconfirmed").into());
        }
        session.pause_observed()?;
        let reference = session.capture(source, VMM_UID, frozen)?;
        self.check_expiry()?;
        if self.capture_api(input)?.instance_info().await?.state != InstanceState::Paused {
            return Err(invalid("rootfs original VMM pause changed during disk production").into());
        }
        Ok(reference)
    }
    /// Capture is already closed (Captured or Failed) before any source resume
    /// or thaw is attempted. A lost response is reconciled on the same owner.
    pub(crate) async fn recover_rootfs_source(
        &self,
        input: &BootInput,
        session: &mut RootfsCaptureSession,
    ) -> Result<()> {
        let intent = session.intent().clone();
        if intent.source.source_generation != self.generation
            || intent.source.sandbox != self.record().owner.sandbox_id
        {
            return Err(invalid("rootfs source recovery owner differs").into());
        }
        let source = self.rootfs_source_disk(input)?;
        session.validate_source(&source, VMM_UID)?;
        let api = self.capture_api(input)?;
        let control = session.vm_control().clone();
        match api.instance_info().await?.state {
            InstanceState::Paused => {
                if !control.pause_dispatched || control.resume_started {
                    return Err(invalid(
                        "rootfs pause ownership or prior resume remains unconfirmed",
                    )
                    .into());
                }
                if !control.pause_observed {
                    session.pause_observed()?;
                }
                session.resume_started()?;
                api.resume().await?;
            }
            InstanceState::Running => {
                if control.pause_dispatched && !control.resume_started {
                    return Err(invalid("running VMM does not settle a possibly delayed original pause; source remains fenced").into());
                }
            }
            _ => {
                return Err(
                    invalid("rootfs source cannot be recovered from this VMM state").into(),
                );
            }
        }
        if api.instance_info().await?.state != InstanceState::Running {
            return Err(invalid("rootfs VMM resume is unconfirmed").into());
        }
        if !session.source_resumed() {
            let agent = AgentClient::new(
                api.clone(),
                self.jail.join("vsock.sock"),
                52,
                Duration::from_secs(20),
            )?;
            let receipt = agent.rootfs_thaw(intent.barrier).await?;
            if receipt.phase != GuestBarrierPhase::Resumed {
                return Err(invalid("rootfs original guest recovery is unconfirmed").into());
            }
            let current = agent.rootfs_status(intent.barrier).await?;
            if current != receipt {
                return Err(invalid("rootfs guest recovery changed before acknowledgement").into());
            }
            let info = agent.control_info().await?;
            if info.generation != Some(self.generation) || info.pids != self.resources.pids {
                return Err(invalid("rootfs recovered guest authority or limits differ").into());
            }
            if !matches!(
                super::rpc(&agent, AgentRequest::Ping).await?,
                AgentResponse::Pong { .. }
            ) {
                return Err(invalid("rootfs recovered agent ping differs").into());
            }
            session.confirm_source_resumed(receipt)?;
        }
        self.check_expiry()?;
        if self.capture_api(input)?.instance_info().await?.state != InstanceState::Running {
            return Err(invalid("rootfs recovered source stopped running").into());
        }
        Ok(())
    }
}
