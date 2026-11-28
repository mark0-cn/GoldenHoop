use super::*;
use crate::rootfs::storage::RootfsBootTarget;

impl NativeEngine {
    pub(in crate::lifecycle) async fn rootfs_boot(
        &self,
        request: &RootfsBootRequest,
    ) -> std::result::Result<RuntimeHandle, ApiError> {
        self.create_with_input(
            &request.sandbox,
            &request.request,
            None,
            None,
            Some(request),
        )
        .await
    }
    pub(super) fn rootfs_boot_binding(
        &self,
        request: &RootfsBootRequest,
    ) -> Result<RootfsBootBinding> {
        let digest = request.digest()?;
        let cfg = &self.inner.cfg;
        if cfg.record_path(request.sandbox.id).try_exists()? {
            let record = self.load(request.sandbox.id)?;
            let binding = record.rootfs_boot.as_ref().ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Conflict,
                    "native target belongs to another boot kind",
                )
            })?;
            if record.owner.request_sha256 != digest
                || record.owner.expires_at != request.sandbox.expires_at
                || binding.target.reference != request.reference
                || binding.target.operation != request.operation
            {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "native rootfs target has a different immutable intent",
                )
                .into());
            }
            return Ok(binding.clone());
        }
        let manifest = cfg
            .rootfs_store()?
            .manifest_for_boot(&request.reference, &cfg.rootfs_boot_contract()?)?;
        let expected = native_handle(
            manifest.intent.source.installation,
            manifest.intent.source.sandbox,
            manifest.intent.source.source_generation,
        );
        if request
            .expected_source
            .as_ref()
            .is_some_and(|value| value != &expected)
        {
            return Err(ApiError::new(
                ErrorCode::Conflict,
                "rootfs captured source generation differs",
            )
            .into());
        }
        let generation = Uuid::new_v4();
        Ok(RootfsBootBinding {
            target: RootfsBootTarget::observe(
                request.reference.clone(),
                request.operation,
                request.sandbox.id,
                generation,
                digest,
                cfg.paths(generation)?.root,
            )?,
            manifest,
        })
    }
    pub(super) async fn rootfs_supervisor_input(
        &self,
        binding: &RootfsBootBinding,
    ) -> Result<File> {
        let store = self.inner.cfg.rootfs_store()?;
        let boot = self.inner.cfg.rootfs_boot_contract()?;
        // This acknowledged mutation runs before yielding to a read-only worker;
        // dropping an IPC future cannot leave a late reservation writer.
        store.reserve_boot(binding.target.clone(), &boot)?;
        let permit = self
            .inner
            .capture_slot
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::BackendUnavailable,
                    "rootfs source verification worker is reserved",
                )
            })?;
        let target = binding.target.clone();
        let reader = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            store.boot_reader(&target, &boot)
        })
        .await??;
        reader.supervisor_lock()
    }
    pub(super) async fn close_collected_rootfs_boot(&self, record: &VmJournal) -> Result<()> {
        let Some(binding) = &record.rootfs_boot else {
            return Ok(());
        };
        if !self.physical_absence(record)? {
            return Err(invalid("rootfs native target physical collection is unconfirmed").into());
        }
        let proof = CollectedRootfsBoot::observe(&self.inner.cfg, record)?;
        self.inner
            .cfg
            .rootfs_store()?
            .close_collected_boot(&binding.target, &proof)
    }
}
