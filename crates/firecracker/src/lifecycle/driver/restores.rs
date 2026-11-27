//! Private native restoration admission. Only its supervisor consumes the claim.
use super::*;
use crate::checkpoint::storage::{CheckpointStore, Destination, restore::RestoreIntent};

impl NativeEngine {
    pub(super) async fn close_collected_restore(&self, record: &VmJournal) -> Result<()> {
        if let Some(binding) = &record.restore {
            if !self.physical_absence(record)? {
                return Err(invalid("native restore target is not physically collected").into());
            }
            if let Some(producer) = record.supervisor.clone() {
                // Collection can have advanced the durable journal since the
                // stop request. Only the completed collector's original
                // receipts can confirm the unacknowledged launch window.
                let current = self.load(record.owner.sandbox_id)?;
                if current.owner != record.owner
                    || current.restore != record.restore
                    || current.supervisor != record.supervisor
                {
                    return Err(invalid("native restoration changed during collection").into());
                }
                let collected =
                    if current.root_collection_started && current.vm_cgroup_identity.is_some() {
                        Some(CollectedNativeRestore::observe(&self.inner.cfg, &current)?)
                    } else {
                        None
                    };
                let checkpoint = self
                    .inner
                    .cfg
                    .checkpoint_config(binding.intent.reference.capture)?;
                let intent = binding.intent.clone();
                tokio::task::spawn_blocking(move || {
                    CheckpointStore::open_or_initialize(&checkpoint)?.close_native_restore(
                        &intent,
                        &producer,
                        collected.as_ref(),
                    )
                })
                .await??;
            }
        }
        Ok(())
    }
    pub(in crate::lifecycle) async fn checkpoint_restore(
        &self,
        request: &ManagedRestoreRequest,
    ) -> std::result::Result<RuntimeHandle, ApiError> {
        self.create_with_input(&request.sandbox, &request.request, None, Some(request))
            .await
    }

    pub(super) async fn restore_binding(
        &self,
        request: &ManagedRestoreRequest,
    ) -> Result<RestoreBinding> {
        let digest = request.digest()?;
        let cfg = &self.inner.cfg;
        let target = request.sandbox.id;
        if cfg.record_path(target).try_exists()? {
            let record = self.load(target)?;
            let binding = record.restore.ok_or_else(|| {
                ApiError::new(
                    ErrorCode::Conflict,
                    "native target already belongs to ordinary boot",
                )
            })?;
            if record.owner.request_sha256 != digest
                || record.owner.expires_at != request.sandbox.expires_at
                || binding.intent.reference != request.reference
                || binding.intent.restoration != request.restoration
            {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "native target already has a different restore intent",
                )
                .into());
            }
            return Ok(binding);
        }
        if request.reference.installation != cfg.installation_id
            || request.request.image != cfg.image
        {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "private native restoration currently requires this installation baseline image",
            )
            .into());
        }
        let checkpoint = cfg.checkpoint_config(request.reference.capture)?;
        let reference = request.reference.clone();
        let permit = self
            .inner
            .capture_slot
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "native checkpoint validation worker is reserved",
                )
            })?;
        let manifest = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            CheckpointStore::open_or_initialize(&checkpoint)?
                .verify(&reference, |manifest, _| Ok(manifest.clone()))
        })
        .await??;
        let source = self.load(manifest.source.sandbox)?;
        if source.owner.installation_id != manifest.source.installation
            || source.owner.generation != manifest.source.source_generation
            || source.owner.request_sha256 != manifest.source.request_sha256
            || source.capture_hold != Some(request.reference.capture)
            || source.selected_image.is_some()
            || source.resources != request.request.resources
            || manifest.resources != request.request.resources
            || source.artifacts != cfg.artifacts
            || !self.physical_absence(&source)?
        {
            return Err(invalid(
                "native restore source provenance, resources or physical absence differs",
            )
            .into());
        }
        let generation = Uuid::new_v4();
        Ok(RestoreBinding {
            intent: RestoreIntent {
                reference: request.reference.clone(),
                runtime: manifest.runtime,
                restoration: request.restoration,
                sandbox: target,
                generation,
                destination: Destination::observe(&cfg.paths(generation)?.root, generation)?,
            },
        })
    }
}
