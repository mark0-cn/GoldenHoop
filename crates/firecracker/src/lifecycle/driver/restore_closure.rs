//! Closing the pre-journal restore window must fence a late manager request.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosedRestore {
    format: u32,
    installation: Uuid,
    target: Uuid,
    restoration: Uuid,
    request_sha256: String,
}
impl ClosedRestore {
    fn validate(&self, cfg: &DriverConfig, target: Uuid) -> Result<()> {
        if self.format != 1
            || self.installation != cfg.installation_id
            || self.target != target
            || target.is_nil()
            || self.restoration.is_nil()
            || self.request_sha256.len() != 64
            || !self
                .request_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("native restoration closure binding differs").into());
        }
        Ok(())
    }
}
impl NativeEngine {
    fn restore_closure(&self, target: Uuid) -> Result<Option<ClosedRestore>> {
        if target.is_nil() {
            return Err(invalid("native restoration target is nil").into());
        }
        let cfg = &self.inner.cfg;
        let directory = cfg.data_root.join("restore-closures");
        private_directory(&directory)?;
        let name = format!("{target}.json");
        let recovery = metadata::recover_entries(&directory, &[&name], true, |filename, bytes| {
            let parsed = Uuid::parse_str(
                filename
                    .strip_suffix(".json")
                    .ok_or_else(|| invalid("native closure filename differs"))?,
            )?;
            if filename != format!("{parsed}.json") {
                return Err(invalid("native closure target is not canonical").into());
            }
            serde_json::from_slice::<ClosedRestore>(bytes)?.validate(cfg, parsed)
        })?;
        if !recovery.unconfirmed.is_empty() {
            return Err(invalid("native restoration closure writer remains unconfirmed").into());
        }
        let path = directory.join(name);
        if !path.try_exists()? {
            return Ok(None);
        }
        let closed: ClosedRestore = read_json(&path)?;
        closed.validate(cfg, target)?;
        Ok(Some(closed))
    }
    pub(super) fn require_restore_target_open(&self, target: Uuid) -> Result<()> {
        if self.restore_closure(target)?.is_some() {
            return Err(ApiError::new(
                ErrorCode::InvalidState,
                "native restoration target is permanently closed",
            )
            .into());
        }
        Ok(())
    }
    pub(in crate::lifecycle) async fn checkpoint_restore_collect(
        &self,
        request: &ManagedRestoreRequest,
    ) -> std::result::Result<(), ApiError> {
        let lock = self.vm_lock(request.sandbox.id).await;
        let _guard = lock.lock().await;
        let result: Result<()> = async {
            let cfg = &self.inner.cfg;
            let digest = request.digest()?;
            if request.reference.installation != cfg.installation_id
                || request.sandbox.profile != PROFILE
                || request.request.profile != PROFILE
                || request.sandbox.image != request.request.image
                || request.sandbox.resources != request.request.resources
            {
                return Err(invalid("native restoration collection request differs").into());
            }
            if let Some(closed) = self.restore_closure(request.sandbox.id)? {
                if closed.restoration != request.restoration || closed.request_sha256 != digest {
                    return Err(ApiError::new(
                        ErrorCode::Conflict,
                        "native restoration closure belongs to a different intent",
                    )
                    .into());
                }
                return Ok(());
            }
            if cfg.record_path(request.sandbox.id).try_exists()? {
                let record = self.load(request.sandbox.id)?;
                if record.owner.request_sha256 != digest
                    || record.restore.as_ref().is_none_or(|r| {
                        r.intent.reference != request.reference
                            || r.intent.restoration != request.restoration
                    })
                {
                    return Err(ApiError::new(
                        ErrorCode::Conflict,
                        "native restoration collector does not own this target",
                    )
                    .into());
                }
                self.remove_owned(&record).await?;
                let current = self.load(request.sandbox.id)?;
                if current.owner != record.owner
                    || current.restore != record.restore
                    || !self.physical_absence(&current)?
                    || current.phase != "collected"
                {
                    return Err(invalid(
                        "native restoration target collection remains unconfirmed",
                    )
                    .into());
                }
            }
            // Under the original per-target mutex, either the validated native
            // journal is positively collected, or no producer was authorized.
            // Publish before acknowledging closure; future ordinary/restore
            // creation checks this receipt under that same mutex.
            let _admission = self.inner.operations.lock().await;
            let directory = cfg.data_root.join("restore-closures");
            let count = std::fs::read_dir(&directory)?.try_fold(
                0usize,
                |n, item| -> io::Result<usize> {
                    Ok(n + usize::from(item?.file_name().to_string_lossy().ends_with(".json")))
                },
            )?;
            if count >= 2048 {
                return Err(ApiError::new(
                    ErrorCode::QuotaExceeded,
                    "native restoration closure history limit reached",
                )
                .into());
            }
            let closed = ClosedRestore {
                format: 1,
                installation: cfg.installation_id,
                target: request.sandbox.id,
                restoration: request.restoration,
                request_sha256: digest,
            };
            metadata::initial_json(
                &directory.join(format!("{}.json", request.sandbox.id)),
                &closed,
            )?;
            Ok(())
        }
        .await;
        result.map_err(|error| {
            error
                .downcast_ref::<ApiError>()
                .cloned()
                .unwrap_or_else(|| unavailable(error))
        })
    }
}
