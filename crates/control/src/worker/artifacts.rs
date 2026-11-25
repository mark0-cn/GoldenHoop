use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use goldenhoop_artifacts::{BlobRef, MAX_BLOB_BYTES};
use goldenhoop_store::StoredArtifact;
use sha2::{Digest, Sha256};

fn reference(artifact: &Artifact) -> Option<BlobRef> {
    Some(BlobRef {
        id: artifact.id,
        sha256: artifact.sha256.clone()?,
        size_bytes: artifact.size_bytes?,
    })
}
impl Worker {
    pub async fn sweep_artifacts(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                return;
            }
            let sweep = async {
                // Probes finish before this task starts. Their separate namespace
                // contains only temporary data owned by this active controller.
                self.artifacts.clear_probe_residue().await?;
                for id in self.artifacts.ids().await? {
                    let Ok(_guard) = self.lock(id).await.try_lock_owned() else {
                        continue;
                    };
                    let stored = match self.store.artifact(id).await {
                        Ok(stored) => stored,
                        Err(error) if error.code == ErrorCode::NotFound => continue,
                        Err(error) => return Err(error),
                    };
                    if !matches!(
                        stored.artifact.state,
                        ArtifactState::Deleted | ArtifactState::Failed
                    ) {
                        continue;
                    }
                    self.store.note_artifact_residue(id).await?;
                    self.artifacts.delete(id).await?;
                    let error = if stored.artifact.desired_state == ArtifactDesiredState::Deleted {
                        None
                    } else {
                        self.store
                            .operation(stored.create_operation)
                            .await?
                            .error
                            .or(stored.artifact.error)
                    };
                    self.store
                        .observe_artifact(id, stored.artifact.state, CleanupState::Complete, error)
                        .await?;
                    println!(
                        "{}",
                        serde_json::json!({"event":"artifact_residue_removed","artifact_id":id})
                    );
                }
                Ok::<_, ApiError>(())
            };
            tokio::select! {
                result=sweep=>{if let Err(error)=result {report("artifact_residue_scan_failed",&error);}},
                result=shutdown.changed()=>{if result.is_err() || *shutdown.borrow() {return;}}
            }
            tokio::select! {result=shutdown.changed()=>{if result.is_err(){return;}},_=tokio::time::sleep(Duration::from_secs(5))=>{}}
        }
    }
    pub(super) async fn reconcile_artifact(&self, id: Uuid) -> Result<(), ApiError> {
        let stored = self.store.artifact(id).await?;
        let artifact = &stored.artifact;
        if artifact.desired_state == ArtifactDesiredState::Deleted
            || artifact.state == ArtifactState::Failed
        {
            self.artifacts.delete(id).await?;
            self.store
                .observe_artifact(
                    id,
                    if artifact.desired_state == ArtifactDesiredState::Deleted {
                        ArtifactState::Deleted
                    } else {
                        ArtifactState::Failed
                    },
                    CleanupState::Complete,
                    if artifact.desired_state == ArtifactDesiredState::Deleted {
                        None
                    } else {
                        artifact.error.clone()
                    },
                )
                .await?;
            return Ok(());
        }
        if let Some(reference) = reference(artifact) {
            match self.artifacts.read(&reference).await {
                Ok(_) => {
                    self.store
                        .observe_artifact(id, ArtifactState::Available, CleanupState::Pending, None)
                        .await?;
                    return Ok(());
                }
                Err(error) if error.code == ErrorCode::NotFound => {}
                Err(error) if error.code == ErrorCode::Conflict => {
                    return self.fail_artifact(id, error).await;
                }
                Err(error) => return Err(error),
            }
        }
        let sandbox = self.store.sandbox(artifact.sandbox_id).await?.sandbox;
        let effective = self.store.effective_desired(artifact.sandbox_id).await?;
        if effective == DesiredState::Terminated
            || matches!(
                sandbox.state,
                SandboxState::Terminated | SandboxState::Failed
            )
            || expired(&sandbox, Utc::now())
        {
            return self
                .fail_artifact(
                    id,
                    ApiError::new(
                        ErrorCode::InvalidState,
                        "artifact source sandbox is no longer available",
                    ),
                )
                .await;
        }
        if sandbox.state != SandboxState::Running || effective != DesiredState::Running {
            return Ok(());
        }
        let bytes = match self.capture_artifact(&stored).await {
            Ok(bytes) => bytes,
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::NotFound
                        | ErrorCode::Forbidden
                        | ErrorCode::InvalidRequest
                        | ErrorCode::QuotaExceeded
                ) =>
            {
                return self.fail_artifact(id, error).await;
            }
            Err(error) => return Err(error),
        };
        let digest = format!("{:x}", Sha256::digest(&bytes));
        if artifact.sha256.as_deref().is_some_and(|sha| sha != digest)
            || artifact
                .size_bytes
                .is_some_and(|size| size != bytes.len() as u64)
        {
            return self
                .fail_artifact(
                    id,
                    ApiError::new(
                        ErrorCode::Conflict,
                        "source changed before an interrupted artifact upload could be recovered",
                    ),
                )
                .await;
        }
        let prepared = self
            .store
            .prepare_artifact(id, &digest, bytes.len() as u64)
            .await?;
        if prepared.artifact.desired_state == ArtifactDesiredState::Deleted {
            return Ok(());
        }
        match self.artifacts.put(id, &bytes).await {
            Ok(_) => {}
            Err(error) if error.code == ErrorCode::Conflict => {
                return self.fail_artifact(id, error).await;
            }
            Err(error) => return Err(error),
        }
        self.store
            .observe_artifact(id, ArtifactState::Available, CleanupState::Pending, None)
            .await?;
        Ok(())
    }

    async fn capture_artifact(&self, stored: &StoredArtifact) -> Result<Vec<u8>, ApiError> {
        let _guard = self
            .lock(stored.artifact.sandbox_id)
            .await
            .lock_owned()
            .await;
        let sandbox = self.store.sandbox(stored.artifact.sandbox_id).await?;
        self.store
            .authorize_work(stored.artifact.sandbox_id, Capability::Artifacts)
            .await?;
        if sandbox.sandbox.state != SandboxState::Running
            || sandbox.sandbox.desired_state != DesiredState::Running
            || expired(&sandbox.sandbox, Utc::now())
        {
            return Err(ApiError::new(
                ErrorCode::BackendUnavailable,
                "artifact source is not currently accepting file reads",
            ));
        }
        let driver = self.drivers.get(&sandbox.sandbox.profile).ok_or_else(|| {
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "source runtime profile is unavailable",
            )
        })?;
        let handle = self
            .recovered_handle(&sandbox, driver)
            .await?
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::BackendUnavailable,
                    "source runtime handle is absent",
                )
            })?;
        let reply = self
            .rpc(
                driver,
                &handle,
                &AgentRequest::ReadFile {
                    path: stored.request.path.clone(),
                    max_bytes: MAX_BLOB_BYTES as u64,
                },
            )
            .await?;
        let AgentResponse::File { data_base64 } = reply else {
            return Err(ApiError::new(
                ErrorCode::BackendUnavailable,
                "unexpected artifact source response",
            ));
        };
        let bytes = STANDARD.decode(data_base64).map_err(|_| {
            ApiError::new(
                ErrorCode::BackendUnavailable,
                "invalid artifact source encoding",
            )
        })?;
        if bytes.len() > MAX_BLOB_BYTES {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                "artifact source exceeds its transfer limit",
            ));
        }
        Ok(bytes)
    }

    async fn fail_artifact(&self, id: Uuid, error: ApiError) -> Result<(), ApiError> {
        self.store
            .observe_artifact(
                id,
                ArtifactState::Failed,
                CleanupState::Pending,
                Some(error.clone()),
            )
            .await?;
        self.artifacts.delete(id).await?;
        self.store
            .observe_artifact(
                id,
                ArtifactState::Failed,
                CleanupState::Complete,
                Some(error),
            )
            .await?;
        Ok(())
    }

    pub(super) async fn artifact_error(&self, id: Uuid, error: &ApiError) {
        if let Ok(stored) = self.store.artifact(id).await
            && stored.artifact.cleanup != CleanupState::Complete
            && stored.artifact.state != ArtifactState::Available
        {
            let state = stored.artifact.state;
            let reason = if state == ArtifactState::Failed {
                stored.artifact.error.or(Some(error.clone()))
            } else {
                Some(error.clone())
            };
            if let Err(error) = self
                .store
                .observe_artifact(id, state, CleanupState::Unknown, reason)
                .await
            {
                report("artifact_error_persist_failed", &error);
            }
        }
    }
}

pub(super) async fn content(
    State(worker): State<Arc<Worker>>,
    ApiJson(call): ApiJson<crate::InternalArtifactCall>,
) -> Result<Json<FileData>, HttpError> {
    let _guard = worker.lock(call.artifact_id).await.lock_owned().await;
    let artifact = worker.store.artifact(call.artifact_id).await?.artifact;
    worker
        .store
        .authorize_feature(artifact.sandbox_id, Capability::Artifacts)
        .await?;
    if artifact.state != ArtifactState::Available
        || artifact.desired_state != ArtifactDesiredState::Available
    {
        return Err(
            ApiError::new(ErrorCode::InvalidState, "artifact content is not available").into(),
        );
    }
    let reference = reference(&artifact)
        .ok_or_else(|| ApiError::new(ErrorCode::Internal, "artifact content metadata is absent"))?;
    Ok(Json(FileData {
        data_base64: STANDARD.encode(worker.artifacts.read(&reference).await?),
    }))
}
