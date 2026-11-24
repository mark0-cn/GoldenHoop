use super::*;
use sha2::{Digest, Sha256};

impl Client {
    pub async fn create_artifact(
        &self,
        sandbox: Uuid,
        request: &CreateArtifact,
        key: &str,
    ) -> Result<ArtifactCreated> {
        let value: ArtifactCreated = Self::json(
            self.send(
                Method::POST,
                &format!("v1/sandboxes/{sandbox}/artifacts"),
                Some(
                    serde_json::to_value(request)
                        .map_err(|_| Error::Protocol("invalid artifact request"))?,
                ),
                Some(key),
            )
            .await?,
        )
        .await?;
        if value.artifact.id.is_nil()
            || value.artifact.sandbox_id != sandbox
            || value.artifact.name != request.name
            || value.artifact.source_path != request.path
            || value.operation.resource_id != value.artifact.id
        {
            return Err(Error::Protocol(
                "artifact create response identity mismatch",
            ));
        }
        Ok(value)
    }
    pub async fn artifact(&self, id: Uuid) -> Result<Artifact> {
        let value: Artifact = self.get(&format!("v1/artifacts/{id}")).await?;
        if value.id != id {
            return Err(Error::Protocol("artifact identity mismatch"));
        }
        Ok(value)
    }
    pub async fn list_artifacts(
        &self,
        sandbox: Option<Uuid>,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<ArtifactPage> {
        let mut path = format!("v1/artifacts?limit={limit}");
        if let Some(id) = sandbox {
            path.push_str(&format!("&sandbox_id={id}"));
        }
        if let Some(id) = after {
            path.push_str(&format!("&after={id}"));
        }
        self.get(&path).await
    }
    pub async fn delete_artifact(&self, id: Uuid, key: &str) -> Result<Operation> {
        let value: Operation = Self::json(
            self.send(
                Method::DELETE,
                &format!("v1/artifacts/{id}"),
                None,
                Some(key),
            )
            .await?,
        )
        .await?;
        if value.resource_id != id {
            return Err(Error::Protocol(
                "artifact delete response identity mismatch",
            ));
        }
        Ok(value)
    }
    pub async fn artifact_bytes(&self, id: Uuid) -> Result<Vec<u8>> {
        let metadata = self.artifact(id).await?;
        if metadata.state != ArtifactState::Available
            || metadata.desired_state != ArtifactDesiredState::Available
        {
            return Err(Error::Api(ApiError::new(
                ErrorCode::InvalidState,
                "artifact content is not available",
            )));
        }
        let response = self
            .send(
                Method::GET,
                &format!("v1/artifacts/{id}/content"),
                None,
                None,
            )
            .await?;
        if !response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/octet-stream"))
        {
            return Err(Error::Protocol("expected binary artifact content"));
        }
        let bytes = Self::body(response, 16 * 1024 * 1024).await?;
        if metadata.size_bytes != Some(bytes.len() as u64)
            || metadata.sha256.as_deref() != Some(&format!("{:x}", Sha256::digest(&bytes)))
        {
            return Err(Error::Protocol("artifact content integrity check failed"));
        }
        Ok(bytes)
    }
    /// Retained output; closing its source sandbox does not delete this artifact.
    pub async fn capture_artifact(
        &self,
        sandbox: Uuid,
        request: &CreateArtifact,
    ) -> Result<Artifact> {
        let key = Uuid::new_v4().to_string();
        let created = match self.create_artifact(sandbox, request, &key).await {
            Ok(value) => value,
            Err(Error::Transport) => return Err(Error::UncertainRequest(key)),
            Err(Error::Api(error)) if error.code == ErrorCode::BackendUnavailable => {
                return Err(Error::UncertainRequest(key));
            }
            Err(error) => return Err(error),
        };
        let id = created.artifact.id;
        let result = async {
            self.wait_operation(created.operation.id, Duration::from_secs(60))
                .await?;
            let artifact = self.artifact(id).await?;
            if artifact.state != ArtifactState::Available {
                return Err(Error::Protocol("artifact is not available after capture"));
            }
            Ok(artifact)
        }
        .await;
        result.map_err(|error| Error::Artifact(id, Box::new(error)))
    }
}
