use super::*;

impl Client {
    /// The token is returned once. The API never retries this non-idempotent call.
    pub async fn issue_api_key(&self, spec: &CreateApiKey) -> Result<ApiKeyIssued> {
        Self::json(
            self.send(
                Method::POST,
                "v1/api-keys",
                Some(
                    serde_json::to_value(spec)
                        .map_err(|_| Error::Protocol("invalid key request"))?,
                ),
                None,
            )
            .await?,
        )
        .await
    }
    pub async fn api_key(&self, id: Uuid) -> Result<ApiKey> {
        Self::json(
            self.send(Method::GET, &format!("v1/api-keys/{id}"), None, None)
                .await?,
        )
        .await
    }
    pub async fn revoke_api_key(&self, id: Uuid) -> Result<ApiKey> {
        Self::json(
            self.send(Method::DELETE, &format!("v1/api-keys/{id}"), None, None)
                .await?,
        )
        .await
    }
    pub async fn audit(&self, after: u64, limit: u32) -> Result<AuditPage> {
        Self::json(
            self.send(
                Method::GET,
                &format!("v1/audit?after={after}&limit={limit}"),
                None,
                None,
            )
            .await?,
        )
        .await
    }
    pub async fn audit_through(&self, after: u64, limit: u32, through: u64) -> Result<AuditPage> {
        Self::json(
            self.send(
                Method::GET,
                &format!("v1/audit?after={after}&limit={limit}&through={through}"),
                None,
                None,
            )
            .await?,
        )
        .await
    }
}
