use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialCa {
    pub sandbox_id: Uuid,
    pub certificate_pem: String,
}

fn validate(
    sandbox: Uuid,
    id: Option<Uuid>,
    record: CredentialBinding,
) -> Result<CredentialBinding> {
    if record.sandbox_id != sandbox
        || id.is_some_and(|id| id != record.id)
        || record.id.is_nil()
        || record.revision == 0
        || record.applied_revision.is_some_and(|r| r > record.revision)
        || (record.state == CredentialState::Active
            && record.applied_revision != Some(record.revision))
        || record.binding.canonicalize().ok().as_ref() != Some(&record.binding)
    {
        return Err(Error::Protocol("credential identity or revision differs"));
    }
    Ok(record)
}
impl Client {
    pub async fn credentials(&self, sandbox: Uuid) -> Result<Vec<CredentialBinding>> {
        let records: Vec<CredentialBinding> = Self::json(
            self.send(
                Method::GET,
                &format!("v1/sandboxes/{sandbox}/credentials"),
                None,
                None,
            )
            .await?,
        )
        .await?;
        let mut ids = std::collections::BTreeSet::new();
        records
            .into_iter()
            .map(|record| {
                if !ids.insert(record.id) {
                    return Err(Error::Protocol("credential collection repeats an identity"));
                }
                validate(sandbox, None, record)
            })
            .collect()
    }
    pub async fn credential(&self, sandbox: Uuid, id: Uuid) -> Result<CredentialBinding> {
        let record = Self::json(
            self.send(
                Method::GET,
                &format!("v1/sandboxes/{sandbox}/credentials/{id}"),
                None,
                None,
            )
            .await?,
        )
        .await?;
        validate(sandbox, Some(id), record)
    }
    /// Expected-revision CAS is replayable using exactly the same input. The
    /// client performs no automatic retry or promotion of Pending intent.
    pub async fn put_credential(
        &self,
        sandbox: Uuid,
        id: Uuid,
        input: &WriteCredential,
    ) -> Result<CredentialBinding> {
        let value = serde_json::to_value(input)
            .map_err(|_| Error::Protocol("invalid credential request"))?;
        let record = Self::json(
            self.send(
                Method::PUT,
                &format!("v1/sandboxes/{sandbox}/credentials/{id}"),
                Some(value),
                None,
            )
            .await?,
        )
        .await?;
        validate(sandbox, Some(id), record)
    }
    pub async fn revoke_credential(&self, sandbox: Uuid, id: Uuid) -> Result<CredentialBinding> {
        let record = Self::json(
            self.send(
                Method::DELETE,
                &format!("v1/sandboxes/{sandbox}/credentials/{id}"),
                None,
                None,
            )
            .await?,
        )
        .await?;
        validate(sandbox, Some(id), record)
    }
    pub async fn credential_ca(&self, sandbox: Uuid) -> Result<CredentialCa> {
        let ca: CredentialCa = Self::json(
            self.send(
                Method::GET,
                &format!("v1/sandboxes/{sandbox}/credential-ca"),
                None,
                None,
            )
            .await?,
        )
        .await?;
        if ca.sandbox_id != sandbox
            || ca.certificate_pem.len() > 16384
            || !ca
                .certificate_pem
                .starts_with("-----BEGIN CERTIFICATE-----")
            || ca.certificate_pem.contains("PRIVATE KEY")
        {
            return Err(Error::Protocol("credential public CA identity differs"));
        }
        Ok(ca)
    }
}
