use super::*;

fn record(
    value: &Snapshot,
    id: Option<Uuid>,
    source: Option<Uuid>,
    kind: Option<SnapshotKind>,
) -> Result<()> {
    if value.id.is_nil()
        || value.source_sandbox_id.is_nil()
        || id.is_some_and(|id| id != value.id)
        || source.is_some_and(|id| id != value.source_sandbox_id)
        || kind.is_some_and(|kind| kind != value.kind)
        || value.state == SnapshotState::Ready && value.manifest.is_none()
        || value.state == SnapshotState::Collected && value.cleanup != CleanupState::Complete
        || value.cleanup == CleanupState::Complete
            && !matches!(
                value.state,
                SnapshotState::Collected | SnapshotState::Failed
            )
    {
        return Err(Error::Protocol(
            "snapshot identity or completion evidence mismatch",
        ));
    }
    if let Some(manifest) = &value.manifest
        && (manifest.format_version != 1
            || manifest.id != value.id
            || manifest.source_sandbox_id != value.source_sandbox_id
            || manifest.kind != value.kind
            || manifest.driver.is_empty()
            || manifest.architecture.is_empty()
            || manifest.runtime_version.is_empty()
            || manifest.image_digest.is_empty()
            || manifest.objects.is_empty()
            || manifest.objects.values().any(|v| {
                !v.strip_prefix("sha256:").is_some_and(|sha| {
                    sha.len() == 64
                        && sha
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            })
            || value.kind == SnapshotKind::MemoryAndDisk
                && (manifest.objects.len() != 3
                    || ["state", "memory", "disk"]
                        .iter()
                        .any(|k| !manifest.objects.contains_key(*k))))
    {
        return Err(Error::Protocol(
            "snapshot manifest differs from public resource",
        ));
    }
    Ok(())
}
impl Client {
    /// Keep this key after transport uncertainty; a retry must use the same key.
    pub async fn create_snapshot(
        &self,
        source: Uuid,
        request: &CreateSnapshot,
        key: &str,
    ) -> Result<SnapshotCreated> {
        let body = serde_json::to_value(request)
            .map_err(|_| Error::Protocol("invalid snapshot request"))?;
        let value: SnapshotCreated = Self::json(
            self.send(
                Method::POST,
                &format!("v1/sandboxes/{source}/snapshots"),
                Some(body),
                Some(key),
            )
            .await?,
        )
        .await?;
        record(&value.snapshot, None, Some(source), Some(request.kind))?;
        if value.operation.id.is_nil() || value.operation.resource_id != value.snapshot.id {
            return Err(Error::Protocol("snapshot operation identity mismatch"));
        }
        Ok(value)
    }
    pub async fn snapshot(&self, id: Uuid) -> Result<Snapshot> {
        let value: Snapshot = self.get(&format!("v1/snapshots/{id}")).await?;
        record(&value, Some(id), None, None)?;
        Ok(value)
    }
    pub async fn list_snapshots(
        &self,
        sandbox: Option<Uuid>,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<SnapshotPage> {
        if !(1..=1000).contains(&limit) {
            return Err(Error::Protocol(
                "snapshot page limit must be between 1 and 1000",
            ));
        }
        let mut path = format!("v1/snapshots?limit={limit}");
        if let Some(id) = sandbox {
            path.push_str(&format!("&sandbox_id={id}"));
        }
        if let Some(id) = after {
            path.push_str(&format!("&after={id}"));
        }
        let value: SnapshotPage = self.get(&path).await?;
        if value.items.len() > limit as usize {
            return Err(Error::Protocol("snapshot page exceeds requested limit"));
        }
        let mut cursor = after;
        for item in &value.items {
            record(item, None, sandbox, None)?;
            if cursor.is_some_and(|id| id >= item.id) {
                return Err(Error::Protocol("snapshot page cursor did not advance"));
            }
            cursor = Some(item.id);
        }
        if value.next_cursor.is_some()
            && (value.next_cursor != cursor || value.items.len() != limit as usize)
        {
            return Err(Error::Protocol(
                "snapshot continuation cursor differs from page",
            ));
        }
        Ok(value)
    }
    /// Records deletion; it does not implicitly remove the source sandbox.
    pub async fn delete_snapshot(&self, id: Uuid, key: &str) -> Result<Operation> {
        let value: Operation = Self::json(
            self.send(
                Method::DELETE,
                &format!("v1/snapshots/{id}"),
                None,
                Some(key),
            )
            .await?,
        )
        .await?;
        if value.id.is_nil() || value.resource_id != id {
            return Err(Error::Protocol(
                "snapshot deletion operation identity mismatch",
            ));
        }
        Ok(value)
    }
}
