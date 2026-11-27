//! Private image preparation intents. Provider writes must follow durable CAS.
//! Payload state transitions and runtime ownership belong to the trusted host
//! image orchestrator; these records are never exposed through the public API.
use super::*;
use serde_json::Value;

const LIMIT: usize = 65536;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageJob {
    pub id: Uuid,
    pub installation_id: Uuid,
    pub generation: Uuid,
    pub request_sha256: String,
    pub request: Value,
    pub payload: Value,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
}
fn conflict() -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        "image intent identity or revision differs",
    )
}
fn encoded(value: &Value) -> Result<String, ApiError> {
    let result = serde_json::to_string(value).map_err(|_| internal())?;
    if !value.is_object() || result.len() > LIMIT {
        return Err(ApiError::new(
            ErrorCode::InvalidRequest,
            "image intent must be a bounded object",
        ));
    }
    Ok(result)
}
fn fingerprint(value: &Value) -> Result<String, ApiError> {
    Ok(format!("{:x}", Sha256::digest(encoded(value)?.as_bytes())))
}
fn record(value: sqlx::sqlite::SqliteRow, installation: Uuid) -> Result<ImageJob, ApiError> {
    let json = |name: &str| -> Result<Value, ApiError> {
        let raw: &str = value.try_get(name).map_err(db)?;
        if raw.len() > LIMIT {
            return Err(internal());
        }
        serde_json::from_str(raw).map_err(|_| internal())
    };
    let parsed = |name: &str| -> Result<Uuid, ApiError> {
        Uuid::parse_str(value.try_get(name).map_err(db)?).map_err(|_| internal())
    };
    let result = ImageJob {
        id: parsed("id")?,
        installation_id: parsed("installation_id")?,
        generation: parsed("generation")?,
        request_sha256: value.try_get("request_sha256").map_err(db)?,
        request: json("request_json")?,
        payload: json("payload_json")?,
        revision: u64::try_from(value.try_get::<i64, _>("revision").map_err(db)?)
            .map_err(|_| internal())?,
        created_at: value
            .try_get::<&str, _>("created_at")
            .map_err(db)?
            .parse()
            .map_err(|_| internal())?,
    };
    if result.id.is_nil()
        || result.generation.is_nil()
        || result.installation_id != installation
        || result.request_sha256 != fingerprint(&result.request)?
    {
        return Err(conflict());
    }
    encoded(&result.payload)?;
    Ok(result)
}
impl Store {
    /// New ownership is committed before any provider mutation. Reusing an ID
    /// returns its original payload, never a new generation or reset revision.
    pub async fn reserve_image_job(
        &self,
        id: Uuid,
        generation: Uuid,
        request: &Value,
        initial: &Value,
    ) -> Result<ImageJob, ApiError> {
        if id.is_nil() || generation.is_nil() {
            return Err(conflict());
        }
        let request_json = encoded(request)?;
        let payload_json = encoded(initial)?;
        let request_sha256 = fingerprint(request)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        if let Some(row) = sqlx::query("SELECT * FROM image_jobs WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
        {
            let existing = record(row, self.installation_id)?;
            if existing.generation != generation || existing.request_sha256 != request_sha256 {
                return Err(conflict());
            }
            tx.commit().await.map_err(db)?;
            return Ok(existing);
        }
        if sqlx::query("SELECT id FROM image_jobs WHERE installation_id=? AND generation=?")
            .bind(self.installation_id.to_string())
            .bind(generation.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .is_some()
        {
            return Err(conflict());
        }
        sqlx::query("INSERT INTO image_jobs(id,installation_id,generation,request_sha256,request_json,payload_json,revision,created_at) VALUES(?,?,?,?,?,?,0,?)")
            .bind(id.to_string()).bind(self.installation_id.to_string()).bind(generation.to_string()).bind(request_sha256)
            .bind(request_json).bind(payload_json).bind(Utc::now().to_rfc3339()).execute(&mut *tx).await.map_err(db)?;
        let row = sqlx::query("SELECT * FROM image_jobs WHERE id=?")
            .bind(id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let result = record(row, self.installation_id)?;
        tx.commit().await.map_err(db)?;
        Ok(result)
    }
    pub async fn image_job(&self, id: Uuid) -> Result<ImageJob, ApiError> {
        let row = sqlx::query("SELECT * FROM image_jobs WHERE id=?")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "image intent is absent"))?;
        record(row, self.installation_id)
    }
    /// Compare-and-swap prevents a stale producer or collector from committing
    /// over a newer owner decision. It cannot establish provider completion.
    pub async fn update_image_job(
        &self,
        expected: &ImageJob,
        payload: &Value,
    ) -> Result<ImageJob, ApiError> {
        let next = expected
            .revision
            .checked_add(1)
            .and_then(|v| i64::try_from(v).ok())
            .ok_or_else(conflict)?;
        if expected.installation_id != self.installation_id {
            return Err(conflict());
        }
        let bytes = encoded(payload)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let changed = sqlx::query("UPDATE image_jobs SET payload_json=?,revision=? WHERE id=? AND installation_id=? AND generation=? AND request_sha256=? AND revision=?")
            .bind(bytes).bind(next).bind(expected.id.to_string()).bind(self.installation_id.to_string()).bind(expected.generation.to_string())
            .bind(&expected.request_sha256).bind(i64::try_from(expected.revision).map_err(|_| conflict())?).execute(&mut *tx).await.map_err(db)?;
        if changed.rows_affected() != 1 {
            return Err(conflict());
        }
        let row = sqlx::query("SELECT * FROM image_jobs WHERE id=?")
            .bind(expected.id.to_string())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let result = record(row, self.installation_id)?;
        tx.commit().await.map_err(db)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[tokio::test]
    async fn image_intent_survives_reopen_and_never_resets_an_uncertain_dispatch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_owned();
        let database = path.join("image.db");
        let store = Store::open(&database).await.unwrap();
        let id = Uuid::new_v4();
        let generation = Uuid::new_v4();
        let request = json!({"source":"sha256:pinned"});
        let job = store
            .reserve_image_job(id, generation, &request, &json!({"phase":"reserved"}))
            .await
            .unwrap();
        let unknown = store
            .update_image_job(
                &job,
                &json!({"phase":"export_create_dispatched","acknowledgement":"unknown"}),
            )
            .await
            .unwrap();
        assert_eq!(unknown.revision, 1);
        assert!(
            store
                .update_image_job(&job, &json!({"phase":"reserved"}))
                .await
                .is_err()
        );
        store.close().await;
        let reopened = Store::open(&database).await.unwrap();
        let existing = reopened
            .reserve_image_job(id, generation, &request, &json!({"phase":"reserved"}))
            .await
            .unwrap();
        assert_eq!(existing.revision, 1);
        assert_eq!(existing.payload, unknown.payload);
        assert!(
            reopened
                .reserve_image_job(id, Uuid::new_v4(), &request, &json!({}))
                .await
                .is_err()
        );
        assert!(
            reopened
                .reserve_image_job(id, generation, &json!({"source":"foreign"}), &json!({}))
                .await
                .is_err()
        );
        reopened.close().await;
        directory.close().unwrap();
        assert!(!path.exists());
    }
    #[tokio::test]
    async fn bounded_records_refuse_foreign_installations_and_corrupt_immutable_input() {
        let store = Store::memory().await.unwrap();
        let id = Uuid::new_v4();
        let generation = Uuid::new_v4();
        let job = store
            .reserve_image_job(
                id,
                generation,
                &json!({"image":"pinned"}),
                &json!({"phase":"reserved"}),
            )
            .await
            .unwrap();
        assert!(
            store
                .update_image_job(&job, &json!({"padding":"x".repeat(LIMIT)}))
                .await
                .is_err()
        );
        assert_eq!(store.image_job(id).await.unwrap().revision, 0);
        sqlx::query("UPDATE image_jobs SET request_json=? WHERE id=?")
            .bind("{\"image\":\"foreign\"}")
            .bind(id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.image_job(id).await.is_err());
        sqlx::query("UPDATE image_jobs SET request_json=?,installation_id=? WHERE id=?")
            .bind("{\"image\":\"pinned\"}")
            .bind(Uuid::new_v4().to_string())
            .bind(id.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.image_job(id).await.is_err());
        store.close().await;
    }
}
