//! Durable control state. Runtime access belongs exclusively to the worker.
mod artifacts;
mod contexts;
mod controllers;
pub use controllers::{ControllerAbsence, ControllerPhase, NetworkController};
mod executions;
mod isolated;
mod lifecycle;
mod networks;
mod sessions;
pub use networks::{
    NetworkAbsence, NetworkAllocation, NetworkBinding, NetworkNativeBinding, NetworkPhase,
};

use std::{path::Path, time::Duration};

use chrono::{DateTime, Utc};
use goldenhoop_protocol::*;
use goldenhoop_runtime::RuntimeHandle;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct Store {
    pub(crate) pool: SqlitePool,
    installation_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct StoredSandbox {
    pub sandbox: Sandbox,
    pub request: CreateSandbox,
    pub handle: Option<RuntimeHandle>,
    pub ever_running: bool,
    pub create_operation: Uuid,
}

#[derive(Debug, Clone)]
pub struct StoredExecution {
    pub execution: Execution,
    pub spec: CommandSpec,
    pub cancel_requested: bool,
    pub cursor: u64,
}

#[derive(Debug, Clone)]
pub struct StoredArtifact {
    pub artifact: Artifact,
    pub request: CreateArtifact,
    pub create_operation: Uuid,
}

#[derive(Debug, Clone)]
pub struct StoredSessionControl {
    pub request: SessionControl,
    pub receipt: SessionControlReceipt,
}

#[derive(Debug, Clone)]
pub struct StoredCodeContext {
    pub context: CodeContext,
    /// Set before any create RPC. A missing previously dispatched ID is not replayable.
    pub dispatched: bool,
    pub ever_ready: bool,
    /// Agent acknowledgement cursor, distinct from the public event cursor.
    pub cursor: u64,
    pub events_cursor: u64,
}

#[derive(Debug, Clone)]
pub struct StoredCodeRun {
    pub run: CodeRun,
    pub spec: CodeRunSpec,
    pub dispatched: bool,
    pub cancel_requested: bool,
}

/// Private host metadata. Never serialize this structure through the public API.
#[derive(Clone, Serialize, Deserialize)]
pub struct WorkerRegistration {
    pub id: Uuid,
    pub endpoint: String,
    pub token: String,
    pub heartbeat: DateTime<Utc>,
    pub profiles: Vec<RuntimeProfile>,
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::Internal, "persistent state is invalid")
}
fn db(_error: sqlx::Error) -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "persistent store operation failed",
    )
}
fn encode(value: &impl Serialize) -> Result<String, ApiError> {
    serde_json::to_string(value).map_err(|_| internal())
}
fn decode<T: DeserializeOwned>(value: &str) -> Result<T, ApiError> {
    serde_json::from_str(value).map_err(|_| internal())
}
fn tag(value: &impl Serialize) -> Result<String, ApiError> {
    serde_json::to_value(value)
        .map_err(|_| internal())?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(internal)
}
pub fn fingerprint(value: &impl Serialize) -> Result<String, ApiError> {
    Ok(format!("{:x}", Sha256::digest(encode(value)?)))
}
fn not_found(what: &str) -> ApiError {
    ApiError::new(ErrorCode::NotFound, format!("{what} not found"))
}
fn sandbox_row(row: &sqlx::sqlite::SqliteRow) -> Result<StoredSandbox, ApiError> {
    let mut sandbox: Sandbox = decode(row.try_get("payload").map_err(db)?)?;
    sandbox.desired_state = decode(&format!(
        "\"{}\"",
        row.try_get::<&str, _>("desired").map_err(db)?
    ))?;
    Ok(StoredSandbox {
        sandbox,
        request: decode(row.try_get("request").map_err(db)?)?,
        handle: row
            .try_get::<Option<&str>, _>("handle")
            .map_err(db)?
            .map(decode)
            .transpose()?,
        ever_running: row.try_get("ever_running").map_err(db)?,
        create_operation: Uuid::parse_str(row.try_get("create_operation").map_err(db)?)
            .map_err(|_| internal())?,
    })
}

async fn reserve(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    scope: &str,
    key: &str,
    fingerprint: &str,
    id: Uuid,
) -> Result<Option<Uuid>, ApiError> {
    goldenhoop_core::validate_idempotency_key(key)?;
    let inserted = sqlx::query("INSERT OR IGNORE INTO idempotency(scope,client_key,fingerprint,resource_id) VALUES(?,?,?,?)")
        .bind(scope).bind(key).bind(fingerprint).bind(id.to_string()).execute(&mut **tx).await.map_err(db)?;
    if inserted.rows_affected() == 1 {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT fingerprint,resource_id FROM idempotency WHERE scope=? AND client_key=?",
    )
    .bind(scope)
    .bind(key)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if row.try_get::<&str, _>("fingerprint").map_err(db)? != fingerprint {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "idempotency key has different request content",
        ));
    }
    Ok(Some(
        Uuid::parse_str(row.try_get("resource_id").map_err(db)?).map_err(|_| internal())?,
    ))
}

impl Store {
    pub async fn open(path: &Path) -> Result<Self, ApiError> {
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
            let mut directories = std::fs::DirBuilder::new();
            directories.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                directories.mode(0o700);
            }
            directories.create(parent).map_err(|_| internal())?;
        }
        let mut file = std::fs::OpenOptions::new();
        file.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            file.mode(0o600);
        }
        match file.open(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(internal()),
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|_| internal())?;
        if !metadata.is_file() {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "database must be a regular private file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ApiError::new(
                    ErrorCode::Forbidden,
                    "database file permissions must exclude group and other users",
                ));
            }
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(false)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        Self::connect(options).await
    }

    pub async fn memory() -> Result<Self, ApiError> {
        Self::connect(
            SqliteConnectOptions::new()
                .in_memory(true)
                .foreign_keys(true),
        )
        .await
    }

    async fn connect(options: SqliteConnectOptions) -> Result<Self, ApiError> {
        // One connection per process keeps transactions predictable. SQLite WAL permits
        // the separate API and worker processes to read while the other writes.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(db)?;
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        sqlx::raw_sql(include_str!("schema.sql"))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version','1')")
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let version: String =
            sqlx::query_scalar("SELECT value FROM meta WHERE key='schema_version'")
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        if !matches!(
            version.as_str(),
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10"
        ) {
            return Err(ApiError::new(
                ErrorCode::UnsupportedCapability,
                "database schema version is unsupported",
            ));
        }
        if version == "1" {
            sqlx::raw_sql(include_str!("schema-v2.sql"))
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        if matches!(version.as_str(), "1" | "2") {
            sqlx::raw_sql(include_str!("schema-v3.sql"))
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        if matches!(version.as_str(), "1" | "2" | "3") {
            sqlx::raw_sql(include_str!("schema-v4.sql"))
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        if matches!(version.as_str(), "1" | "2" | "3" | "4") {
            sqlx::raw_sql(include_str!("schema-v5.sql"))
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        if !matches!(version.as_str(), "6" | "7" | "8" | "9" | "10") {
            sqlx::raw_sql(include_str!("schema-v6.sql"))
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        if !matches!(version.as_str(), "7" | "8" | "9" | "10") {
            sqlx::raw_sql(include_str!("schema-v7.sql"))
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        if !matches!(version.as_str(), "8" | "9" | "10") {
            sqlx::raw_sql(include_str!("schema-v8.sql"))
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        if !matches!(version.as_str(), "9" | "10") {
            sqlx::raw_sql(include_str!("schema-v9.sql"))
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        if version != "10" {
            sqlx::raw_sql(include_str!("schema-v10.sql"))
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        sqlx::query("INSERT OR IGNORE INTO meta(key,value) VALUES('installation_id',?)")
            .bind(Uuid::new_v4().to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let value: String =
            sqlx::query_scalar("SELECT value FROM meta WHERE key='installation_id'")
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        let installation_id = Uuid::parse_str(&value).map_err(|_| internal())?;
        tx.commit().await.map_err(db)?;
        Ok(Self {
            pool,
            installation_id,
        })
    }

    pub fn installation_id(&self) -> Uuid {
        self.installation_id
    }
    pub async fn close(&self) {
        self.pool.close().await;
    }

    pub async fn register_worker(&self, worker: &WorkerRegistration) -> Result<(), ApiError> {
        sqlx::query("INSERT INTO meta(key,value) VALUES('worker',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            .bind(encode(worker)?).execute(&self.pool).await.map_err(db)?;
        Ok(())
    }

    pub async fn worker(&self) -> Result<WorkerRegistration, ApiError> {
        let value: Option<String> = sqlx::query_scalar("SELECT value FROM meta WHERE key='worker'")
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        let worker: WorkerRegistration = decode(&value.ok_or_else(|| {
            ApiError::new(ErrorCode::BackendUnavailable, "worker has not registered")
        })?)?;
        if Utc::now()
            .signed_duration_since(worker.heartbeat)
            .num_seconds()
            > 10
            || worker.heartbeat > Utc::now() + chrono::Duration::seconds(5)
        {
            return Err(ApiError::new(
                ErrorCode::BackendUnavailable,
                "worker heartbeat is stale",
            ));
        }
        Ok(worker)
    }

    pub async fn idempotent_resource(
        &self,
        scope: &str,
        key: &str,
        fingerprint: &str,
    ) -> Result<Option<Uuid>, ApiError> {
        goldenhoop_core::validate_idempotency_key(key)?;
        let row = sqlx::query(
            "SELECT fingerprint,resource_id FROM idempotency WHERE scope=? AND client_key=?",
        )
        .bind(scope)
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        row.map(|row| {
            if row.try_get::<&str, _>("fingerprint").map_err(db)? != fingerprint {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    "idempotency key has different request content",
                ));
            }
            Uuid::parse_str(row.try_get("resource_id").map_err(db)?).map_err(|_| internal())
        })
        .transpose()
    }
}
