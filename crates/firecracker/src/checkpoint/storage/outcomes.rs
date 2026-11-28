//! Permanent source-bound decisions before a capture reservation. Absence alone
//! is not a refusal: late producers must observe a durable closed identifier.
use super::*;
use files::{admission_name, refusal_name};
use goldenhoop_protocol::{ApiError, ErrorCode};
use std::collections::HashSet;

fn validate_source(source: &CaptureIdentity, root: &Root) -> Result<()> {
    if source.installation != root.installation()
        || [
            source.installation,
            source.sandbox,
            source.source_generation,
            source.capture,
        ]
        .iter()
        .any(Uuid::is_nil)
        || !valid_sha(&source.request_sha256)
    {
        return Err(invalid("capture outcome source binding differs").into());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaptureAdmission {
    format: u16,
    store: Uuid,
    pub(super) source: CaptureIdentity,
    pub(super) intent_sha256: String,
}
impl CaptureAdmission {
    pub(super) fn validate(&self, root: &Root) -> Result<()> {
        validate_source(&self.source, root)?;
        if self.format != 1 || self.store != root.nonce() || !valid_sha(&self.intent_sha256) {
            return Err(invalid("capture admission receipt differs").into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RefusalReceipt {
    pub format: u16,
    pub store: Uuid,
    pub source: CaptureIdentity,
    pub reason: ApiError,
}
impl RefusalReceipt {
    pub(super) fn validate(&self, root: &Root) -> Result<()> {
        validate_source(&self.source, root)?;
        if self.format != 1 || self.store != root.nonce() || self.reason.message.len() > 512 {
            return Err(invalid("capture refusal receipt differs").into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaptureRefusal {
    pub(super) receipt: RefusalReceipt,
    diagnostic: String,
}
impl CaptureRefusal {
    pub(super) fn validate(&self, root: &Root) -> Result<()> {
        self.receipt.validate(root)?;
        if self.diagnostic.len() > 8192 {
            return Err(invalid("capture refusal diagnostic exceeds bound").into());
        }
        Ok(())
    }
    pub(super) fn status(&self) -> serde_json::Value {
        serde_json::json!({"capture":self.receipt.source.capture,"phase":"refused","capture_outcome":"not_started",
            "reserved_bytes":0,"objects_absent":true,"content_verified":false,"manifest":null,"reference":null,
            "error":null,"refusal":self.receipt})
    }
}

impl Root {
    pub(super) fn admission(&self, id: Uuid) -> Result<Option<CaptureAdmission>> {
        let value: Option<CaptureAdmission> = self.optional_json(&admission_name(id))?;
        if let Some(value) = &value {
            value.validate(self)?;
            if value.source.capture != id {
                return Err(invalid("capture admission ID differs").into());
            }
        }
        Ok(value)
    }
    pub(super) fn refusal(&self, id: Uuid) -> Result<Option<CaptureRefusal>> {
        let value: Option<CaptureRefusal> = self.optional_json(&refusal_name(id))?;
        if let Some(value) = &value {
            value.validate(self)?;
            if value.receipt.source.capture != id {
                return Err(invalid("capture refusal ID differs").into());
            }
            if self
                .admission(id)?
                .is_some_and(|admission| admission.source != value.receipt.source)
            {
                return Err(invalid("capture refusal contradicts its admission source").into());
            }
            if self
                .optional_json::<serde_json::Value>(&record_name(id))?
                .is_some()
            {
                return Err(invalid("capture refusal contradicts an existing reservation").into());
            }
        }
        Ok(value)
    }
    pub(super) fn require_history_room(&self, id: Uuid) -> Result<()> {
        let mut ids: HashSet<_> = self
            .records()?
            .into_iter()
            .map(|r| r.intent.source.capture)
            .collect();
        ids.extend(self.metadata_ids("admission-")?);
        ids.extend(self.metadata_ids("refusal-")?);
        if !ids.contains(&id) && ids.len() >= 1024 {
            return Err(
                invalid("checkpoint history is full; no identifier history is evicted").into(),
            );
        }
        Ok(())
    }
    pub(super) fn admit_capture(&self, intent: &Intent) -> Result<()> {
        let digest = intent.digest()?;
        if let Some(existing) = self.admission(intent.source.capture)? {
            if existing.source != intent.source || existing.intent_sha256 != digest {
                return Err(
                    invalid("capture ID already has a different immutable admission").into(),
                );
            }
            return Ok(());
        }
        let value = CaptureAdmission {
            format: 1,
            store: self.nonce(),
            source: intent.source.clone(),
            intent_sha256: digest,
        };
        value.validate(self)?;
        metadata::initial_json(
            &self.path.join(admission_name(intent.source.capture)),
            &value,
        )
    }
}

impl CheckpointStore {
    /// Caller holds the original native VM mutex and has checked that this
    /// source never acknowledged the requested capture hold. An existing
    /// reservation is inspected instead. No producer is dispatched here.
    pub(crate) fn close_unstarted(
        &self,
        source: CaptureIdentity,
        error: &ApiError,
    ) -> Result<Option<serde_json::Value>> {
        validate_source(&source, &self.root)?;
        let _quota = self.root.quota(true)?;
        self.root.recover_capture(source.capture)?;
        if let Some(record) = self
            .root
            .records()?
            .into_iter()
            .find(|r| r.intent.source.capture == source.capture)
        {
            if record.intent.source != source {
                return Err(
                    invalid("capture reservation belongs to another original source").into(),
                );
            }
            return Ok(None);
        }
        if let Some(refusal) = self.root.refusal(source.capture)? {
            if refusal.receipt.source != source {
                return Err(invalid("capture refusal belongs to another original source").into());
            }
            return Ok(Some(refusal.status()));
        }
        if let Some(admission) = self.root.admission(source.capture)? {
            if admission.source != source {
                return Err(invalid("capture admission belongs to another original source").into());
            }
        } else if self.root.capture_mutex_exists(source.capture)? {
            // Older headers contain only an intent hash. Do not guess which
            // source owns an incomplete legacy admission or delete its mutex.
            return Err(invalid("unbound legacy capture mutex prevents refusal proof").into());
        }
        self.root.require_history_room(source.capture)?;
        let message = if error.code == ErrorCode::QuotaExceeded {
            "native capture capacity refused before reservation"
        } else {
            "native capture intent closed before reservation"
        };
        let refusal = CaptureRefusal {
            receipt: RefusalReceipt {
                format: 1,
                store: self.root.nonce(),
                source: source.clone(),
                reason: ApiError::new(error.code, message),
            },
            diagnostic: error.message.chars().take(2048).collect(),
        };
        refusal.validate(&self.root)?;
        metadata::initial_json(&self.root.path.join(refusal_name(source.capture)), &refusal)?;
        Ok(Some(refusal.status()))
    }
}
