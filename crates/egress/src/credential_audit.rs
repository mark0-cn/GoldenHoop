//! Bounded private audit delivery. Upstream dispatch waits for a durable worker
//! acknowledgement; merely reading a batch does not acknowledge its records.
use async_trait::async_trait;
use goldenhoop_credentials::{BrokerAudit, BrokerAuditDelivery, CredentialAudit};
use goldenhoop_protocol::{ApiError, ErrorCode};
use std::{
    collections::{BTreeSet, VecDeque},
    time::Duration,
};
use tokio::sync::{Mutex, oneshot};
use uuid::Uuid;

struct Pending {
    delivery: BrokerAuditDelivery,
    accepted: oneshot::Sender<()>,
}
#[derive(Default)]
pub struct AcknowledgedAudit {
    pending: Mutex<VecDeque<Pending>>,
}

impl AcknowledgedAudit {
    pub async fn poll(&self, acknowledged: &[Uuid]) -> Result<Vec<BrokerAuditDelivery>, ApiError> {
        if acknowledged.len() > 64
            || acknowledged.iter().collect::<BTreeSet<_>>().len() != acknowledged.len()
        {
            return Err(crate::error(
                ErrorCode::InvalidRequest,
                "invalid broker audit acknowledgement",
            ));
        }
        let mut queue = self.pending.lock().await;
        if acknowledged
            .iter()
            .any(|id| !queue.iter().any(|p| p.delivery.id == *id))
        {
            return Err(crate::error(
                ErrorCode::Conflict,
                "broker audit acknowledgement differs",
            ));
        }
        let mut retained = VecDeque::new();
        while let Some(pending) = queue.pop_front() {
            if acknowledged.contains(&pending.delivery.id) {
                let _ = pending.accepted.send(());
            } else {
                retained.push_back(pending);
            }
        }
        *queue = retained;
        Ok(queue.iter().take(64).map(|p| p.delivery.clone()).collect())
    }
}
#[async_trait]
impl CredentialAudit for AcknowledgedAudit {
    async fn append(&self, record: BrokerAudit) -> Result<(), ApiError> {
        let (accepted, waiting) = oneshot::channel();
        {
            let mut queue = self.pending.lock().await;
            if queue.len() >= 128 {
                return Err(crate::error(
                    ErrorCode::QuotaExceeded,
                    "broker audit queue is full",
                ));
            }
            queue.push_back(Pending {
                delivery: BrokerAuditDelivery {
                    id: Uuid::new_v4(),
                    record,
                },
                accepted,
            });
        }
        tokio::time::timeout(Duration::from_secs(8), waiting)
            .await
            .map_err(|_| {
                crate::error(
                    ErrorCode::BackendUnavailable,
                    "broker audit acknowledgement timed out",
                )
            })?
            .map_err(|_| {
                crate::error(
                    ErrorCode::BackendUnavailable,
                    "broker audit acknowledgement channel closed",
                )
            })
    }
}
