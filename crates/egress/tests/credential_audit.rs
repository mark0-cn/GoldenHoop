use goldenhoop_credentials::{BrokerAudit, CredentialAudit, CredentialOutcome};
use goldenhoop_egress::AcknowledgedAudit;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

#[tokio::test]
async fn reading_a_private_batch_does_not_allow_dispatch_before_exact_durable_ack() {
    let queue = Arc::new(AcknowledgedAudit::default());
    let writer = queue.clone();
    let task = tokio::spawn(async move {
        writer
            .append(BrokerAudit {
                request_id: Uuid::new_v4(),
                sandbox_id: Uuid::new_v4(),
                binding_id: Uuid::new_v4(),
                binding_revision: 1,
                policy_revision: 9,
                broker_epoch: Uuid::new_v4(),
                outcome: CredentialOutcome::DispatchIntent,
            })
            .await
    });
    let batch = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let batch = queue.poll(&[]).await.unwrap();
            if !batch.is_empty() {
                break batch;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(batch.len(), 1);
    assert!(!task.is_finished());
    let again = queue.poll(&[]).await.unwrap();
    assert_eq!(again[0].id, batch[0].id);
    assert!(!task.is_finished());
    assert!(queue.poll(&[Uuid::new_v4()]).await.is_err());
    assert!(!task.is_finished());
    assert!(queue.poll(&[batch[0].id, batch[0].id]).await.is_err());
    assert!(!task.is_finished());
    assert!(queue.poll(&[batch[0].id]).await.unwrap().is_empty());
    task.await.unwrap().unwrap();
}
