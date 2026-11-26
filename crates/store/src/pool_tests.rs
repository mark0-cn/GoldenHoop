use super::*;
use std::{future::Future, task::Poll};

#[tokio::test]
async fn cancelling_an_idle_acquire_preserves_the_in_memory_database() {
    let store = Store::memory().await.unwrap();
    let expected = store.installation_id().to_string();
    for _ in 0..32 {
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.pool.num_idle() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Poll once and immediately abandon the acquisition, as happens when
        // a revoked observer drops its pending read. A health-check await
        // must not destroy the sole connection and its actual database.
        let mut acquiring = Box::pin(store.pool.acquire());
        std::future::poll_fn(|cx| {
            if let Poll::Ready(connection) = acquiring.as_mut().poll(cx) {
                drop(connection.unwrap());
            }
            Poll::Ready(())
        })
        .await;
        drop(acquiring);
        let actual: String =
            sqlx::query_scalar("SELECT value FROM meta WHERE key='installation_id'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(actual, expected);
    }
    store.close().await;
}
