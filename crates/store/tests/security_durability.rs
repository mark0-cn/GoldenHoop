use std::panic::AssertUnwindSafe;

use chrono::Utc;
use futures_util::FutureExt;
use goldenhoop_protocol::*;
use goldenhoop_store::Store;
use sqlx::{Connection, SqliteConnection};
use uuid::Uuid;

#[tokio::test]
async fn verifier_only_persistence_reopen_revocation_audit_order_and_append_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("security.db");
    let store = Store::open(&path).await.unwrap();
    let result = AssertUnwindSafe(async {
        let spec = CreateApiKey {
            permissions: [KeyPermission::Read].into(),
            resources: KeyResources::All,
            expires_at: Utc::now() + chrono::Duration::hours(1),
        };
        let issued = store.issue_api_key(&spec, Uuid::new_v4()).await.unwrap();
        assert_eq!(
            store.authenticate_api_key(&issued.token).await.unwrap().id,
            issued.key.id
        );
        let mut invalid = issued.token.clone().into_bytes();
        let last = invalid.len() - 1;
        invalid[last] = if invalid[last] == b'a' { b'b' } else { b'a' };
        assert_eq!(
            store
                .authenticate_api_key(std::str::from_utf8(&invalid).unwrap())
                .await
                .unwrap_err()
                .code,
            ErrorCode::Unauthorized
        );
        let mut raw = SqliteConnection::connect(&format!("sqlite://{}", path.display()))
            .await
            .unwrap();
        let (payload, verifier): (String, Vec<u8>) =
            sqlx::query_as("SELECT payload,verifier FROM api_keys WHERE id=?")
                .bind(issued.key.id.to_string())
                .fetch_one(&mut raw)
                .await
                .unwrap();
        assert!(!payload.contains(&issued.token));
        assert_eq!(verifier.len(), 32);
        assert!(
            sqlx::query("DELETE FROM audit")
                .execute(&mut raw)
                .await
                .is_err()
        );
        assert!(
            sqlx::query("UPDATE audit SET event='{}'")
                .execute(&mut raw)
                .await
                .is_err()
        );
        raw.close().await.unwrap();
        store
            .revoke_api_key(issued.key.id, Uuid::new_v4())
            .await
            .unwrap();
        store.close().await;
        let reopened = Store::open(&path).await.unwrap();
        let checks = AssertUnwindSafe(async {
            assert!(
                reopened
                    .api_key(issued.key.id)
                    .await
                    .unwrap()
                    .revoked_at
                    .is_some()
            );
            assert_eq!(
                reopened
                    .authenticate_api_key(&issued.token)
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::Unauthorized
            );
            let first = reopened.audit_page(0, 1).await.unwrap();
            let next = first.next_after.unwrap();
            let second = reopened.audit_page(next, 1).await.unwrap();
            assert_eq!(first.items[0].event.phase, AuditPhase::Created);
            assert_eq!(second.items[0].event.phase, AuditPhase::Revoked);
            assert!(second.items[0].sequence > first.items[0].sequence);
            assert!(
                !serde_json::to_string(&first)
                    .unwrap()
                    .contains(&issued.token)
            );
        })
        .catch_unwind()
        .await;
        reopened.close().await;
        if let Err(error) = checks {
            std::panic::resume_unwind(error);
        }
    })
    .catch_unwind()
    .await;
    store.close().await;
    let root = dir.path().to_owned();
    dir.close().unwrap();
    assert!(!root.exists());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn expired_empty_and_excessive_grants_are_refused() {
    let store = Store::memory().await.unwrap();
    let mut spec = CreateApiKey {
        permissions: [KeyPermission::Read].into(),
        resources: KeyResources::All,
        expires_at: Utc::now() - chrono::Duration::seconds(1),
    };
    assert!(store.issue_api_key(&spec, Uuid::new_v4()).await.is_err());
    spec.expires_at = Utc::now() + chrono::Duration::days(367);
    assert!(store.issue_api_key(&spec, Uuid::new_v4()).await.is_err());
    spec.expires_at = Utc::now() + chrono::Duration::hours(1);
    spec.permissions.clear();
    assert!(store.issue_api_key(&spec, Uuid::new_v4()).await.is_err());
    store.close().await;
}
