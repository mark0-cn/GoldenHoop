//! Synthetic durable-domain observations; no native collection claim.
use futures_util::FutureExt;
use goldenhoop_credentials::*;
use goldenhoop_protocol::*;
use goldenhoop_store::Store;
use sqlx::{Connection, SqliteConnection};
use std::panic::AssertUnwindSafe;
use uuid::Uuid;
use zeroize::Zeroizing;

#[tokio::test]
async fn private_ca_reopens_without_rotation_wrong_keys_refuse_and_collection_retires_private_material()
 {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.db");
    let mut stores = Vec::new();
    let result=AssertUnwindSafe(async {
        let store=Store::open(&path).await.unwrap();stores.push(store.clone());
        let profile:RuntimeProfile=serde_json::from_value(serde_json::json!({"id":"fixture","placement":"local","isolation":"gvisor","availability":"available","capabilities":["commands","network_isolation"],"max_resources":{"cpu_millis":1000,"memory_bytes":1073741824,"pids":256},"max_ttl_seconds":3600})).unwrap();
        let sandbox=store.create_sandbox(&profile,&CreateSandbox::new("fixture","fixture"),"source").await.unwrap().sandbox.id;
        let key=VaultKey::from_bytes([62;32]);let wrong=VaultKey::from_bytes([63;32]);
        let public=store.ensure_credential_ca(&key,sandbox).await.unwrap();assert!(public.contains("BEGIN CERTIFICATE"));assert!(!public.contains("PRIVATE KEY"));
        assert_eq!(store.ensure_credential_ca(&key,sandbox).await.unwrap(),public);assert!(store.verify_vault_key(&wrong).await.is_err());
        let material=store.credential_ca_material(&key,sandbox).await.unwrap();assert_eq!(CertificateAuthority::open(material).unwrap().public_pem(),public);
        let id=Uuid::new_v4();
        let record=store.put_credential(&key,Uuid::new_v4(),sandbox,id,WriteCredential{expected_revision:0,binding:BindingSpec{scheme:Scheme::Https,host:"api.example.test".into(),port:443,methods:["POST".into()].into(),path_prefix:"/v1/".into(),injection:Injection::Bearer,substitutions:Vec::new()},secret:SecretSource::Literal{value:Secret(Zeroizing::new("private-credential-value".into()))}}).await.unwrap();assert_eq!(record.state,CredentialState::Pending);
        store.close().await;let reopened=Store::open(&path).await.unwrap();stores.push(reopened.clone());
        assert_eq!(reopened.ensure_credential_ca(&key,sandbox).await.unwrap(),public);
        assert!(reopened.ensure_credential_ca(&wrong,sandbox).await.is_err());
        let mut connection=SqliteConnection::connect(&format!("sqlite://{}",path.display())).await.unwrap();
        let raw:Result<String,_>=sqlx::query_scalar("SELECT sealed FROM credential_cas WHERE sandbox_id=?").bind(sandbox.to_string()).fetch_one(&mut connection).await;
        connection.close().await.unwrap();let raw=raw.unwrap();assert!(!raw.contains("PRIVATE KEY"));assert!(!raw.contains(&public));
        let mut stored=reopened.sandbox(sandbox).await.unwrap();stored.sandbox.state=SandboxState::Starting;reopened.observe(stored.clone()).await.unwrap();
        stored.sandbox.state=SandboxState::Failed;stored.sandbox.cleanup=CleanupState::Complete;reopened.observe(stored).await.unwrap();
        assert!(reopened.credential_ca_material(&key,sandbox).await.is_err());assert!(reopened.ensure_credential_ca(&key,sandbox).await.is_err());
        assert_eq!(reopened.credential(sandbox,id).await.unwrap().state,CredentialState::Revoked);assert!(reopened.credential_secret(&key,sandbox,id,1).await.is_err());
        let audit=reopened.audit_page(0,1000).await.unwrap();assert!(audit.items.iter().any(|r|r.event.target_id==Some(id)&&r.observation.as_ref().is_some_and(|v|v["collection"]=="sandbox_runtime")));
    }).catch_unwind().await;
    for store in stores {
        store.close().await;
    }
    let root = dir.path().to_owned();
    dir.close().unwrap();
    assert!(!root.exists());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn missing_provisioned_ca_is_not_silently_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-ca.db");
    let store = Store::open(&path).await.unwrap();
    let result=AssertUnwindSafe(async {
        let profile:RuntimeProfile=serde_json::from_value(serde_json::json!({"id":"fixture","placement":"local","isolation":"gvisor","availability":"available","capabilities":["commands","network_isolation"],"max_resources":{"cpu_millis":1000,"memory_bytes":1073741824,"pids":256},"max_ttl_seconds":3600})).unwrap();
        let sandbox=store.create_sandbox(&profile,&CreateSandbox::new("fixture","fixture"),"source").await.unwrap().sandbox.id;let key=VaultKey::from_bytes([71;32]);
        store.ensure_credential_ca(&key,sandbox).await.unwrap();
        let mut connection=SqliteConnection::connect(&format!("sqlite://{}",path.display())).await.unwrap();
        let deletion=sqlx::query("DELETE FROM credential_cas WHERE sandbox_id=?").bind(sandbox.to_string()).execute(&mut connection).await;connection.close().await.unwrap();deletion.unwrap();
        assert!(store.ensure_credential_ca(&key,sandbox).await.is_err());assert!(store.credential_ca_public(sandbox).await.is_err());
    }).catch_unwind().await;
    store.close().await;
    let root = dir.path().to_owned();
    dir.close().unwrap();
    assert!(!root.exists());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn excluded_secret_feature_cannot_persist_a_ca_as_a_failed_write_side_effect() {
    let store = Store::memory().await.unwrap();
    let profile:RuntimeProfile=serde_json::from_value(serde_json::json!({"id":"fixture","placement":"local","isolation":"gvisor","availability":"available","capabilities":["commands","network_isolation","isolated_sessions","secret_injection"],"max_resources":{"cpu_millis":1000,"memory_bytes":1073741824,"pids":256},"max_ttl_seconds":3600})).unwrap();
    let mut request = CreateSandbox::new("fixture", "fixture");
    request.feature_limit = Some([Capability::Commands, Capability::NetworkIsolation].into());
    let id = store
        .create_sandbox(&profile, &request, "source")
        .await
        .unwrap()
        .sandbox
        .id;
    let result = store
        .ensure_credential_ca(&VaultKey::from_bytes([75; 32]), id)
        .await;
    assert!(matches!(
        result,
        Err(ApiError {
            code: ErrorCode::Forbidden,
            ..
        })
    ));
    assert!(store.credential_ca_public(id).await.is_err());
    store.close().await;
}
