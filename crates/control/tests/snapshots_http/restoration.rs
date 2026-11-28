use super::*;

async fn ready(store: &Store, src: Uuid) -> (Uuid, Execution) {
    let mut old = store
        .create_execution(src, &CommandSpec::new(["retained"]), "retained")
        .await
        .unwrap();
    old.state = ExecutionState::Running;
    old.started_at = Some(Utc::now());
    old.cleanup = CleanupState::Pending;
    store
        .persist_execution(
            &old,
            &[ExecutionEvent {
                execution_id: old.id,
                sequence: 1,
                timestamp: Utc::now(),
                kind: EventKind::Started,
                data: json!({}),
            }],
        )
        .await
        .unwrap();
    let created = store
        .create_snapshot(&profile(), src, &intent(), "capture")
        .await
        .unwrap();
    let id = created.snapshot.id;
    let original = store.sandbox(src).await.unwrap();
    let handle = original.handle.unwrap();
    store.begin_snapshot_capture(id, &handle).await.unwrap();
    let manifest:SnapshotManifest=serde_json::from_value(json!({"format_version":1,"id":id,"source_sandbox_id":src,"kind":"memory_and_disk","driver":profile().id,"architecture":"x86_64","image_digest":original.sandbox.image,"objects":{"state":format!("sha256:{}","a".repeat(64)),"memory":format!("sha256:{}","b".repeat(64)),"disk":format!("sha256:{}","c".repeat(64))},"runtime_version":"synthetic","created_at":created.snapshot.created_at})).unwrap();
    store
        .snapshot_capture_ready(
            id,
            &handle,
            &manifest,
            &json!({"private_reference":"not-public"}),
        )
        .await
        .unwrap();
    store
        .set_desired(src, DesiredState::Terminated, "source-delete")
        .await
        .unwrap();
    let mut source = store.sandbox(src).await.unwrap();
    source.sandbox.state = SandboxState::Stopping;
    store.observe(source.clone()).await.unwrap();
    source.sandbox.state = SandboxState::Terminated;
    source.sandbox.cleanup = CleanupState::Complete;
    source.handle = None;
    store.observe(source).await.unwrap();
    store
        .finish_execution(old.id, ExecutionState::Cancelled, "source collected")
        .await
        .unwrap();
    (id, old)
}

#[tokio::test]
async fn restoration_requires_global_creation_authority_and_exact_new_target_grants_after_reply_loss()
 {
    checked(|store,_|async move {
        let src=source(&store,"source").await;let other=source(&store,"foreign").await;let(snapshot,old)=ready(&store,src).await;
        let source_owner=key(&store,src,true).await;let reader=key(&store,src,false).await;let foreign=key(&store,other,true).await;
        let owner=store.issue_api_key(&CreateApiKey{resources:KeyResources::All,permissions:BTreeSet::from([KeyPermission::Read,KeyPermission::Write]),expires_at:Utc::now()+chrono::Duration::hours(1)},Uuid::new_v4()).await.unwrap().token;
        let calls=Arc::new(AtomicUsize::new(0));let observed_calls=calls.clone();let private_store=store.clone();
        let private=Router::new().route("/internal/restorations",post(move|headers:HeaderMap,Json(request):Json<goldenhoop_control::InternalRestoreCall>|{
            let store=private_store.clone();let calls=observed_calls.clone();async move{
                assert_eq!(headers["authorization"],format!("Bearer {PRIVATE}"));let index=calls.fetch_add(1,Ordering::SeqCst);
                let created=store.create_restoration(&profile(),request.snapshot_id,&request.request,&request.idempotency_key).await.unwrap();
                if index==0{return(StatusCode::SERVICE_UNAVAILABLE,Json(json!(ApiError::new(ErrorCode::BackendUnavailable,"synthetic private reply loss"))));}
                let mut value=json!(created);value["private_reference"]=json!("not-public");value["sandbox"]["runtime_handle"]=json!("not-public");(StatusCode::ACCEPTED,Json(value))
            }
        }));
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let mut registration=WorkerRegistration{id:Uuid::new_v4(),endpoint:format!("http://{}/",listener.local_addr().unwrap()),token:PRIVATE.into(),heartbeat:Utc::now(),profiles:vec![profile()]};let _server=Server(tokio::spawn(async move{axum::serve(listener,private).await.unwrap();}));store.register_worker(&registration).await.unwrap();
        let app=api::router(store.clone(),ADMIN).unwrap();let path=format!("/v1/snapshots/{snapshot}/restore");let request=RestoreSnapshot{target:store.sandbox(src).await.unwrap().request};
        assert_eq!(call(&app,Some(&source_owner),"POST",&path,Some(json!(request)),Some("restore")).await.0,StatusCode::FORBIDDEN);
        assert_eq!(call(&app,Some(&reader),"POST",&path,Some(json!(request)),Some("restore")).await.0,StatusCode::FORBIDDEN);
        assert_eq!(call(&app,Some(&foreign),"POST",&path,Some(json!(request)),Some("restore")).await.0,StatusCode::FORBIDDEN);
        assert_eq!(call(&app,Some(&owner),"POST",&path,Some(json!(request)),None).await.0,StatusCode::BAD_REQUEST);
        let mut unknown=json!(request);unknown["target"]["host_path"]=json!("forbidden");assert_eq!(call(&app,Some(&owner),"POST",&path,Some(unknown),Some("invalid")).await.0,StatusCode::BAD_REQUEST);assert_eq!(calls.load(Ordering::SeqCst),0);
        assert_eq!(call(&app,Some(&owner),"POST",&path,Some(json!(request)),Some("restore")).await.0,StatusCode::SERVICE_UNAVAILABLE);
        let stored=store.prior_restoration(snapshot,&request,"restore").await.unwrap().unwrap();let target=stored.sandbox.id;let execution=stored.executions[0].execution.id;assert_ne!(execution,old.id);
        registration.heartbeat=Utc::now()-chrono::Duration::minutes(10);registration.profiles[0].capabilities.remove(&Capability::MemorySnapshot);store.register_worker(&registration).await.unwrap();
        let(status,value)=call(&app,Some(&owner),"POST",&path,Some(json!(request)),Some("restore")).await;assert_eq!(status,StatusCode::ACCEPTED);assert_eq!(value,json!(stored));assert_eq!(calls.load(Ordering::SeqCst),1);
        assert_eq!(call(&app,Some(&source_owner),"POST",&path,Some(json!(request)),Some("restore")).await.0,StatusCode::FORBIDDEN);
        let mut changed=request.clone();changed.target.ttl_seconds-=1;assert_eq!(call(&app,Some(&owner),"POST",&path,Some(json!(changed)),Some("restore")).await.0,StatusCode::CONFLICT);
        let direct=key(&store,target,false).await;
        for path in [format!("/v1/sandboxes/{target}"),format!("/v1/sandboxes/{target}/restoration"),format!("/v1/operations/{}",stored.operation.id),format!("/v1/executions/{execution}")] {
            assert_eq!(call(&app,Some(&owner),"GET",&path,None,None).await.0,StatusCode::OK);
            assert_eq!(call(&app,Some(&direct),"GET",&path,None,None).await.0,StatusCode::OK);
            assert_eq!(call(&app,Some(&source_owner),"GET",&path,None,None).await.0,StatusCode::FORBIDDEN);
            assert_eq!(call(&app,Some(&foreign),"GET",&path,None,None).await.0,StatusCode::FORBIDDEN);
        }
        assert_eq!(call(&app,Some(&owner),"POST",&format!("/v1/executions/{execution}/cancel"),None,None).await.0,StatusCode::FORBIDDEN);
        assert!(!store.execution(old.id).await.unwrap().cancel_requested);assert_eq!(store.sandbox(src).await.unwrap().sandbox.cleanup,CleanupState::Complete);
        registration.heartbeat=Utc::now();registration.profiles=vec![profile()];store.register_worker(&registration).await.unwrap();let(second,_)=ready(&store,other).await;let request2=RestoreSnapshot{target:store.sandbox(other).await.unwrap().request};let(status,value)=call(&app,Some(ADMIN),"POST",&format!("/v1/snapshots/{second}/restore"),Some(json!(request2)),Some("restore-second")).await;assert_eq!(status,StatusCode::ACCEPTED);assert!(value.get("private_reference").is_none());assert!(value["sandbox"].get("runtime_handle").is_none());assert_eq!(calls.load(Ordering::SeqCst),2);
    }).await;
}
