//! Actual untrusted-UID HTTP/TLS requests through the production broker. A
//! failing credential probe withholds only SecretInjection; network acceptance
//! and collection remain independently required. The operator owns the receiver.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use goldenhoop_credentials::{
    BindingSpec, CredentialState, Injection, Scheme, SecretSource, WriteCredential,
};
use std::collections::{BTreeMap, BTreeSet};

fn failed() -> ApiError {
    ApiError::new(
        ErrorCode::BackendUnavailable,
        "actual credential deployment probe did not confirm HTTP/TLS forwarding",
    )
}
const CLIENT: &str = r#"import http.client,os,ssl,urllib.parse
assert os.geteuid()==1000
assert int(next(line.split()[1] for line in open('/proc/self/status') if line.startswith('CapEff:')),16)==0
for raw in [os.environ['GH_HTTP_PROBE'],os.environ['GH_HTTPS_PROBE']]:
    url=urllib.parse.urlsplit(raw)
    if url.scheme=='https':
        context=ssl.create_default_context(cadata=os.environ['GH_PUBLIC_CA'])
        connection=http.client.HTTPSConnection(url.hostname,url.port,context=context,timeout=5)
    else:
        connection=http.client.HTTPConnection(url.hostname,url.port,timeout=5)
    connection.request('GET',url.path,headers={'Connection':'close'})
    response=connection.getresponse()
    assert response.status==200
    assert response.read(129).decode()==os.environ['GH_EXPECTED_PROBE_BODY']
    connection.close()
print('goldenhoop_credential_profile_probe',end='')
"#;

impl Worker {
    pub(super) async fn probe_credential_profile(&self, root: Uuid) -> Result<(), ApiError> {
        let setup = self.credentials.as_ref().ok_or_else(failed)?;
        let probe = setup.probe.as_ref().ok_or_else(failed)?;
        let urls = probe.urls()?;
        let desired = self.store.public_network_policy(root).await?;
        let rules = urls
            .iter()
            .map(|url| NetworkRule {
                destination: url
                    .host_str()
                    .expect("validated native endpoint")
                    .trim_matches(['[', ']'])
                    .into(),
                ports: vec![url.port_or_known_default().expect("validated port")],
                action: NetworkAction::Allow,
            })
            .collect();
        self.store
            .set_public_network_policy(
                root,
                &SetNetworkPolicy {
                    expected_revision: desired.revision,
                    policy: NetworkPolicy {
                        default_action: NetworkAction::Deny,
                        rules,
                    },
                },
                &Uuid::new_v4().to_string(),
            )
            .await?;
        self.wait_probe_ready(&[root]).await?;
        let public_ca = self.store.ensure_credential_ca(&setup.key, root).await?;
        let audit_start = self.store.audit_page(0, 1).await?.through_sequence;
        let mut bindings = BTreeSet::new();
        for (url, scheme) in urls.iter().zip([Scheme::Http, Scheme::Https]) {
            let id = Uuid::new_v4();
            self.store
                .put_credential(
                    &setup.key,
                    Uuid::new_v4(),
                    root,
                    id,
                    WriteCredential {
                        expected_revision: 0,
                        binding: BindingSpec {
                            scheme,
                            host: url
                                .host_str()
                                .expect("validated endpoint")
                                .trim_matches(['[', ']'])
                                .into(),
                            port: url.port_or_known_default().expect("validated port"),
                            methods: ["GET".into()].into(),
                            path_prefix: url.path().into(),
                            injection: Injection::Bearer,
                            substitutions: Vec::new(),
                        },
                        secret: SecretSource::Literal {
                            value: probe.credential.clone(),
                        },
                    },
                )
                .await?;
            bindings.insert(id);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
        loop {
            Box::pin(self.reconcile(root)).await?;
            let current = self.store.credentials(root).await?;
            if bindings.iter().all(|id| {
                current.iter().any(|r| {
                    r.id == *id
                        && r.state == CredentialState::Active
                        && r.applied_revision == Some(r.revision)
                })
            }) && self.require_network_dispatch(root).await.is_ok()
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(failed());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let spec:CommandSpec=serde_json::from_value(serde_json::json!({
            "argv":["python3","-c",CLIENT],"timeout_seconds":20,
            "env":{"GH_HTTP_PROBE":urls[0].as_str(),"GH_HTTPS_PROBE":urls[1].as_str(),"GH_PUBLIC_CA":public_ca,"GH_EXPECTED_PROBE_BODY":probe.expected_body}
        })).map_err(|_|failed())?;
        let execution = self
            .store
            .create_execution(root, &spec, &Uuid::new_v4().to_string())
            .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(35);
        loop {
            Box::pin(self.reconcile(root)).await?;
            let current = self.store.execution(execution.id).await?.execution;
            if current.state.is_terminal() {
                if current.state != ExecutionState::Succeeded || current.exit_code != Some(0) {
                    return Err(failed());
                }
                let mut stdout = Vec::new();
                let mut completed = 0;
                for event in self.store.events(execution.id, 0).await? {
                    if event.kind == EventKind::Stdout {
                        stdout.extend(
                            STANDARD
                                .decode(event.data["data"].as_str().ok_or_else(failed)?)
                                .map_err(|_| failed())?,
                        );
                    }
                    if event.kind == EventKind::Completed {
                        completed += 1;
                    }
                }
                if stdout != b"goldenhoop_credential_profile_probe" || completed != 1 {
                    return Err(failed());
                }
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(failed());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut cursor = audit_start;
        let mut outcomes = BTreeMap::<Uuid, BTreeSet<&str>>::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let page = self.store.audit_page(cursor, 1000).await?;
            for record in page.items {
                cursor = record.sequence;
                if let Some(observation) = record.observation
                    && let Ok(event) =
                        serde_json::from_value::<goldenhoop_credentials::BrokerAudit>(observation)
                    && event.sandbox_id == root
                    && bindings.contains(&event.binding_id)
                {
                    use goldenhoop_credentials::CredentialOutcome::*;
                    let kind = match event.outcome {
                        DispatchIntent => Some("dispatch_intent"),
                        UpstreamResponded { status: 200 } => Some("responded"),
                        BodyCompleted => Some("completed"),
                        _ => None,
                    };
                    if let Some(kind) = kind {
                        outcomes.entry(event.binding_id).or_default().insert(kind);
                    }
                }
            }
            if bindings
                .iter()
                .all(|id| outcomes.get(id).is_some_and(|k| k.len() == 3))
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(failed());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
