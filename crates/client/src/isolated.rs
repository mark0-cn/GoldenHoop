use super::*;

fn check_scope(value: &SandboxScope, id: Uuid) -> Result<()> {
    if value.sandbox_id != id
        || value.root_id.is_nil()
        || value.depth > 4
        || (value.depth == 0 && (value.parent_id.is_some() || value.root_id != id))
        || (value.depth > 0
            && (value.root_id == id
                || value
                    .parent_id
                    .is_none_or(|parent| parent.is_nil() || parent == id)
                || value.feature_limit.is_none()))
    {
        return Err(Error::Protocol("sandbox scope identity mismatch"));
    }
    let used = &value.allocated_to_children;
    if let Some(budget) = &value.child_budget {
        if budget.cpu_millis == 0
            || budget.memory_bytes == 0
            || budget.pids == 0
            || used.cpu_millis > budget.cpu_millis
            || used.memory_bytes > budget.memory_bytes
            || used.pids > budget.pids
        {
            return Err(Error::Protocol(
                "sandbox child allocation exceeds its reservation",
            ));
        }
    } else if used.cpu_millis != 0 || used.memory_bytes != 0 || used.pids != 0 {
        return Err(Error::Protocol("sandbox allocation lacks a reservation"));
    }
    Ok(())
}

impl Client {
    pub async fn create_isolated_session(
        &self,
        parent: Uuid,
        request: &CreateIsolatedSession,
        key: &str,
    ) -> Result<IsolatedSessionCreated> {
        let source = self.sandbox(parent).await?;
        let source_scope = self.sandbox_scope(parent).await?;
        let value: IsolatedSessionCreated = Self::json(
            self.send(
                Method::POST,
                &format!("v1/sandboxes/{parent}/isolated-sessions"),
                Some(
                    serde_json::to_value(request)
                        .map_err(|_| Error::Protocol("invalid isolated session request"))?,
                ),
                Some(key),
            )
            .await?,
        )
        .await?;
        check_scope(&value.scope, value.sandbox.id)?;
        if value.sandbox.id.is_nil()
            || value.scope.parent_id != Some(parent)
            || value.scope.depth == 0
            || value.scope.root_id != source_scope.root_id
            || value.scope.depth != source_scope.depth + 1
            || value.operation.resource_id != value.sandbox.id
            || value.sandbox.profile != source.profile
            || value.sandbox.image != request.image.as_ref().unwrap_or(&source.image).as_str()
            || value.sandbox.resources != request.resources
            || value.sandbox.expires_at > source.expires_at
            || value.scope.child_budget != request.child_budget
            || request.feature_limit.as_ref().is_some_and(|requested| {
                value
                    .scope
                    .feature_limit
                    .as_ref()
                    .is_none_or(|granted| !granted.is_subset(requested))
            })
        {
            return Err(Error::Protocol("isolated session create response mismatch"));
        }
        Ok(value)
    }
    pub async fn sandbox_scope(&self, id: Uuid) -> Result<SandboxScope> {
        let value: SandboxScope = self.get(&format!("v1/sandboxes/{id}/scope")).await?;
        check_scope(&value, id)?;
        Ok(value)
    }
    pub async fn isolated_sessions(
        &self,
        parent: Uuid,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<SandboxPage> {
        let mut path = format!("v1/sandboxes/{parent}/isolated-sessions?limit={limit}");
        if let Some(after) = after {
            path.push_str(&format!("&after={after}"));
        }
        self.get(&path).await
    }
    pub async fn isolated_lease(
        &self,
        parent: Uuid,
        request: &CreateIsolatedSession,
    ) -> Result<SandboxLease> {
        let key = Uuid::new_v4().to_string();
        let created = match self.create_isolated_session(parent, request, &key).await {
            Ok(value) => value,
            Err(Error::Transport) => return Err(Error::UncertainRequest(key)),
            Err(Error::Api(error)) if error.code == ErrorCode::BackendUnavailable => {
                return Err(Error::UncertainRequest(key));
            }
            Err(error) => return Err(error),
        };
        self.lease_created(SandboxCreated {
            sandbox: created.sandbox,
            operation: created.operation,
        })
        .await
    }
}
